"""Leadership / incident views across every source:

  * Top risky assets  - one additive score per asset (every point explained): internet exposure, shadow ports, EDR gap,
                        critical / high / exploitable vulnerabilities, CrowdStrike detections and Seceon NDR alerts in the
                        chosen date range, failed MBSS rules and uninstalled security errata (Satellite), and how many weak
                        internal assets it can reach through the communication matrix.
  * Attack paths      - internet -> exposed asset (inbound rule / public IP) -> internal assets that asset may reach through
                        active Allow rules of the communication matrix (1 or 2 hops), with each target's EDR and vulnerabilities.
  * Analyst workload  - alerts per analyst in a date range: CrowdStrike (assigned_to on the Alerts API) and Splunk
                        Enterprise Security notables (owner), side by side and combined."""
import bisect
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from . import commatrix, config, db, splunk
from .exporter import xlsx_response

router = APIRouter()

HIGH = ("Critical", "High")


def _range(d_from, d_to, days=30):
    now = datetime.now(timezone.utc)
    return d_from or (now - timedelta(days=days - 1)).strftime("%Y-%m-%d"), d_to or now.strftime("%Y-%m-%d")


def _lob_filter(lob):
    return ("r.lob_ids LIKE ?", [f"%,{int(lob)},%"]) if lob and str(lob).isdigit() else ("1=1", [])


# ------------------------------------------------------------------ reachability (communication matrix)
def _ranges(text):
    """(is_any, [(version, lo, hi)]) for a matrix source / destination cell."""
    anyv, nets = commatrix.endpoints(text)
    return anyv, [(n.version, int(n.network_address), int(n.broadcast_address)) for n in nets]


class Graph:
    """Active Allow rules of the matrix, parsed once, and the registry's internal assets sorted by address for range look-ups."""
    MAX_DST = 4096  # a destination wider than this (e.g. a /8) is too broad to call a path; it is listed as a note instead

    def __init__(self, c):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.assets = {}
        for r in db.rows(c, """SELECT ip, name, lobs, edr_status, edr_applicable, crit, high, exposed, os, node_type FROM asset_registry
                               WHERE ip IS NOT NULL AND nat_of IS NULL"""):
            try:
                a = ipaddress.ip_address(r["ip"])
            except ValueError:
                continue
            r["_v"], r["_n"] = a.version, int(a)
            self.assets[r["ip"]] = r
        self.sorted = {v: sorted((a["_n"], ip) for ip, a in self.assets.items() if a["_v"] == v) for v in (4, 6)}
        self.keys = {v: [n for n, _ in self.sorted[v]] for v in (4, 6)}
        self.inbound, self.internal = [], []
        for r in commatrix.load_rules(c):
            if (r["action"] or "allow").strip().lower() not in ("allow", "permit", "accept", "yes", ""):
                continue
            s_any, s_rng = _ranges(r["src"])
            d_any, d_rng = _ranges(r["dst"])
            rule = {"rule_id": r["rule_id"], "ports": r["ports"] or "any", "protocol": r["protocol"] or "", "service": r["service"] or "",
                    "firewall": r["firewall"] or "", "src_zone": r["src_zone"] or "", "dst_zone": r["dst_zone"] or "", "isp": r["isp"] or "",
                    "src_rng": s_rng, "src_any": s_any, "dst_rng": d_rng, "dst_any": d_any, "dst_nat": set(db.all_ips(r["dst_nat"])),
                    "valid_till": r["valid_till"]}
            (self.inbound if r["inbound_internet"] else self.internal).append(rule)
        self._reach = {}

    def inside(self, rng):
        v, lo, hi = rng
        if hi - lo + 1 > self.MAX_DST:
            return None
        ks = self.keys.get(v, [])
        i, j = bisect.bisect_left(ks, lo), bisect.bisect_right(ks, hi)
        return [self.sorted[v][k][1] for k in range(i, j)]

    @staticmethod
    def _has(rngs, a):
        return any(v == a["_v"] and lo <= a["_n"] <= hi for v, lo, hi in rngs)

    def entry_rules(self, ip, public_ips):
        a = self.assets.get(ip)
        return [r for r in self.inbound if (a and self._has(r["dst_rng"], a)) or (r["dst_nat"] & public_ips)]

    def reach(self, ip):
        """{target ip: [(rule_id, ports)]} of internal assets `ip` may open connections to (explicit source match only)."""
        if ip in self._reach:
            return self._reach[ip]
        a, out = self.assets.get(ip), {}
        if a:
            for r in self.internal:
                if not self._has(r["src_rng"], a):
                    continue
                for d in r["dst_rng"]:
                    for t in self.inside(d) or []:
                        if t != ip:
                            out.setdefault(t, []).append((r["rule_id"], r["ports"]))
        self._reach[ip] = out
        return out

    @staticmethod
    def weak(t):
        return (t["crit"] or 0) > 0 or (t["edr_applicable"] and t["edr_status"] == "Not Installed")

    def summary(self, ip, depth=2):
        hop1 = self.reach(ip)
        hop2 = {}
        if depth > 1:
            for t in hop1:
                for u, via in self.reach(t).items():
                    if u != ip and u not in hop1:
                        hop2.setdefault(u, []).extend((t, r, p) for r, p in via)
        targets = [self.assets[t] for t in [*hop1, *hop2]]
        return hop1, hop2, targets


# ------------------------------------------------------------------ top risky assets
def _detections(c, d_from, d_to):
    by_aid, by_host = {}, {}
    for r in c.execute("""SELECT aid, LOWER(hostname) hn, severity, COUNT(*) n FROM detections
                          WHERE substr(created_at,1,10) BETWEEN ? AND ? GROUP BY 1, 2, 3""", (d_from, d_to)):
        for key, m in ((r["aid"], by_aid), (r["hn"], by_host)):
            if key:
                d = m.setdefault(key, {"n": 0, "high": 0})
                d["n"] += r["n"]
                d["high"] += r["n"] if r["severity"] in HIGH else 0
    return by_aid, by_host


def _ndr(c, d_from, d_to):
    out = {}
    for r in c.execute("""SELECT src_ip, dst_ip, severity FROM ndr_alerts WHERE substr(created_at,1,10) BETWEEN ? AND ?""", (d_from, d_to)):
        for ip in {r["src_ip"], r["dst_ip"]} - {None, ""}:
            d = out.setdefault(ip, {"n": 0, "high": 0})
            d["n"] += 1
            d["high"] += 1 if r["severity"] in HIGH else 0
    return out


def score(a, ext):
    """(points, [(factor, points)], next action). Additive and explained, like the Risk ranking page."""
    f = []
    if a["exposed"]:
        f.append((f"Internet exposed ({', '.join(x for x in (a['exposure_src'] or '').split(',') if x)})", 25))
    elif a["cgnat"]:
        f.append(("Indirectly exposed (telecom / CGNAT)", 8))
    if ext.get("shadow"):
        f.append((f"{ext['shadow']} shadow port(s): open, no firewall rule", min(15, 8 + 2 * ext["shadow"])))
    if a["edr_applicable"] and a["edr_status"] == "Not Installed":
        f.append(("No EDR agent", 25))
    elif a["edr_status"] == "Offline":
        f.append(("EDR offline", 10))
    elif a["feasibility"] == "No" and a["edr_status"] == "Not Installed":
        f.append(("EDR not feasible (compensating controls?)", 5))
    if a["crit"]:
        f.append((f"{a['crit']} open critical vulnerabilities", min(25, 10 + 5 * (a["crit"] - 1))))
    if a["high"]:
        f.append((f"{a['high']} open high", min(10, 3 + a["high"])))
    if ext.get("exploitable"):
        f.append(("Exploit available", 10))
    det = ext.get("det") or {}
    if det.get("n"):
        f.append((f"{det['n']} CrowdStrike detection(s){', ' + str(det['high']) + ' critical/high' if det['high'] else ''}", 20 if det["high"] else 8))
    ndr = ext.get("ndr") or {}
    if ndr.get("n"):
        f.append((f"{ndr['n']} Seceon NDR alert(s)", 12 if ndr["high"] else 5))
    sat = ext.get("sat") or {}
    if sat.get("compliance_failed"):
        f.append((f"{sat['compliance_failed']} failed MBSS rule(s)", min(8, 2 + sat["compliance_failed"])))
    if sat.get("installable_security"):
        f.append((f"{sat['installable_security']} security errata not installed", 5))
    if ext.get("weak_reach"):
        f.append((f"Reaches {ext['weak_reach']} weak internal asset(s)", min(10, 2 * ext["weak_reach"])))
    pts = sum(p for _, p in f)
    if a["live"] == "Non Live":
        pts = round(pts * 0.5)
        f.append(("Non Live node (× 0.5)", 0))
    return pts, f, _action(a, ext)


def _action(a, ext):
    if ext.get("det") and ext["det"].get("high"):
        return "Investigate the open critical / high detections"
    if a["exposed"] and a["edr_applicable"] and a["edr_status"] == "Not Installed":
        return "Install the EDR agent: internet exposed without EDR"
    if ext.get("shadow"):
        return "Close the shadow ports or document them in the firewall matrix"
    if a["exposed"] and a["crit"]:
        return "Patch the critical vulnerabilities (internet exposed)"
    if a["edr_status"] == "Offline":
        return "Bring the EDR agent back online"
    if a["crit"]:
        return "Patch the critical vulnerabilities"
    if (ext.get("sat") or {}).get("installable_security"):
        return "Install the available security errata"
    if ext.get("weak_reach"):
        return "Restrict matrix rules to the weak internal assets it reaches"
    return "Review"


def top_risks(c, d_from, d_to, lob="", limit=10, exposed_only=False):
    where, params = _lob_filter(lob)
    if exposed_only:
        where += " AND (r.exposed=1 OR r.cgnat=1)"
    regs = db.rows(c, f"""SELECT r.asset_key, r.ip, r.name, r.lobs, r.msps, r.node_type, r.live, r.edr_applicable, r.edr_status, r.aid, r.cs_hostname,
                          r.crit, r.high, r.med, r.exposed, r.exposure_src, r.public_ips, r.cgnat, r.os, r.feasibility, r.in_inventory
                          FROM asset_registry r WHERE r.nat_of IS NULL AND {where}""", params)
    by_aid, by_host = _detections(c, d_from, d_to)
    ndr = _ndr(c, d_from, d_to)
    expl = {r["ip"]: r["n"] for r in c.execute("SELECT ip, MAX(exploitable) n FROM asset_risk WHERE exploitable>0 GROUP BY ip")}
    sat = {r["ip"]: r for r in db.rows(c, "SELECT ip, name_norm, compliance_failed, installable_security FROM satellite_hosts")}
    sat_n = {r["name_norm"]: r for r in sat.values() if r["name_norm"]}
    scored = []
    for a in regs:
        names = [db.norm_hostname(n) for n in (a["name"] or "").split(", ") + [a["cs_hostname"] or ""] if n]
        det = by_aid.get(a["aid"]) or next((by_host[n] for n in names if n in by_host), None)
        s = sat.get(a["ip"]) or next((sat_n[n] for n in names if n in sat_n), None)
        ext = {"det": det, "ndr": ndr.get(a["ip"]), "sat": s, "exploitable": expl.get(a["ip"])}
        pts, f, _ = score(a, ext)
        scored.append([pts, a, ext])
    scored.sort(key=lambda x: -x[0])
    # costly factors (shadow ports, reachable weak assets) only for the leading candidates
    g = Graph(c)
    cand = [x for x in scored[: max(limit * 5, 50)] if x[0] > 0]
    from .commatrix import shadow_ports
    from .registry import exposed_by_itself, is_public
    for x in cand:
        a, ext = x[1], x[2]
        if a["exposed"]:
            pubs = [p for p in (a["public_ips"] or "").split(", ") if p] + ([a["ip"]] if exposed_by_itself(a["ip"]) else [])
            ext["shadow"] = sum(sum(1 for p in shadow_ports(c, pub, [a["ip"]])[0] if p["shadow"] and p["open"]) for pub in pubs[:3])
            if a["ip"]:
                _, _, targets = g.summary(a["ip"], 2)
                ext["weak_reach"] = sum(1 for t in targets if g.weak(t))
        pts, f, act = score(a, ext)
        x[0] = pts
        x[2]["factors"], x[2]["action"] = f, act
    cand.sort(key=lambda x: -x[0])
    out = []
    for rank, (pts, a, ext) in enumerate(cand[:limit], start=1):
        out.append({"rank": rank, "score": pts, "ip": a["ip"], "name": a["name"] or a["cs_hostname"], "lobs": a["lobs"], "msps": a["msps"],
                    "node_type": a["node_type"], "os": a["os"], "edr_status": a["edr_status"], "edr_applicable": a["edr_applicable"],
                    "aid": a["aid"], "exposed": a["exposed"], "indirect": a["cgnat"], "public_ips": a["public_ips"],
                    "crit": a["crit"], "high": a["high"], "detections": (ext.get("det") or {}).get("n", 0),
                    "detections_high": (ext.get("det") or {}).get("high", 0), "ndr": (ext.get("ndr") or {}).get("n", 0),
                    "mbss_failed": (ext.get("sat") or {}).get("compliance_failed") or 0, "shadow": ext.get("shadow", 0),
                    "weak_reach": ext.get("weak_reach", 0), "factors": ext["factors"], "action": ext["action"]})
    return out


@router.get("/api/top-risks")
def top_risks_api(date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to"), lob: str = "", limit: int = 10,
                  exposed: str = ""):
    d_from, d_to = _range(date_from, date_to)
    with db.get_conn() as c:
        rows = top_risks(c, d_from, d_to, lob, max(1, min(100, limit)), exposed == "1")
    return {"rows": rows, "from": d_from, "to": d_to}


TOP_EXPORT = [("rank", "Rank"), ("score", "Risk points"), ("name", "Asset"), ("ip", "IP"), ("public_ips", "Public IP"), ("lobs", "LOB"),
              ("msps", "MSP"), ("os", "OS"), ("edr_status", "EDR"), ("crit", "Critical"), ("high", "High"), ("detections", "CS detections"),
              ("ndr", "NDR alerts"), ("mbss_failed", "MBSS failed"), ("shadow", "Shadow ports"), ("weak_reach", "Weak assets reachable"),
              ("why", "Why"), ("action", "Next action")]


@router.get("/api/top-risks/export")
def top_risks_export(date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to"), lob: str = "", limit: int = 10, exposed: str = ""):
    rows = top_risks_api(date_from, date_to, lob, limit, exposed)["rows"]
    for r in rows:
        r["why"] = "; ".join(f"{n} (+{p})" for n, p in r["factors"] if p)
    return xlsx_response([("Top risky assets", TOP_EXPORT, rows)], "top_risky_assets")


# ------------------------------------------------------------------ attack paths
def _target(t, via, hop):
    return {"ip": t["ip"], "name": t["name"], "lobs": t["lobs"], "edr_status": t["edr_status"], "edr_applicable": t["edr_applicable"],
            "crit": t["crit"] or 0, "high": t["high"] or 0, "os": t["os"], "node_type": t["node_type"], "exposed": t["exposed"],
            "weak": bool(Graph.weak(t)), "hop": hop, "via": via}


def _entries(c, lob=""):
    where, params = _lob_filter(lob)
    return db.rows(c, f"""SELECT r.ip, r.name, r.lobs, r.edr_status, r.edr_applicable, r.crit, r.high, r.public_ips, r.exposure_src, r.os, r.node_type
                          FROM asset_registry r WHERE r.exposed=1 AND r.nat_of IS NULL AND r.ip IS NOT NULL AND {where}""", params)


def _node(a):
    return {"ip": a["ip"], "name": a["name"], "lobs": a["lobs"], "edr_status": a["edr_status"], "crit": a["crit"] or 0, "high": a["high"] or 0,
            "weak": bool(Graph.weak(a)), "exposed": a.get("exposed"), "os": a.get("os"), "node_type": a.get("node_type")}


@router.get("/api/attack-paths")
def attack_paths(lob: str = "", depth: int = 2):
    """Every internet-exposed asset as an entry point, with what it can reach inside; plus choke points (internal assets many
    paths pass through) and the matrix rules that open the most paths (tighten one, cut many)."""
    depth = 2 if depth != 1 else 1
    with db.get_conn() as c:
        g = Graph(c)
        entries = _entries(c, lob)
    out, choke, rules = [], {}, {}
    for e in entries:
        pubs = {p for p in (e["public_ips"] or "").split(", ") if p}
        ins = g.entry_rules(e["ip"], pubs)
        hop1, hop2, targets = g.summary(e["ip"], depth)
        weak = [t for t in targets if g.weak(t)]
        out.append({**e, "entry_ports": ", ".join(sorted({r["ports"] for r in ins})) or "",
                    "entry_rules": len(ins), "hop1": len(hop1), "hop2": len(hop2), "weak": len(weak),
                    "crit_targets": sum(1 for t in targets if t["crit"]),
                    "no_edr_targets": sum(1 for t in targets if t["edr_applicable"] and t["edr_status"] == "Not Installed"),
                    "entry_weak": bool(g.weak({**e})) or e["edr_status"] == "Offline"})
        # choke points: every internal asset on a path, with the entry points that reach it and the weak assets behind it
        for t, via in hop1.items():
            ch = choke.setdefault(t, {"entries": set(), "weak_behind": set()})
            ch["entries"].add(e["ip"])
            for rid, _ in via:
                ru = rules.setdefault(rid, {"entries": set(), "weak": set(), "targets": set()})
                ru["entries"].add(e["ip"])
                ru["targets"].add(t)
                if g.weak(g.assets[t]):
                    ru["weak"].add(t)
        for u, via in hop2.items():
            weak_u = g.weak(g.assets[u])
            for frm, rid, _ in via:
                if weak_u:
                    choke[frm]["weak_behind"].add(u)
                ru = rules.setdefault(rid, {"entries": set(), "weak": set(), "targets": set()})
                ru["entries"].add(e["ip"])
                ru["targets"].add(u)
                if weak_u:
                    ru["weak"].add(u)
    out.sort(key=lambda x: (-x["weak"], -(x["hop1"] + x["hop2"]), -(x["crit"] or 0)))
    chokes = sorted(({**_node(g.assets[ip]), "entries": len(v["entries"]), "weak_behind": len(v["weak_behind"])} for ip, v in choke.items()),
                    key=lambda x: (-(x["entries"] * (1 + x["weak_behind"]) + (5 if x["weak"] else 0)), x["ip"]))[:50]
    by_id = {r["rule_id"]: r for r in g.internal}
    tighten = sorted(({"rule_id": rid, "ports": by_id[rid]["ports"], "protocol": by_id[rid]["protocol"], "service": by_id[rid]["service"],
                       "firewall": by_id[rid]["firewall"], "src_zone": by_id[rid]["src_zone"], "dst_zone": by_id[rid]["dst_zone"],
                       "entries": len(v["entries"]), "targets": len(v["targets"]), "weak": len(v["weak"])} for rid, v in rules.items()),
                     key=lambda x: (-x["weak"], -x["entries"], -x["targets"]))
    return {"rows": out, "rules": {"inbound": len(g.inbound), "internal": len(g.internal)}, "depth": depth,
            "with_paths": sum(1 for r in out if r["hop1"]), "weak_paths": sum(1 for r in out if r["weak"]),
            "choke_points": chokes, "choke_total": sum(1 for v in choke.values() if len(v["entries"]) > 1), "tighten": tighten}


def path_detail(c, ip, depth=2, g=None):
    g = g or Graph(c)
    e = db.one(c, "SELECT ip, name, lobs, edr_status, edr_applicable, crit, high, public_ips, exposed, os, node_type FROM asset_registry WHERE ip=?", (ip,))
    if not e:
        return None
    pubs = {p for p in (e["public_ips"] or "").split(", ") if p}
    ins = g.entry_rules(ip, pubs)
    hop1, hop2, _ = g.summary(ip, 2 if depth != 1 else 1)
    t1 = [_target(g.assets[t], [{"from": ip, "rule_id": r, "ports": p} for r, p in via], 1) for t, via in hop1.items()]
    t2 = [_target(g.assets[t], [{"from": frm, "rule_id": r, "ports": p} for frm, r, p in via], 2) for t, via in hop2.items()]
    key = lambda t: (not t["weak"], -(t["crit"]), -(t["high"]), t["ip"])  # noqa: E731
    # who can reach this asset: internet-exposed entry points with a path to it (inbound blast radius)
    reached_by = []
    if ip in g.assets:
        for x in db.rows(c, "SELECT ip, name, edr_status, crit, high, exposed, lobs, edr_applicable FROM asset_registry WHERE exposed=1 AND nat_of IS NULL AND ip IS NOT NULL"):
            if x["ip"] == ip:
                continue
            h1 = g.reach(x["ip"])
            if ip in h1:
                reached_by.append({**_node(x), "hops": 1, "via": [{"rule_id": r, "ports": p} for r, p in h1[ip]]})
            elif depth != 1:
                mid = next((m for m in h1 if ip in g.reach(m)), None)
                if mid:
                    reached_by.append({**_node(x), "hops": 2, "through": mid, "via": [{"rule_id": r, "ports": p} for r, p in g.reach(mid)[ip]]})
    return {"entry": e, "internet": [{"rule_id": r["rule_id"], "ports": r["ports"], "protocol": r["protocol"], "isp": r["isp"], "zone": r["src_zone"],
                                      "firewall": r["firewall"], "public": ", ".join(sorted(r["dst_nat"] & pubs))} for r in ins],
            "hop1": sorted(t1, key=key)[:300], "hop2": sorted(t2, key=key)[:300], "hop1_total": len(t1), "hop2_total": len(t2),
            "reached_by": sorted(reached_by, key=lambda x: (x["hops"], not x["weak"], x["ip"]))[:100],
            "broad": sum(1 for r in g.internal if g._has(r["src_rng"], g.assets[ip]) and any(hi - lo + 1 > Graph.MAX_DST for _, lo, hi in r["dst_rng"]))
            if ip in g.assets else 0}


@router.get("/api/attack-paths/detail")
def attack_path_detail(ip: str, depth: int = 2):
    with db.get_conn() as c:
        d = path_detail(c, db.canon_ip(ip), depth)
    if not d:
        raise HTTPException(404, "Asset not found")
    return d


@router.get("/api/asset/posture")
def asset_posture(ips: str = "", names: str = "", aids: str = ""):
    """Asset 360 headline: the same explained risk score as Top riskiest assets, the next action, and one status per area
    (detections 7 days, NDR, patches / MBSS, blast radius)."""
    ip_l = [db.canon_ip(i) for i in ips.split(",") if i]
    hn_l = [db.norm_hostname(h) for h in names.split(",") if h]
    aid_l = [a for a in aids.split(",") if a]
    now = datetime.now(timezone.utc)
    d_from, d_to = (now - timedelta(days=6)).strftime("%Y-%m-%d"), now.strftime("%Y-%m-%d")
    with db.get_conn() as c:
        reg = [r for r in db.rows(c, f"""SELECT * FROM asset_registry WHERE nat_of IS NULL AND ip IN ({','.join('?' * len(ip_l))})""", ip_l)] if ip_l else []
        a = max(reg, key=lambda r: (r["exposed"] or 0, r["crit"] or 0), default=None)
        det = {"n": 0, "high": 0}
        w, p = [], []
        if aid_l:
            w.append(f"aid IN ({','.join('?' * len(aid_l))})")
            p += aid_l
        if hn_l:
            w.append(f"LOWER(hostname) IN ({','.join('?' * len(hn_l))})")
            p += hn_l
        if w:
            r = db.one(c, f"""SELECT COUNT(*) n, SUM(severity IN ('Critical','High')) high, SUM(LOWER(status)<>'closed') open FROM detections
                              WHERE ({' OR '.join(w)}) AND substr(created_at,1,10) BETWEEN ? AND ?""", p + [d_from, d_to])
            det = {"n": r["n"] or 0, "high": r["high"] or 0, "open": r["open"] or 0}
        ndr = {"n": 0, "high": 0}
        if ip_l:
            ph = ",".join("?" * len(ip_l))
            r = db.one(c, f"""SELECT COUNT(*) n, SUM(severity IN ('Critical','High')) high FROM ndr_alerts WHERE (src_ip IN ({ph}) OR dst_ip IN ({ph}))
                              AND substr(created_at,1,10) BETWEEN ? AND ?""", ip_l + ip_l + [d_from, d_to])
            ndr = {"n": r["n"] or 0, "high": r["high"] or 0}
        sat = None
        sw, sp = [], []
        if ip_l:
            sw.append(f"ip IN ({','.join('?' * len(ip_l))})")
            sp += ip_l
        if hn_l:
            sw.append(f"name_norm IN ({','.join('?' * len(hn_l))})")
            sp += hn_l
        if sw:
            sat = db.one(c, f"""SELECT compliance_passed, compliance_failed, installable_security, errata_security, upgradable
                                FROM satellite_hosts WHERE {' OR '.join(sw)} LIMIT 1""", sp)
        expl = db.one(c, f"SELECT MAX(exploitable) n FROM asset_risk WHERE ip IN ({','.join('?' * len(ip_l))})", ip_l)["n"] if ip_l else None
        blast = None
        if a and a["ip"]:
            g = Graph(c)
            _, _, targets = g.summary(a["ip"], 2)
            d = path_detail(c, a["ip"], 2, g)
            blast = {"reach": len(targets), "weak": sum(1 for t in targets if g.weak(t)), "reached_by": len(d["reached_by"]) if d else 0, "ip": a["ip"]}
        shadow = 0
        if a and a["exposed"]:
            from .commatrix import shadow_ports
            from .registry import exposed_by_itself, is_public
            pubs = [x for x in (a["public_ips"] or "").split(", ") if x] + ([a["ip"]] if exposed_by_itself(a["ip"]) else [])
            shadow = sum(sum(1 for q in shadow_ports(c, pub, [a["ip"]])[0] if q["shadow"] and q["open"]) for pub in pubs[:3])
    if not a:
        return {"score": None, "det": det, "ndr": ndr, "sat": sat, "blast": blast}
    ext = {"det": det, "ndr": ndr, "sat": sat, "exploitable": expl, "shadow": shadow, "weak_reach": (blast or {}).get("weak", 0)}
    pts, f, act = score(a, ext)
    return {"score": pts, "factors": f, "action": act, "det": det, "ndr": ndr, "sat": sat, "blast": blast, "shadow": shadow,
            "level": "Critical" if pts >= 80 else "High" if pts >= 60 else "Medium" if pts >= 35 else "Low"}


# ------------------------------------------------------------------ analyst workload (CrowdStrike + Splunk)
DEMO_ANALYSTS = ["Priya Sharma", "Rahul Verma", "Ankit Mehta", "Neha Kapoor", "Vikram Rao"]
CS_STATUS = {"new": "new", "in_progress": "in_progress", "closed": "closed", "reopened": "reopened"}


def _blank(name):
    return {"analyst": name, "total": 0, "new": 0, "in_progress": 0, "closed": 0, "crit": 0, "high": 0, "hours": [], "last": None}


def _cs_workload(c, d_from, d_to, severity=""):
    out = {}
    w, params = "substr(created_at,1,10) BETWEEN ? AND ?", [d_from, d_to]
    if severity:
        w += " AND severity=?"
        params.append(severity)
    for r in c.execute(f"SELECT assigned_to, status, severity, created_at, updated_at FROM detections WHERE {w}", params):
        name = (r["assigned_to"] or "").strip() or "Unassigned"
        d = out.setdefault(name.lower(), _blank(name))
        d["total"] += 1
        st = (r["status"] or "new").lower()
        d["closed" if st == "closed" else "in_progress" if st == "in_progress" else "new"] += 1
        d["crit"] += r["severity"] == "Critical"
        d["high"] += r["severity"] == "High"
        if st == "closed" and r["updated_at"] and r["created_at"]:
            a, b = db.parse_ts(r["created_at"]), db.parse_ts(r["updated_at"])
            try:
                h = (datetime.fromisoformat(b.replace("Z", "+00:00")) - datetime.fromisoformat(a.replace("Z", "+00:00"))).total_seconds() / 3600
                if h >= 0:
                    d["hours"].append(h)
            except (AttributeError, ValueError):
                pass
        d["last"] = max(filter(None, [d["last"], r["updated_at"] or r["created_at"]]), default=None)
    return out


def _splunk_workload(d_from, d_to, severity=""):
    """{analyst: counts} from ES notables in the range, or (None, reason) when Splunk is not connected."""
    cfg = splunk.settings()
    if config.DEMO:
        start = datetime.strptime(d_from, "%Y-%m-%d")
        days = max(1, (datetime.strptime(d_to, "%Y-%m-%d") - start).days + 1)
        out = {}
        for k, name in enumerate(DEMO_ANALYSTS[1:] + ["Unassigned"]):
            seed = int(hashlib.md5(f"{name}{d_from}{d_to}{severity}".encode()).hexdigest(), 16)
            total = max(0, round(days * ((seed % 4) + (1.5 if name != "Unassigned" else 0.5)) * 0.35 * (0.35 if severity else 1)))
            closed = 0 if name == "Unassigned" else total * (55 + seed % 40) // 100
            prog = 0 if name == "Unassigned" else (total - closed) * (seed % 60) // 100
            d = _blank(name)
            d.update(total=total, closed=closed, in_progress=prog, new=total - closed - prog, crit=total * (seed % 9) // 100,
                     high=total * (15 + seed % 20) // 100, mttr=round(2 + (seed % 400) / 10, 1) if closed else None,
                     last=(start + timedelta(days=days - 1, hours=seed % 20)).strftime("%Y-%m-%dT%H:%M:%SZ") if total else None)
            out[name.lower()] = d
        return out, None
    if not cfg["url"]:
        return None, "Splunk is not connected"
    sev = f' urgency="{severity.lower()}"' if severity else ""
    spl = ('search `notable`' + sev + ' | eval owner=if(isnull(owner) OR owner="" OR owner="unassigned","Unassigned",owner) '
           '| eval u=lower(urgency), closed_t=if(in(status_label,"Closed","Resolved"), review_time, null()) '
           '| stats count AS total count(eval(status_label="New")) AS new count(eval(status_label="In Progress")) AS in_progress '
           'count(eval(in(status_label,"Closed","Resolved"))) AS closed count(eval(u="critical")) AS crit count(eval(u="high")) AS high '
           'avg(eval((closed_t-_time)/3600)) AS mttr max(_time) AS last BY owner')
    try:
        res = splunk._search_window(cfg, spl, d_from, d_to)
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    out = {}
    for r in res:
        name = r.get("owner") or "Unassigned"
        d = _blank(name)
        for k in ("total", "new", "in_progress", "closed", "crit", "high"):
            d[k] = int(float(r.get(k) or 0))
        d["mttr"] = round(float(r["mttr"]), 1) if r.get("mttr") not in (None, "") else None
        d["last"] = datetime.fromtimestamp(float(r["last"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if r.get("last") else None
        out[name.lower()] = d
    return out, None


def _median(xs):
    xs = sorted(xs)
    return round((xs[len(xs) // 2] if len(xs) % 2 else (xs[len(xs) // 2 - 1] + xs[len(xs) // 2]) / 2), 1) if xs else None


def workload(d_from, d_to, severity=""):
    with db.get_conn() as c:
        cs = _cs_workload(c, d_from, d_to, severity)
        cs_fetched = db.one(c, "SELECT MAX(fetched_at) at FROM detections")["at"]
    for d in cs.values():
        d["mttr"] = _median(d.pop("hours"))
    sp, sp_err = _splunk_workload(d_from, d_to, severity)
    for d in (sp or {}).values():
        d.pop("hours", None)
    rows = []
    for key in sorted(set(cs) | set(sp or {})):
        a, b = cs.get(key), (sp or {}).get(key)
        name = (a or b)["analyst"]
        tot = lambda k: (a or {}).get(k, 0) + (b or {}).get(k, 0)  # noqa: E731
        rows.append({"analyst": name, "unassigned": name == "Unassigned", "cs": a, "splunk": b,
                     "total": tot("total"), "closed": tot("closed"), "open": tot("new") + tot("in_progress"), "crit_high": tot("crit") + tot("high"),
                     "closed_pct": round(100 * tot("closed") / tot("total")) if tot("total") else None,
                     "last": max(filter(None, [(a or {}).get("last"), (b or {}).get("last")]), default=None)})
    rows.sort(key=lambda r: (r["unassigned"], -r["total"]))
    assigned = [r for r in rows if not r["unassigned"]]
    kp = lambda src, k: sum(((r[src] or {}).get(k) or 0) for r in rows)  # noqa: E731
    return {"rows": rows, "from": d_from, "to": d_to, "splunk_error": sp_err, "splunk_simulated": config.DEMO, "cs_fetched_at": cs_fetched,
            "kpi": {"analysts": len(assigned), "total": sum(r["total"] for r in rows), "cs_total": kp("cs", "total"), "splunk_total": kp("splunk", "total"),
                    "closed": sum(r["closed"] for r in rows), "open": sum(r["open"] for r in rows),
                    "unassigned": sum(r["total"] for r in rows if r["unassigned"]),
                    "cs_mttr": _median([r["cs"]["mttr"] for r in assigned if r["cs"] and r["cs"]["mttr"] is not None])}}


@router.get("/api/analysts")
def analysts(date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to"), severity: str = ""):
    d_from, d_to = _range(date_from, date_to)
    return workload(d_from, d_to, severity)


@router.get("/api/analysts/alerts")
def analyst_alerts(analyst: str, source: str = "crowdstrike", date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to"),
                   severity: str = "", status: str = ""):
    d_from, d_to = _range(date_from, date_to)
    if source == "splunk":
        cfg = splunk.settings()
        if config.DEMO:
            return {"rows": [], "note": "Sample data: Splunk alert lists are not simulated. With Splunk connected this lists the notables."}
        if not cfg["url"]:
            return {"rows": [], "note": "Splunk is not connected"}
        own = 'owner="unassigned" OR NOT owner=*' if analyst == "Unassigned" else f"owner={splunk._quote(analyst)}"
        sev = f' urgency="{severity.lower()}"' if severity else ""
        spl = (f'search `notable` ({own}){sev} | eval t=strftime(_time, "%Y-%m-%dT%H:%M:%SZ") '
               "| table t rule_name urgency status_label src dest owner | head 1000")
        try:
            res = splunk._search_window(cfg, spl, d_from, d_to)
        except Exception as e:  # noqa: BLE001
            return {"rows": [], "note": str(e)}
        rows = [{"created_at": r.get("t"), "name": r.get("rule_name"), "severity": str(r.get("urgency") or "").title(),
                 "status": r.get("status_label"), "hostname": r.get("dest") or r.get("src"), "src": "Splunk"} for r in res]
        return {"rows": [r for r in rows if not status or (r["status"] or "").lower().replace(" ", "_") == status]}
    w = ["substr(created_at,1,10) BETWEEN ? AND ?"]
    params = [d_from, d_to]
    if analyst == "Unassigned":
        w.append("COALESCE(TRIM(assigned_to),'')=''")
    else:
        w.append("LOWER(assigned_to)=LOWER(?)")
        params.append(analyst)
    if severity:
        w.append("severity=?")
        params.append(severity)
    if status:
        w.append("LOWER(status)=?")
        params.append(status)
    with db.get_conn() as c:
        rows = db.rows(c, f"""SELECT id, aid, hostname, severity, name, tactic, technique, status, created_at, updated_at, assigned_to
                              FROM detections WHERE {' AND '.join(w)} ORDER BY created_at DESC LIMIT 1000""", params)
    return {"rows": rows}


AN_EXPORT = [("analyst", "Analyst"), ("total", "Alerts (both)"), ("closed", "Closed"), ("open", "Open"), ("closed_pct", "Closed %"),
             ("cs_total", "CrowdStrike alerts"), ("cs_closed", "CrowdStrike closed"), ("cs_open", "CrowdStrike open"), ("cs_mttr", "CrowdStrike median hours to close"),
             ("sp_total", "Splunk notables"), ("sp_closed", "Splunk closed"), ("sp_open", "Splunk open"), ("sp_mttr", "Splunk avg hours to close"),
             ("crit_high", "Critical + High"), ("last", "Last activity")]


@router.get("/api/analysts/export")
def analysts_export(request: Request):
    p = dict(request.query_params)
    data = analysts(p.get("from", ""), p.get("to", ""), p.get("severity", ""))
    rows = []
    for r in data["rows"]:
        a, b = r["cs"] or {}, r["splunk"] or {}
        rows.append({**r, "cs_total": a.get("total", 0), "cs_closed": a.get("closed", 0), "cs_open": a.get("new", 0) + a.get("in_progress", 0),
                     "cs_mttr": a.get("mttr"), "sp_total": b.get("total", 0), "sp_closed": b.get("closed", 0),
                     "sp_open": b.get("new", 0) + b.get("in_progress", 0), "sp_mttr": b.get("mttr")})
    return xlsx_response([(f"Analysts {data['from']} to {data['to']}", AN_EXPORT, rows)], "analyst_workload")
