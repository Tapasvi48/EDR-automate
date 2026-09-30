"""Asset 360: one answer per IP / hostname / AID across Falcon, LOB inventories, old EDR imports and vulnerability scans."""
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter

from . import commatrix, db, queries
from .exporter import xlsx_response

router = APIRouter()

EDR_ORDER = {"Online": 0, "Offline": 1, "Not Installed": 5}


def agent_status(h):
    """Two states: Online, or Offline (offline in the console, or the agent has left it)."""
    if not h:
        return "Not Installed"
    return "Online" if h["console_state"] == "active" and h["online_state"] == "online" else "Offline"


def agent_detail(h):
    if not h:
        return ""
    if h["console_state"] == "active":
        return "in console"
    if h["console_state"] == "hidden":
        return "hidden in console"
    return {"imported": "old EDR inventory upload", "auto_inactive": "removed from console (inactive)",
            "deleted": "deleted from console"}.get(h.get("removal_type") or "", "removed from console")


def agent_rank(h):
    """Best agent first: online, offline in console, hidden, removed / old import; then most recently seen."""
    st = 0 if agent_status(h) == "Online" else 1 if h["console_state"] == "active" else 2 if h["console_state"] == "hidden" else 3
    return (st, -int(re.sub(r"\D", "", h["last_seen"] or "") or 0))


AGENT_COLS = """h.aid, h.hostname, h.hostname_norm, h.local_ip, h.external_ip, h.connection_ip, h.mac_address, h.platform_name, h.os_version,
    h.agent_version, h.product_type_desc, h.console_state, h.online_state, h.removal_type, h.removed_at, h.source,
    h.first_seen, h.last_seen, h.is_reinstall, h.rfm, h.serial_number, h.last_login_user,
    (SELECT GROUP_CONCAT(DISTINCT l.name) FROM host_map x JOIN lobs l ON l.id=x.lob_id WHERE x.aid=h.aid) lobs,
    (SELECT GROUP_CONCAT(DISTINCT m.name) FROM host_map x JOIN msps m ON m.id=x.msp_id WHERE x.aid=h.aid) msps"""


def _in(n):
    return ",".join("?" * n)


def profile(c, q):
    q = q.strip()
    ip_q = db.is_ip(q)
    if ip_q:
        q = db.canon_ip(q)
    hn = "" if ip_q else db.norm_hostname(q)
    ips = {q} if ip_q else set()
    agents = []
    if ip_q:
        agents = db.rows(c, f"SELECT {AGENT_COLS} FROM hosts h WHERE h.console_state<>'hidden' AND (h.local_ip=? OR h.external_ip=? OR h.connection_ip=?)", (q, q, q))
    else:
        agents = db.rows(c, f"SELECT {AGENT_COLS} FROM hosts h WHERE h.console_state<>'hidden' AND (h.aid=? OR h.hostname_norm=?)", (q.lower(), hn))
        ips |= {a["local_ip"] for a in agents if a["local_ip"]}
    inv = db.rows(c, f"""SELECT l.name lob, l.id lob_id, ic.* FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
        WHERE {'ic.ip=?' if ip_q else 'LOWER(ic.node_name)=? OR LOWER(ic.node_name) LIKE ?'}""",
                     (q,) if ip_q else (q.lower(), hn + ".%"))
    if not ip_q:
        ips |= {r["ip"] for r in inv if r["ip"]}
        # an NE ID from the NIAM dump resolves to its host IPs
        ips |= {r["ip"] for r in db.rows(c, "SELECT ip FROM niam_nodes WHERE ne_id=? COLLATE NOCASE AND ip<>''", (q,))}
        if not inv and ips:
            inv = db.rows(c, f"""SELECT l.name lob, l.id lob_id, ic.* FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
                WHERE ic.ip IN ({_in(len(ips))})""", list(ips))
        if not agents and ips:  # found only via inventory / NIAM -> agents on its IPs
            agents = db.rows(c, f"SELECT {AGENT_COLS} FROM hosts h WHERE h.console_state<>'hidden' AND h.local_ip IN ({_in(len(ips))})", list(ips))
    ipl = sorted(ips)
    vulns, counts, scans, history, niam, risk, ports = [], {}, [], [], [], [], []
    if ipl:
        vulns = db.rows(c, f"""SELECT f.id, l.name lob, f.lob_id, f.ip, f.severity, f.sev_rank, f.name, f.plugin_id, f.port, f.protocol,
            f.cve, f.exploit_ease, f.first_discovered, f.last_observed, f.status, f.fixed_at
            FROM vuln_findings f JOIN lobs l ON l.id=f.lob_id WHERE f.ip IN ({_in(len(ipl))})
            ORDER BY f.status='open' DESC, f.sev_rank DESC, f.name LIMIT 1000""", ipl)
        for v in vulns:
            k = v["severity"] if v["status"] == "open" else "fixed"
            counts[k] = counts.get(k, 0) + 1
        scans = db.rows(c, f"""SELECT sh.ip, l.name lob, sh.scanned_at, s.filename FROM vuln_scan_hosts sh JOIN lobs l ON l.id=sh.lob_id
            LEFT JOIN vuln_scans s ON s.id=sh.scan_id WHERE sh.ip IN ({_in(len(ipl))}) ORDER BY sh.scanned_at DESC""", ipl)
        risk = db.rows(c, f"""SELECT r.lob_id, l.name lob, r.ip, r.score, r.level, r.factors FROM asset_risk r JOIN lobs l ON l.id=r.lob_id
            WHERE r.ip IN ({_in(len(ipl))}) ORDER BY r.score DESC""", ipl)
        for x in risk:
            x["factors"] = [f for f in json.loads(x["factors"] or "[]")]
        niam = db.rows(c, f"""SELECT ne_id, host, ip, present, first_seen_at, last_seen_at, removed_at, extra FROM niam_nodes
            WHERE ip IN ({_in(len(ipl))}) ORDER BY present DESC, ne_id""", ipl)
        for n in niam:
            n["extra"] = db.jloads(n["extra"], {})
        history = db.rows(c, f"""SELECT ih.ip, ih.kind, ih.source, ih.first_seen, ih.last_seen, h.aid, h.hostname, h.console_state,
            h.online_state, h.removal_type FROM ip_history ih JOIN hosts h ON h.aid=ih.aid WHERE ih.ip IN ({_in(len(ipl))})
            ORDER BY ih.last_seen DESC LIMIT 500""", ipl)
    # open ports seen by the vulnerability scanner (every finding carries its port / protocol)
    sev_name = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
    by_port = {}
    for v in vulns:
        if str(v.get("port") or "") in ("", "0"):
            continue
        k = (v["ip"], v["port"], v["protocol"] or "")
        pt = by_port.setdefault(k, {"ip": v["ip"], "port": v["port"], "protocol": v["protocol"] or "", "findings": 0, "open_findings": 0,
                                    "max_rank": None, "last_observed": None, "names": []})
        pt["findings"] += 1
        pt["last_observed"] = max(pt["last_observed"] or "", v["last_observed"] or "") or None
        if v["status"] == "open":
            pt["open_findings"] += 1
            pt["max_rank"] = max(pt["max_rank"] if pt["max_rank"] is not None else -1, v["sev_rank"])
            if v["sev_rank"] >= 1 and v["name"] not in pt["names"]:
                pt["names"].append(v["name"])
    ports = sorted(by_port.values(), key=lambda x: (int(re.sub(r"\D", "", str(x["port"])) or 0), x["protocol"], x["ip"]))
    for pt in ports:
        pt["max_severity"] = sev_name.get(pt["max_rank"]) if pt["max_rank"] is not None else None
    for a in agents:
        a["edr_status"] = agent_status(a)
        a["edr_detail"] = agent_detail(a)
    agents.sort(key=agent_rank)
    best = agents[0] if agents else None
    summary = {
        "query": q, "found": bool(agents or inv or vulns or niam),
        "ips": ipl, "hostnames": sorted({a["hostname"] for a in agents if a["hostname"]} | {r["node_name"] for r in inv if r["node_name"]}),
        "edr_status": best["edr_status"] if best else "Not Installed",
        "edr_agent": best, "edr_detail": best["edr_detail"] if best else "", "active_agents": sum(1 for a in agents if a["console_state"] == "active"),
        "lobs": sorted({r["lob"] for r in inv} | {x for a in agents for x in (a["lobs"] or "").split(",") if x}),
        "msps": sorted({r["msp"] for r in inv if r["msp"]} | {x for a in agents for x in (a["msps"] or "").split(",") if x}),
        "in_inventory": bool(inv),
        "inventory_claim": sorted({r["edr_installed"] for r in inv if r["edr_installed"]}),
        "vulns": {k: counts.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Info", "fixed")},
        "last_scan": scans[0]["scanned_at"] if scans else None,
        "risk": risk[0] if risk else None,
        "exposure": [e for r in (db.rows(c, f"SELECT exposure FROM asset_registry WHERE ip IN ({_in(len(ipl))}) AND exposed=1", ipl) if ipl else [])
                     for e in json.loads(r["exposure"] or "[]")],
        "ne_ids": sorted({n["ne_id"] for n in niam if n["present"] and n["ne_id"]}),
    }
    reg = db.one(c, f"""SELECT os, os_source, feasibility, feasibility_reason FROM asset_registry WHERE ip IN ({_in(len(ipl))})
                       ORDER BY in_inventory DESC, COALESCE(os,'')='' LIMIT 1""", ipl) if ipl else None
    summary.update(os=reg["os"] if reg else None, os_source=reg["os_source"] if reg else None,
                   feasibility=reg["feasibility"] if reg else None, feasibility_reason=reg["feasibility_reason"] if reg else None)
    from .satellite import cve_fixes, fix_for
    fixes = cve_fixes(c, ipl)
    for v in vulns:  # Nessus CVE -> the Satellite erratum that fixes it on this host
        v["fix"] = fix_for(fixes, v["ip"], v.get("cve"))
    flows = commatrix.flows_for(c, ipl) if ipl else []
    for r in inv:  # where each inventory record comes from (manual upload today; ServiceNow CMDB / Jaspersoft later)
        v = db.one(c, """SELECT v.version_no, v.filename, v.uploaded_at, v.uploaded_by FROM inventory_versions v
                         JOIN inventory_current ic ON ic.lob_id=v.lob_id WHERE v.lob_id=? AND ic.item_key=?
                         AND v.version_no=ic.last_changed_version_no AND COALESCE(v.type_id,0)=COALESCE(ic.type_id,0) LIMIT 1""",
                   (r["lob_id"], r["item_key"]))
        r["source"] = {"kind": "manual", "label": "Manual upload", **(v or {})}
    return {"mode": "single", "summary": summary, "agents": agents, "inventory": inv, "vulns": vulns, "scans": scans, "history": history,
            "niam": niam, "ports": ports, "flows": flows, "internet": internet_detail(c, ipl, agents, flows)}


# ------------------------------------------------------------------ SOD exceptions, related assets, last known good
@router.get("/api/asset/context")
def asset_context(ips: str = "", names: str = "", aids: str = ""):
    """Exceptions touching the asset, related assets and 'last known good' timestamps (loaded after the main profile)."""
    ipl = [db.canon_ip(i) for i in ips.split(",") if i]
    hn = [db.norm_hostname(h) for h in names.split(",") if h]
    aid_l = [a for a in aids.split(",") if a]
    with db.get_conn() as c:
        return {"exceptions": asset_exceptions(c, ipl), "related": related_assets(c, ipl, hn),
                "last_good": last_known_good(c, ipl, hn, aid_l)}


def asset_exceptions(c, ipl):
    """SOD exceptions covering at least one finding of this asset (active or expired), with days left."""
    import ipaddress
    from .sod import _cves, _status, today
    if not ipl:
        return []
    fnd = db.rows(c, f"""SELECT f.id, f.ip, f.lob_id, l.name lob, f.plugin_id, f.cve, f.name, f.port, f.status, f.exception_ref
                         FROM vuln_findings f JOIN lobs l ON l.id=f.lob_id WHERE f.ip IN ({_in(len(ipl))}) AND f.status<>'fixed'""", ipl)
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    out = []
    for e in db.rows(c, "SELECT * FROM vuln_exceptions"):
        net = db.parse_net(e["target"]) if e["scope"] == "Subnet" else None
        hits = []
        for f in fnd:
            same = ((e["plugin_id"] and e["plugin_id"] == f["plugin_id"]) or (set(_cves(e["cve"])) & set(_cves(f["cve"])))
                    or (e["name"] and e["name"].strip().lower() == (f["name"] or "").strip().lower()))
            if not same or (e["port"] and e["port"] != str(f["port"] or "")):
                continue
            if e["scope"] == "IP" and f["ip"] != e["target"]:
                continue
            if e["scope"] == "Subnet":
                try:
                    if not net or ipaddress.ip_address(f["ip"]) not in net:
                        continue
                except ValueError:
                    continue
            if e["scope"] == "LOB" and (f["lob"] or "").lower() != (e["lob"] or "").strip().lower():
                continue
            hits.append(f)
        if not hits:
            continue
        days = None
        if e["valid_till"]:
            try:
                days = (datetime.strptime(e["valid_till"][:10], "%Y-%m-%d").date() - datetime.now(timezone.utc).date()).days
            except ValueError:
                pass
        out.append({**{k: e[k] for k in ("exception_id", "scope", "target", "lob", "plugin_id", "cve", "name", "justification", "control",
                                         "approved_by", "valid_till", "ticket")},
                    "status": _status(e, now, soon), "days_left": days, "findings": len(hits),
                    "accepted": sum(1 for f in hits if f["status"] == "accepted" and f["exception_ref"] == e["exception_id"]),
                    "finding_names": sorted({f["name"] for f in hits})[:5]})
    return sorted(out, key=lambda x: (x["days_left"] if x["days_left"] is not None else 99999))


def related_assets(c, ipl, hn):
    """Assets worth looking at alongside this one during an incident."""
    import ipaddress
    out = []

    def add(kind, why, rows):
        for r in rows:
            if r["ip"] in ipl:
                continue
            out.append({"kind": kind, "why": why, **r})

    cols = "r.ip, r.name, r.lobs, r.edr_status, r.crit, r.high, r.exposed"
    for ip in ipl:  # same subnet (/24 IPv4, /64 IPv6)
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        net = ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 64}", strict=False)
        if a.version == 4:
            rows = db.rows(c, f"SELECT {cols} FROM asset_registry r WHERE r.ip_num BETWEEN ? AND ? ORDER BY (r.crit + r.high) DESC, r.ip_num LIMIT 40",
                           (int(net.network_address), int(net.broadcast_address)))
        else:
            rows = db.rows(c, f"SELECT {cols} FROM asset_registry r WHERE ip_in(r.ip, ?) LIMIT 40", (str(net),))
        add("Same subnet", str(net), rows)
    for h in hn:  # same hostname family: abc -> abc1, abc2 ...
        stem = re.sub(r"[-_]?\d+$", "", h)
        if len(stem) >= 3:
            rows = db.rows(c, f"""SELECT {cols} FROM asset_registry r WHERE LOWER(r.name) LIKE ? AND r.ip IS NOT NULL LIMIT 30""", (stem + "%",))
            add("Same name family", f"{stem}*", [r for r in rows if db.norm_hostname((r["name"] or "").split(",")[0]) != h])
    if ipl:  # shares a public / NAT IP
        reg = db.rows(c, f"SELECT public_ips FROM asset_registry WHERE ip IN ({_in(len(ipl))})", ipl)
        for p in {x for r in reg for x in (r["public_ips"] or "").split(", ") if x}:
            add("Same public / NAT IP", p, db.rows(c, f"SELECT {cols} FROM asset_registry r WHERE r.public_ips LIKE ?", (f"%{p}%",)))
        # can talk to it / it can talk to: communication-matrix peers (single IPs only)
        for f in commatrix.flows_for(c, ipl)[:100]:
            other = f["src"] if f["role"] == "Destination" else f["dst"]
            for ip in db.all_ips(other)[:5]:
                if "/" in str(other) and ip == str(other).split("/")[0]:
                    continue
                add("Talks to it" if f["role"] == "Destination" else "It talks to", f"rule {f['rule_id']} {(f['protocol'] or 'any').upper()} {f['ports'] or 'any'}",
                    db.rows(c, f"SELECT {cols} FROM asset_registry r WHERE r.ip=?", (ip,)))
    seen, uniq = set(), []
    for r in out:
        k = (r["kind"], r["ip"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq[:200]


def last_known_good(c, ipl, hn, aids):
    """When each source last saw the host - the 'last known good' baseline for an incident timeline."""
    q = lambda sql, p: (db.one(c, sql, p) or {}).get("v")  # noqa: E731
    ip_ph, aid_ph = _in(max(len(ipl), 1)), _in(max(len(aids), 1))
    ipx, aidx = (ipl or [""]), (aids or [""])
    items = [
        ("CrowdStrike check-in", q(f"SELECT MAX(last_seen) v FROM hosts WHERE aid IN ({aid_ph})", aidx), "agent last reported to the Falcon cloud"),
        ("Last CrowdStrike detection", q(f"SELECT MAX(created_at) v FROM detections WHERE aid IN ({aid_ph})", aidx), "most recent alert on the agent"),
        ("Last Seceon NDR alert", q(f"SELECT MAX(created_at) v FROM ndr_alerts WHERE src_ip IN ({ip_ph}) OR dst_ip IN ({ip_ph})", ipx + ipx), "network detection"),
        ("Last VA scan", q(f"SELECT MAX(scanned_at) v FROM vuln_scan_hosts WHERE ip IN ({ip_ph})", ipx), "vulnerability scanner reached it"),
        ("Satellite check-in", q(f"SELECT MAX(last_checkin) v FROM satellite_hosts WHERE ip IN ({ip_ph})", ipx), "patching agent reported"),
        ("Last MBSS report", q(f"SELECT MAX(compliance_at) v FROM satellite_hosts WHERE ip IN ({ip_ph})", ipx), "OpenSCAP compliance run"),
        ("In NIAM dump", q(f"SELECT MAX(last_seen_at) v FROM niam_nodes WHERE ip IN ({ip_ph}) AND present=1", ipx), "network element inventory"),
    ]
    return [{"label": l, "at": v, "hint": h} for l, v, h in items]


def internet_detail(c, ipl, agents, flows):
    """How (and whether) the asset is reachable from the internet, method by method."""
    from .registry import is_cgnat, is_public
    reg = db.rows(c, f"""SELECT ip, exposed, whitelisted, cgnat, exposure, public_ips, nat_of FROM asset_registry
                         WHERE ip IN ({_in(len(ipl))})""", ipl) if ipl else []
    reasons = [e for r in reg for e in json.loads(r["exposure"] or "[]")]
    public = sorted({p for r in reg for p in (r["public_ips"] or "").split(", ") if p} | {ip for ip in ipl if is_public(ip)})
    verdict = ("exposed" if any(r["exposed"] for r in reg) else "whitelisted" if any(r["whitelisted"] for r in reg)
               else "cgnat" if any(r["cgnat"] for r in reg) else "not_exposed")
    # method 1: communication matrix - inbound Internet / ISP rules, via which firewall / ISP link, zones and NAT
    matrix = [{k: f.get(k) for k in ("rule_id", "direction", "src_zone", "src", "src_nat", "isp", "firewall", "fw_rule", "dst_zone",
                                     "dst_nat", "dst", "protocol", "ports", "service", "action", "cr", "valid_till", "remarks")}
              | {"path": "ISP link" if f.get("isp") else "Firewall" if f.get("firewall") else "Rule"}
              for f in flows if f.get("inbound_internet")]
    # method 2: a VA scan caught a public IP of the asset (its own, or its public / NAT IP)
    scanned = []
    for ip in public:
        a = db.one(c, """SELECT MAX(last_scanned_at) at, SUM(crit) crit, SUM(high) high, SUM(med) med, SUM(low) low
                         FROM vuln_assets WHERE ip=?""", (ip,))
        scanned.append({"ip": ip, "cgnat": is_cgnat(ip), "scanned": bool(a and a["at"]), "last_scan": a["at"] if a else None,
                        **{k: (a[k] or 0) if a else 0 for k in ("crit", "high", "med", "low")}})
    # method 3: what CrowdStrike reports - the agent's own interface IPs and the public (egress) IP it connects from
    cs = [{"aid": a["aid"], "hostname": a["hostname"], "local_ip": a["local_ip"], "connection_ip": a.get("connection_ip"),
           "external_ip": a["external_ip"], "public_on_nic": bool(a["local_ip"] and is_public(a["local_ip"])),
           "egress_public": bool(a["external_ip"] and is_public(a["external_ip"]))} for a in agents]
    # real exposure check: ports the scan saw open on each public IP vs the ports the inbound rules allow
    shadow = []
    for ip in public:
        ports, _ = commatrix.shadow_ports(c, ip, ipl)
        shadow += ports
    return {"verdict": verdict, "reasons": reasons, "public_ips": public, "internal_ip": next((ip for ip in ipl if not is_public(ip)), None), "matrix": matrix, "scan": scanned, "crowdstrike": cs,
            "inventory": [e for e in reasons if e.get("src") == "inventory"], "ports": shadow,
            "shadow": sum(1 for p in shadow if p["shadow"])}


def ip_sort_key(r):
    try:
        a = ipaddress.ip_address(r["ip"])
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def is_range(q):
    """CIDR (v4/v6), IPv4 prefix ("10.1."), or an IPv6 text prefix ending in ':' ("2001:db8:")."""
    return db.is_range_query(q) or (not db.is_ip(q) and bool(re.fullmatch(r"[0-9a-fA-F:]+:", q)))


def range_rows(c, q):
    q = q.strip()
    lo, hi = queries.cidr_range(q)
    if lo is not None:  # IPv4 network or prefix: indexed integer range
        cond_h, cond_i, cond_v, prm = "h.local_ip_num BETWEEN ? AND ?", "ic.ip IS NOT NULL", "a.ip_num BETWEEN ? AND ?", [lo, hi]
    elif db.parse_net(q):  # IPv6 network
        cond_h, cond_i, cond_v, prm = "ip_in(h.local_ip, ?)", "ip_in(ic.ip, ?)", "ip_in(a.ip, ?)", [q]
    else:  # IPv6 text prefix such as "2001:db8:"
        pre = q.lower()
        cond_h, cond_i, cond_v, prm = "h.local_ip LIKE ?", "ic.ip LIKE ?", "a.ip LIKE ?", [pre + "%"]
    ips = {}

    def slot(ip):
        return ips.setdefault(ip, {"ip": ip, "hostname": None, "edr_status": "Not Installed", "agents": 0, "aid": None, "lobs": set(),
                                   "msps": set(), "in_inventory": False, "crit": 0, "high": 0, "med": 0, "low": 0, "last_scan": None,
                                   "node_name": None, "last_seen": None, "ne_ids": set(), "risk": None})
    for h in db.rows(c, f"""SELECT aid, hostname, local_ip, console_state, online_state, removal_type, last_seen FROM hosts h
                            WHERE h.console_state<>'hidden' AND {cond_h} ORDER BY console_state='active' DESC, online_state='online' DESC, last_seen DESC LIMIT 20000""", prm):
        s = slot(h["local_ip"])
        s["agents"] += 1 if h["console_state"] == "active" else 0
        st = agent_status(h)
        if s.get("_rank") is None or agent_rank(h) < s["_rank"]:
            s.update(edr_status=st, hostname=h["hostname"], aid=h["aid"], last_seen=h["last_seen"], _rank=agent_rank(h))
    inv_rows = db.rows(c, f"""SELECT ic.ip, ic.node_name, l.name lob, ic.msp FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
                             WHERE {cond_i}""", [] if lo is not None else prm)
    for r in inv_rows:
        n = db.ip_to_num(r["ip"])
        if lo is not None and (n is None or not lo <= n <= hi):
            continue
        s = slot(r["ip"])
        s["in_inventory"] = True
        s["node_name"] = s["node_name"] or r["node_name"]
        s["lobs"].add(r["lob"])
        if r["msp"]:
            s["msps"].add(r["msp"])
    for a in db.rows(c, f"""SELECT a.ip, l.name lob, a.msp, a.crit, a.high, a.med, a.low, a.last_scanned_at FROM vuln_assets a
                            JOIN lobs l ON l.id=a.lob_id WHERE {cond_v}""", prm):
        s = slot(a["ip"])
        for k in ("crit", "high", "med", "low"):
            s[k] += a[k] or 0
        s["lobs"].add(a["lob"])
        if a["msp"]:
            s["msps"].add(a["msp"])
        s["last_scan"] = max(s["last_scan"] or "", a["last_scanned_at"] or "") or None
    for x in db.rows(c, f"SELECT a.ip, MAX(a.score) score FROM asset_risk a WHERE a.ip IS NOT NULL AND {cond_v} GROUP BY a.ip", prm):
        s = slot(x["ip"])
        s["risk"] = x["score"]
    for n in db.rows(c, f"SELECT n.ip, n.ne_id FROM niam_nodes n WHERE n.present=1 AND {cond_v.replace('a.', 'n.')}", prm):
        s = slot(n["ip"])
        s["ne_ids"].add(n["ne_id"])
    out = sorted(ips.values(), key=ip_sort_key)
    for r in out:
        r.pop("_rank", None)
        r["lobs"], r["msps"], r["ne_ids"] = ", ".join(sorted(r["lobs"])), ", ".join(sorted(r["msps"])), ", ".join(sorted(r["ne_ids"]))
    return out[:5000]


@router.get("/api/asset")
def asset(q: str = ""):
    q = (q or "").strip()
    if not q:
        return {"mode": "empty"}
    with db.get_conn() as c:
        if is_range(q):
            rows = range_rows(c, q)
            return {"mode": "range", "rows": rows, "total": len(rows)}
        p = profile(c, q)
        if not p["summary"]["found"] and not db.is_ip(q) and len(q) >= 2:
            rows = name_rows(c, q)  # part of a hostname / node name: pick from the list
            if rows:
                return {"mode": "range", "rows": rows, "total": len(rows), "by_name": True}
        return p


def name_rows(c, q):
    like = f"%{q.lower()}%"
    ips = {r["local_ip"] for r in c.execute("""SELECT local_ip FROM hosts WHERE console_state<>'hidden' AND LOWER(hostname) LIKE ?
                                              AND COALESCE(local_ip,'')<>'' LIMIT 300""", (like,))}
    ips |= {r["ip"] for r in c.execute("SELECT ip FROM inventory_current WHERE LOWER(node_name) LIKE ? AND COALESCE(ip,'')<>'' LIMIT 300", (like,))}
    out = []
    for ip in sorted(ips, key=lambda i: ip_sort_key({"ip": i}))[:300]:
        out += range_rows(c, ip)
    return out


RANGE_COLS = [("ip", "IP"), ("risk", "Risk Score"), ("ne_ids", "NE ID"), ("hostname", "Falcon Hostname"), ("node_name", "Inventory Node Name"), ("edr_status", "EDR Status"),
              ("agents", "Active Agents"), ("lobs", "LOB"), ("msps", "MSP"), ("in_inventory", "In Inventory"), ("crit", "Critical"),
              ("high", "High"), ("med", "Medium"), ("low", "Low"), ("last_scan", "Last Scan"), ("last_seen", "EDR Last Seen")]


@router.get("/api/asset/export")
def asset_export(q: str = ""):
    with db.get_conn() as c:
        if is_range(q.strip()):
            rows = range_rows(c, q)
            for r in rows:
                r["in_inventory"] = "Yes" if r["in_inventory"] else "No"
            return xlsx_response([("Assets", RANGE_COLS, rows)], "asset_search")
        p = profile(c, q)
    return evidence_pack(q, p)


def evidence_pack(q, p):
    """One workbook with everything Asset 360 shows, for audits and incident tickets."""
    from .cs_posture import asset_crowdstrike
    from .detections import asset_detections
    from .satellite import asset_satellite
    from .splunk import asset_splunk
    s, i = p["summary"], p["internet"]
    aids = ",".join(a["aid"] for a in p["agents"])
    names = ",".join(h for h in s["hostnames"] if h)
    det = asset_detections(aids=aids, hostnames=names, date_from=(datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d"), date_to="")
    sat = asset_satellite(ips=",".join(s["ips"]), names=names, errata="all")
    cs = asset_crowdstrike(aids=aids, ips=",".join(s["ips"]))
    spl = asset_splunk(hosts=names, ips=",".join(s["ips"]))
    from .seceon import asset_ndr
    from .splunk import asset_splunk_detections
    d90 = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    ndr = asset_ndr(ips=",".join(s["ips"]), hosts=names, date_from=d90, date_to="")
    snot = asset_splunk_detections(hosts=names, ips=",".join(s["ips"]), date_from=d90, date_to="")
    ctx = asset_context(ips=",".join(s["ips"]), names=names, aids=aids)
    sh = (sat["hosts"] or [{}])[0]
    pol = (cs["posture"] or [{}])[0]
    summary = [{"k": k, "v": v} for k, v in [
        ("Evidence pack generated", db.now_iso()), ("Query", s["query"]), ("IPs", ", ".join(s["ips"])), ("Hostnames", ", ".join(s["hostnames"])),
        ("OS", s.get("os")), ("EDR status", s["edr_status"]), ("Agent ID", (s["edr_agent"] or {}).get("aid")),
        ("Sensor version", (s["edr_agent"] or {}).get("agent_version")), ("Prevention policy", pol.get("policy")),
        ("Policy applied", pol.get("applied")), ("EDR feasibility", s.get("feasibility")),
        ("LOB", ", ".join(s["lobs"])), ("MSP", ", ".join(s["msps"])), ("In inventory", "Yes" if s["in_inventory"] else "No"),
        ("NE ID (NIAM)", ", ".join(s["ne_ids"])), ("Internet exposure", i["verdict"]), ("Public / NAT IPs", ", ".join(i["public_ips"])),
        ("Shadow-exposed ports", i["shadow"]), ("Open critical", s["vulns"]["Critical"]), ("Open high", s["vulns"]["High"]),
        ("Open medium", s["vulns"]["Medium"]), ("Open low", s["vulns"]["Low"]), ("Last VA scan", s["last_scan"]),
        ("CrowdStrike detections (90 days)", len(det["rows"])), ("Splunk notables (90 days)", len(snot.get("rows") or [])),
        ("Seceon NDR alerts (90 days)", len(ndr.get("rows") or [])),
        ("SOD exceptions covering it", len(ctx["exceptions"])), ("Spotlight open vulnerabilities", len(cs["spotlight"])),
        ("Satellite: security errata applicable", sh.get("errata_security")), ("Satellite: fixes installable now", sh.get("installable_security")),
        ("MBSS compliance %", sh.get("compliance_pct")), ("Splunk: indexes with logs", len(spl.get("rows") or [])),
        ("Risk score", (s["risk"] or {}).get("score")), ("Risk level", (s["risk"] or {}).get("level")),
        ("Risk factors", "; ".join(f"{n} (+{pt})" if pt else n for n, pt in (s["risk"] or {}).get("factors", [])))]]
    for v in p["vulns"]:
        v["fix_text"] = ", ".join(e["id"] for e in v.get("fix") or [])
    for x in i["ports"]:
        x["shadow_text"] = "SHADOW - no rule" if x["shadow"] else "allowed"
        x["rules_text"] = ", ".join(x["rules"])
    exposure = [{"method": e["src"], "evidence": e["text"]} for e in i["reasons"]]
    return xlsx_response([
        ("Summary", [("k", "Field"), ("v", "Value")], summary),
        ("Internet exposure", [("method", "Method"), ("evidence", "Evidence")], exposure),
        ("Matrix rules", [("rule_id", "Rule"), ("path", "Path"), ("isp", "ISP / Link"), ("firewall", "Firewall"), ("fw_rule", "FW Rule"),
                          ("src_zone", "Source Zone"), ("src", "Source"), ("dst_zone", "Destination Zone"), ("dst_nat", "Public / NAT IP"),
                          ("dst", "Destination"), ("protocol", "Protocol"), ("ports", "Ports"), ("service", "Service"), ("cr", "CR"),
                          ("valid_till", "Valid Till")], i["matrix"]),
        ("Public ports vs rules", [("ip", "Public IP"), ("port", "Port"), ("protocol", "Protocol"), ("open", "Open Findings"),
                                   ("shadow_text", "Result"), ("rules_text", "Allowed By")], i["ports"]),
        ("Detections 90d", [("created_at", "Created"), ("severity", "Severity"), ("name", "Detection"), ("tactic", "Tactic"),
                            ("technique", "Technique"), ("hostname", "Host"), ("filename", "Process"), ("cmdline", "Command Line"),
                            ("disposition", "Action Taken"), ("status", "Status")], det["rows"]),
        ("Splunk notables 90d", [("created_at", "Time"), ("severity", "Urgency"), ("name", "Rule"), ("category", "Domain"), ("src", "Source"),
                                 ("dest", "Destination"), ("host", "Host"), ("status", "Status")], snot.get("rows") or []),
        ("Seceon NDR 90d", [("created_at", "Time"), ("severity", "Severity"), ("name", "Alert"), ("category", "Category"), ("src_ip", "Source IP"),
                            ("dst_ip", "Destination IP"), ("host", "Host"), ("status", "Status"), ("source", "Received via")], ndr.get("rows") or []),
        ("SOD exceptions", [("exception_id", "Exception"), ("status", "Status"), ("valid_till", "Valid Till"), ("days_left", "Days Left"),
                            ("scope", "Scope"), ("target", "IP / Subnet"), ("lob", "LOB"), ("findings", "Findings Covered"),
                            ("accepted", "Accepted Now"), ("approved_by", "Approved By"), ("justification", "Justification"),
                            ("ticket", "Ticket")], ctx["exceptions"]),
        ("Last known good", [("label", "Source"), ("at", "Last Seen"), ("hint", "Meaning")], ctx["last_good"]),
        ("Related assets", [("kind", "Relation"), ("why", "Why"), ("ip", "IP"), ("name", "Name"), ("lobs", "LOB"), ("edr_status", "EDR"),
                            ("crit", "Critical"), ("high", "High"), ("exposed", "Internet Exposed")], ctx["related"]),
        ("Vulnerabilities", [("lob", "LOB"), ("ip", "IP"), ("severity", "Severity"), ("name", "Vulnerability"), ("plugin_id", "Plugin ID"),
                             ("port", "Port"), ("cve", "CVE"), ("status", "Status"), ("fix_text", "Fix Available (Satellite)"),
                             ("first_discovered", "First Discovered"), ("last_observed", "Last Observed")], p["vulns"]),
        ("Open ports", [("ip", "IP"), ("port", "Port"), ("protocol", "Protocol"), ("max_severity", "Worst Open Finding"),
                        ("open_findings", "Open Findings"), ("last_observed", "Last Observed")], p["ports"]),
        ("Spotlight", [("cve", "CVE"), ("severity", "Severity"), ("score", "CVSS"), ("exprt", "ExPRT"), ("product", "Product"),
                       ("remediation", "Remediation"), ("in_scanner", "Also in VA scan"), ("created_at", "Found")], cs["spotlight"]),
        ("Satellite errata", [("errata_id", "Erratum"), ("severity", "Severity"), ("type", "Type"), ("title", "Title"), ("cves", "CVEs"),
                              ("installable", "Installable Now"), ("issued", "Issued")], sat["errata"]),
        ("MBSS failed rules", [("control", "Control"), ("rule_id", "Rule"), ("title", "Title"), ("severity", "Severity"), ("fix", "Remediation")],
         sat.get("mbss") or []),
        ("Splunk logging", [("host", "Host"), ("index", "Index"), ("sourcetype", "Sourcetype"), ("count", "Events"), ("last_seen", "Last Event")],
         spl.get("rows") or []),
        ("EDR agents", [("hostname", "Hostname"), ("aid", "Agent ID"), ("local_ip", "IP"), ("edr_status", "Status"), ("os_version", "OS"),
                        ("agent_version", "Sensor"), ("lobs", "LOB"), ("msps", "MSP"), ("first_seen", "First Seen"), ("last_seen", "Last Seen")], p["agents"]),
        ("Inventory", [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("live", "Live"),
                       ("edr_feasible", "EDR Feasible"), ("edr_installed", "EDR Installed"), ("coverage_status", "EDR Status")], p["inventory"]),
    ], "evidence_" + re.sub(r"[^A-Za-z0-9._-]", "_", q)[:40])
