"""Asset 360: one answer per IP / hostname / AID across Falcon, LOB inventories, old EDR imports and vulnerability scans."""
import ipaddress
import json
import re

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


AGENT_COLS = """h.aid, h.hostname, h.hostname_norm, h.local_ip, h.external_ip, h.mac_address, h.platform_name, h.os_version,
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
    return {"mode": "single", "summary": summary, "agents": agents, "inventory": inv, "vulns": vulns, "scans": scans, "history": history, "niam": niam, "ports": ports,
            "flows": commatrix.flows_for(c, ipl) if ipl else []}


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
        return profile(c, q)


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
    s = p["summary"]
    summary = [{"k": k, "v": v} for k, v in [
        ("Query", s["query"]), ("IPs", ", ".join(s["ips"])), ("Hostnames", ", ".join(s["hostnames"])), ("EDR status", s["edr_status"]),
        ("Agent ID", (s["edr_agent"] or {}).get("aid")), ("Active agents", s["active_agents"]), ("LOB", ", ".join(s["lobs"])),
        ("MSP", ", ".join(s["msps"])), ("In inventory", "Yes" if s["in_inventory"] else "No"),
        ("Inventory says EDR installed", ", ".join(s["inventory_claim"])), ("NE ID (NIAM)", ", ".join(s["ne_ids"])), ("Open critical", s["vulns"]["Critical"]),
        ("Open high", s["vulns"]["High"]), ("Open medium", s["vulns"]["Medium"]), ("Open low", s["vulns"]["Low"]),
        ("Fixed", s["vulns"]["fixed"]), ("Last scan", s["last_scan"]),
        ("Risk score", (s["risk"] or {}).get("score")), ("Risk level", (s["risk"] or {}).get("level")),
        ("Risk factors", "; ".join(f"{n} (+{p})" if p else n for n, p in (s["risk"] or {}).get("factors", [])))]]
    return xlsx_response([
        ("Summary", [("k", "Field"), ("v", "Value")], summary),
        ("EDR agents", [("hostname", "Hostname"), ("aid", "Agent ID"), ("local_ip", "IP"), ("edr_status", "Status"), ("os_version", "OS"),
                        ("agent_version", "Sensor"), ("lobs", "LOB"), ("msps", "MSP"), ("first_seen", "First Seen"), ("last_seen", "Last Seen")], p["agents"]),
        ("Inventory", [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("live", "Live"),
                       ("edr_feasible", "EDR Feasible"), ("edr_installed", "EDR Installed"), ("coverage_status", "EDR Status")], p["inventory"]),
        ("Vulnerabilities", [("lob", "LOB"), ("ip", "IP"), ("severity", "Severity"), ("name", "Vulnerability"), ("plugin_id", "Plugin ID"),
                             ("port", "Port"), ("cve", "CVE"), ("status", "Status"), ("first_discovered", "First Discovered"),
                             ("last_observed", "Last Observed")], p["vulns"]),
    ], "asset_" + re.sub(r"[^A-Za-z0-9._-]", "_", q)[:40])
