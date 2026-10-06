"""Data-fabric ontology: the entity types the console knows, the relationships between them, and a graph you can walk.

Every source the console holds (CrowdStrike agents / detections / Spotlight / policies, LOB inventories, VA scans, the
communication matrix, exposure, WHOIS, NDR alerts, IOC checks) is one of these entity types, linked by typed relationships:

  Agent ─runs on→ Asset ─has IP→ IP ─in subnet→ Subnet            Asset ─owned by→ LOB ←works for─ MSP
  Detection ─fired on→ Agent   Detection ─maps to→ Tactic   Detection ─involves→ File   User ─last logged on→ Agent
  Agent ─vulnerable to→ CVE    IP ─scan finding→ CVE        Agent ─enforces→ Policy
  IP ─NATs to→ Public IP ─registered to→ Network block      Matrix rule ─allows flow→ IP      NDR alert ─involves→ IP

  /api/fabric/ontology   the schema: entity types and relationship types with live counts and sources
  /api/fabric/node       one entity (type:key): its properties and its neighbours, grouped by relationship — click to walk
  /api/fabric/path       how two entities are connected (shortest path, breadth-first, bounded)
  /api/fabric/search     find entities of any type by name, IP, CVE, user…

The AI SOC uses the same neighbours as context (what is this asset linked to?) and the analyst sees the same graph.
Splunk and NDR sources plug in as more entity / relationship types over the same keys (IP, hostname, user, hash)."""
import ipaddress
import re

from fastapi import APIRouter, HTTPException

from . import db

router = APIRouter()

# id: (label, class, source, description)
TYPES = {
    "asset": ("Asset", "Device", "Inventory · CrowdStrike · VA · NIAM", "a machine, keyed by IP — the join point of every source"),
    "agent": ("CrowdStrike agent", "Device (sensor)", "CrowdStrike Hosts API", "a Falcon sensor (agent ID) with OS, version, state, policy"),
    "ip": ("IP address", "Network endpoint", "every source", "an internal or public IPv4 address"),
    "subnet": ("Subnet", "Network", "derived (/24)", "the /24 an IP sits in"),
    "lob": ("Line of business", "Organization", "LOB inventories", "the business unit that owns assets"),
    "msp": ("MSP", "Organization", "LOB inventories", "the service provider that runs assets for a LOB"),
    "user": ("User account", "User", "CrowdStrike", "an account seen logging on to agents"),
    "detection": ("Detection", "Detection finding", "CrowdStrike Alerts", "a CrowdStrike alert"),
    "tactic": ("MITRE tactic", "Attack", "MITRE ATT&CK via CrowdStrike", "the attacker goal a detection maps to"),
    "file": ("Process / file", "File", "CrowdStrike Alerts", "the process or file a detection involves"),
    "cve": ("Vulnerability (CVE)", "Vulnerability", "Spotlight · VA scans", "a CVE open on agents or scanned IPs"),
    "policy": ("Prevention policy", "Policy", "CrowdStrike Policies", "the prevention policy an agent enforces"),
    "ndr": ("NDR alert", "Network activity", "Seceon NDR", "a network detection between two IPs"),
    "rule": ("Matrix rule", "Network rule", "Communication matrix", "an allowed flow (source → destination, ports)"),
    "netblock": ("Network block", "Organization", "WHOIS / RDAP", "who a public IP range is registered to"),
    "ioc": ("Checked IOC", "Indicator", "IOC checks", "an IP / domain / hash checked against threat intel"),
    "scan": ("VA scan", "Scan", "VA scan uploads", "one vulnerability scan upload of a LOB"),
    "vapub": ("VA public entry", "Exposure record", "VA public inventory", "a public IP ↔ private IP row handed to the VA team"),
    "satellite": ("Satellite host", "Device (patching)", "Red Hat Satellite", "a Linux host with its errata and MBSS compliance"),
    "niam": ("NIAM node", "Network element", "NIAM dump", "a network element (NE ID) and its IP"),
    "exception": ("Risk exception", "Exception", "SOD uploads", "an accepted vulnerability (IP / subnet / LOB scope, expiry)"),
    "service": ("Internet service", "Network service", "Internet DB scan", "an open port seen from the internet on a public IP"),
    "sensor": ("Sensor build", "Software", "CrowdStrike", "a Falcon sensor version and its N / N-1 / N-2 level"),
    "loghost": ("Splunk log host", "Log source", "Splunk", "a host sending events to Splunk, with its indexes and last event"),
    "notable": ("Splunk notable", "Detection finding", "Splunk ES", "an Enterprise Security notable event"),
}
# (from, to, label, source, count SQL)
RELS = [
    ("agent", "asset", "runs on", "CrowdStrike ↔ inventory match", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(aid,'')<>''"),
    ("asset", "ip", "has IP", "inventory / CrowdStrike", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(ip,'')<>''"),
    ("ip", "subnet", "in subnet", "derived", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(ip,'')<>'' AND COALESCE(is_public,0)=0"),
    ("asset", "lob", "owned by", "LOB inventory", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(lobs,'')<>''"),
    ("asset", "msp", "managed by", "LOB inventory", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(msps,'')<>''"),
    ("msp", "lob", "works for", "LOB setup", "SELECT COUNT(*) FROM msps"),
    ("agent", "policy", "enforces", "CrowdStrike Policies", "SELECT COUNT(*) FROM hosts WHERE COALESCE(prevention_policy_id,'')<>''"),
    ("user", "agent", "last logged on", "CrowdStrike Hosts", "SELECT COUNT(*) FROM hosts WHERE COALESCE(last_login_user,'')<>''"),
    ("detection", "agent", "fired on", "CrowdStrike Alerts", "SELECT COUNT(*) FROM detections"),
    ("detection", "tactic", "maps to", "MITRE ATT&CK", "SELECT COUNT(*) FROM detections WHERE COALESCE(tactic,'')<>''"),
    ("detection", "file", "involves", "CrowdStrike Alerts", "SELECT COUNT(*) FROM detections WHERE COALESCE(filename,'')<>''"),
    ("agent", "cve", "vulnerable to", "CrowdStrike Spotlight", "SELECT COUNT(*) FROM spotlight_vulns"),
    ("ip", "cve", "scan finding", "VA scans", "SELECT COUNT(*) FROM vuln_findings WHERE status='open' AND COALESCE(cve,'')<>''"),
    ("ip", "ip", "NATs to", "matrix / exposure", "SELECT COUNT(*) FROM asset_registry WHERE COALESCE(public_ips,'')<>''"),
    ("rule", "ip", "allows flow", "Communication matrix", "SELECT COUNT(*) FROM comm_rules"),
    ("ndr", "ip", "involves", "Seceon NDR", "SELECT COUNT(*) FROM ndr_alerts"),
    ("ip", "netblock", "registered to", "WHOIS / RDAP", "SELECT COUNT(*) FROM ip_whois WHERE COALESCE(handle,'')<>''"),
    ("ioc", "detection", "seen in", "IOC checks", "SELECT COUNT(*) FROM ioc_checks WHERE verdict IN ('Seen internally','Malicious')"),
    ("scan", "ip", "scanned", "VA scans", "SELECT COUNT(*) FROM vuln_scan_hosts"),
    ("scan", "lob", "for LOB", "VA scans", "SELECT COUNT(*) FROM vuln_scans"),
    ("vapub", "ip", "public / private IP", "VA public inventory", "SELECT COUNT(*) FROM va_public"),
    ("satellite", "ip", "has IP", "Red Hat Satellite", "SELECT COUNT(*) FROM satellite_hosts WHERE COALESCE(ip,'')<>''"),
    ("niam", "ip", "has IP", "NIAM dump", "SELECT COUNT(*) FROM niam_nodes WHERE present=1 AND ip<>''"),
    ("exception", "cve", "accepts", "SOD uploads", "SELECT COALESCE(SUM(matched),0) FROM vuln_exceptions"),
    ("ip", "service", "open port", "Internet DB scan", "SELECT COUNT(*) FROM passive_results WHERE status='ok' AND ports<>'[]'"),
    ("loghost", "ip", "logs for", "Splunk", "SELECT COUNT(*) FROM splunk_hosts WHERE asset_ip IS NOT NULL"),
    ("notable", "ip", "about", "Splunk ES", "SELECT COUNT(*) FROM splunk_notables WHERE asset_ip IS NOT NULL"),
    ("agent", "sensor", "runs", "CrowdStrike Hosts", "SELECT COUNT(*) FROM hosts WHERE console_state='active' AND COALESCE(agent_version,'')<>''"),
]
COUNTS = {
    "asset": "SELECT COUNT(*) FROM asset_registry", "agent": "SELECT COUNT(*) FROM hosts WHERE console_state='active'",
    "ip": "SELECT COUNT(DISTINCT ip) FROM asset_registry", "lob": "SELECT COUNT(*) FROM lobs", "msp": "SELECT COUNT(*) FROM msps",
    "user": "SELECT COUNT(DISTINCT last_login_user) FROM hosts WHERE COALESCE(last_login_user,'')<>''", "detection": "SELECT COUNT(*) FROM detections",
    "tactic": "SELECT COUNT(DISTINCT tactic) FROM detections WHERE COALESCE(tactic,'')<>''",
    "file": "SELECT COUNT(DISTINCT filename) FROM detections WHERE COALESCE(filename,'')<>''",
    "cve": "SELECT COUNT(*) FROM (SELECT cve FROM spotlight_vulns UNION SELECT cve FROM vuln_findings WHERE status='open' AND COALESCE(cve,'')<>'' AND cve NOT LIKE '%,%')",
    "policy": "SELECT COUNT(*) FROM prevention_policies", "ndr": "SELECT COUNT(*) FROM ndr_alerts", "rule": "SELECT COUNT(*) FROM comm_rules",
    "netblock": "SELECT COUNT(*) FROM whois_nets", "ioc": "SELECT COUNT(DISTINCT value) FROM ioc_checks",
    "scan": "SELECT COUNT(*) FROM vuln_scans", "vapub": "SELECT COUNT(*) FROM va_public", "satellite": "SELECT COUNT(*) FROM satellite_hosts",
    "niam": "SELECT COUNT(*) FROM niam_nodes WHERE present=1", "exception": "SELECT COUNT(*) FROM vuln_exceptions",
    "service": "SELECT COUNT(*) FROM passive_results WHERE status='ok' AND ports<>'[]'",
    "sensor": "SELECT COUNT(DISTINCT agent_version) FROM hosts WHERE console_state='active'",
    "loghost": "SELECT COUNT(*) FROM splunk_hosts", "notable": "SELECT COUNT(*) FROM splunk_notables",
}
_ONT = {"gen": None, "data": None}


def _safe(c, sql):
    try:
        return c.execute(sql).fetchone()[0] or 0
    except Exception:  # noqa: BLE001 - a source not set up yet
        return 0


@router.get("/api/fabric/ontology")
def ontology():
    if _ONT["gen"] == db.GEN[0] and _ONT["data"]:
        return _ONT["data"]
    with db.get_conn() as c:
        subnets = len({ip.rsplit(".", 1)[0] for (ip,) in c.execute("SELECT ip FROM asset_registry WHERE COALESCE(is_public,0)=0 AND ip LIKE '%.%.%.%'")})
        types = [{"id": t, "label": l, "class": k, "source": s, "description": d, "count": subnets if t == "subnet" else _safe(c, COUNTS.get(t, "SELECT 0"))}
                 for t, (l, k, s, d) in TYPES.items()]
        rels = [{"from": a, "to": b, "label": l, "source": s, "count": _safe(c, q)} for a, b, l, s, q in RELS]
    data = {"types": types, "relations": rels, "planned": [
        {"id": "splunk", "label": "Splunk events", "joins": "host, IP, user", "status": "next"},
        {"id": "ndr_flows", "label": "NDR flows", "joins": "IP pairs", "status": "next"},
        {"id": "identity", "label": "Identity (AD / IdP)", "joins": "user", "status": "planned"},
        {"id": "cmdb", "label": "CMDB", "joins": "asset, owner", "status": "planned"}]}
    _ONT.update(gen=db.GEN[0], data=data)
    return data


# ------------------------------------------------------------------ instance graph
def _nid(t, k):
    return f"{t}:{k}"


def _tone_sev(s):
    s = (s or "").lower()
    return "crit" if s in ("critical", "high") else "warn" if s == "medium" else None


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except ValueError:
        return False


def _subnet(ip):
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


class _N:
    def __init__(self):
        self.items, self.more = [], {}

    def add(self, t, key, label, rel, direction="out", tone=None, sub=None):
        if key in (None, ""):
            return
        nid = _nid(t, key)
        if any(x["id"] == nid and x["rel"] == rel for x in self.items):
            return
        self.items.append({"id": nid, "type": t, "label": str(label or key)[:80], "rel": rel, "dir": direction, "tone": tone, "sub": sub})

    def total(self, rel, n, shown):
        if n > shown:
            self.more[rel] = n


LIM = 12


def node(nid):  # noqa: C901 - one branch per entity type
    if ":" not in nid:
        raise HTTPException(400, "Node ids look like type:key, e.g. asset:10.20.0.95")
    t, key = nid.split(":", 1)
    if t not in TYPES:
        raise HTTPException(400, f"Unknown entity type {t}")
    n, props, label, tone, href = _N(), {}, key, None, None
    with db.get_conn() as c:
        if t == "asset":
            a = db.one(c, "SELECT * FROM asset_registry WHERE ip=?", (key,)) or db.one(c, "SELECT * FROM asset_registry WHERE LOWER(name)=LOWER(?)", (key,))
            if not a:
                raise HTTPException(404, f"No asset {key}")
            key = a["ip"]
            label = a["name"] or a["ip"]
            tone = "crit" if a["exposed"] and a["edr_status"] not in ("Online", "Offline") else "warn" if a["crit"] else None
            href = f"/ip-search/?q={a['ip']}"
            props = {"IP": a["ip"], "Name": a["name"], "LOB": a["lobs"], "MSP": a["msps"], "EDR": a["edr_status"], "OS": a["os"], "Node type": a["node_type"],
                     "Exposed": "yes" if a["exposed"] else "no", "VA open": f"{a['crit'] or 0} critical · {a['high'] or 0} high", "Feasibility": a["feasibility"],
                     "Sources": a["sources"]}
            n.add("ip", a["ip"], a["ip"], "has IP", tone="crit" if a["is_public"] else None)
            if a["aid"]:
                h = db.one(c, "SELECT hostname, online_state FROM hosts WHERE aid=?", (a["aid"],)) or {}
                n.add("agent", a["aid"], f"{h.get('hostname') or 'agent'} · {h.get('online_state') or a['edr_status']}", "runs on", "in",
                      "good" if (h.get("online_state") == "online") else "warn")
            for l in [x.strip() for x in (a["lobs"] or "").split(",") if x.strip()]:
                n.add("lob", l, l, "owned by")
            for m in [x.strip() for x in (a["msps"] or "").split(",") if x.strip()]:
                n.add("msp", m, m, "managed by")
            for p in [x.strip() for x in (a["public_ips"] or "").split(",") if x.strip()][:LIM]:
                n.add("ip", p, f"{p} (public)", "NATs to", tone="crit")
            vf = db.rows(c, """SELECT cve, MAX(sev_rank) r, COUNT(*) n FROM vuln_findings WHERE ip=? AND status='open' AND COALESCE(cve,'')<>''
                               GROUP BY cve ORDER BY r DESC LIMIT ?""", (a["ip"], LIM))
            for v in vf:
                for cv in v["cve"].split(",")[:1]:
                    n.add("cve", cv.strip(), cv.strip(), "scan finding", tone="crit" if (v["r"] or 0) >= 4 else "warn" if (v["r"] or 0) >= 3 else None)
            if a["aid"]:
                for d in db.rows(c, "SELECT id, name, severity FROM detections WHERE aid=? ORDER BY created_at DESC LIMIT ?", (a["aid"], LIM)):
                    n.add("detection", d["id"], d["name"], "fired on", "in", _tone_sev(d["severity"]), d["severity"])
            for x in db.rows(c, "SELECT id, name, severity FROM ndr_alerts WHERE src_ip=? OR dst_ip=? ORDER BY created_at DESC LIMIT ?", (a["ip"], a["ip"], LIM)):
                n.add("ndr", x["id"], x["name"], "involves", "in", _tone_sev(x["severity"]))
            _rules(c, n, [a["ip"]])
            _ip_sources(c, n, a["ip"])
        elif t == "agent":
            h = db.one(c, "SELECT * FROM hosts WHERE aid=?", (key,))
            if not h:
                raise HTTPException(404, f"No agent {key}")
            label = h["hostname"] or key
            tone = "good" if h["online_state"] == "online" else "warn"
            href = f"/ip-search/?q={h['connection_ip'] or h['hostname']}"
            props = {"Hostname": h["hostname"], "Agent ID": key, "Platform": f"{h['platform_name'] or ''} {h['os_version'] or ''}".strip(), "Sensor": h["agent_version"],
                     "State": f"{h['console_state']} · {h['online_state'] or '–'}", "Last seen": h["last_seen"], "Last user": h["last_login_user"],
                     "Local IP": h["local_ip"], "Connection IP": h["connection_ip"], "Containment": h["containment_status"]}
            for r in db.rows(c, "SELECT ip, name FROM asset_registry WHERE aid=? LIMIT 3", (key,)):
                n.add("asset", r["ip"], r["name"] or r["ip"], "runs on")
            for ip in {h["local_ip"], h["connection_ip"]} - {None, ""}:
                n.add("ip", ip, ip, "has IP")
            if h["prevention_policy_id"]:
                p = db.one(c, "SELECT name FROM prevention_policies WHERE id=?", (h["prevention_policy_id"],)) or {}
                n.add("policy", h["prevention_policy_id"], p.get("name") or "policy", "enforces")
            if h["last_login_user"]:
                n.add("user", h["last_login_user"], h["last_login_user"], "last logged on", "in")
            for d in db.rows(c, "SELECT id, name, severity FROM detections WHERE aid=? ORDER BY created_at DESC LIMIT ?", (key, LIM)):
                n.add("detection", d["id"], d["name"], "fired on", "in", _tone_sev(d["severity"]), d["severity"])
            tot = _safe(c, f"SELECT COUNT(*) FROM detections WHERE aid='{key.replace(chr(39), '')}'")
            n.total("fired on", tot, LIM)
            if h["agent_version"]:
                n.add("sensor", h["agent_version"], f"sensor {h['agent_version']}", "runs")
            for v in db.rows(c, "SELECT cve, severity, kev FROM spotlight_vulns WHERE aid=? ORDER BY kev DESC, score DESC LIMIT ?", (key, LIM)):
                n.add("cve", v["cve"], v["cve"], "vulnerable to", tone="crit" if v["kev"] or (v["severity"] or "").upper() == "CRITICAL" else "warn")
        elif t == "ip":
            pub = _is_public(key)
            tone = "crit" if pub else None
            href = f"/ip-search/?q={key}"
            a = db.one(c, "SELECT ip, name, edr_status, lobs FROM asset_registry WHERE ip=?", (key,))
            props = {"IP": key, "Public": "yes" if pub else "no", "Asset": (a or {}).get("name"), "EDR": (a or {}).get("edr_status"), "LOB": (a or {}).get("lobs")}
            if a:
                n.add("asset", a["ip"], a["name"] or a["ip"], "has IP", "in")
            for r in db.rows(c, "SELECT ip, name FROM asset_registry WHERE ', ' || COALESCE(public_ips,'') || ',' LIKE ? LIMIT ?", (f"% {key},%", LIM)):
                n.add("ip", r["ip"], f"{r['ip']} ({r['name'] or 'internal'})", "NATs to", "in")
            for h in db.rows(c, "SELECT aid, hostname FROM hosts WHERE local_ip=? OR connection_ip=? LIMIT ?", (key, key, LIM)):
                n.add("agent", h["aid"], h["hostname"] or h["aid"], "has IP", "in")
            if not pub and (sn := _subnet(key)):
                n.add("subnet", sn, sn, "in subnet")
            if pub:
                w = db.one(c, "SELECT w.handle, w.name, w.org, w.descr FROM ip_whois i JOIN whois_nets w ON w.handle=i.handle WHERE i.ip=?", (key,))
                if w:
                    n.add("netblock", w["handle"], f"{w['name']} · {w['org'] or w['descr'] or ''}"[:70], "registered to")
                    props["Registered to"] = w["name"]
            for x in db.rows(c, "SELECT id, name, severity FROM ndr_alerts WHERE src_ip=? OR dst_ip=? ORDER BY created_at DESC LIMIT ?", (key, key, LIM)):
                n.add("ndr", x["id"], x["name"], "involves", "in", _tone_sev(x["severity"]))
            for v in db.rows(c, """SELECT cve, MAX(sev_rank) r FROM vuln_findings WHERE ip=? AND status='open' AND COALESCE(cve,'')<>'' GROUP BY cve
                                   ORDER BY r DESC LIMIT ?""", (key, LIM)):
                cv = v["cve"].split(",")[0].strip()
                n.add("cve", cv, cv, "scan finding", tone="crit" if (v["r"] or 0) >= 4 else None)
            ic = db.one(c, "SELECT verdict FROM ioc_checks WHERE value=? ORDER BY id DESC LIMIT 1", (key,))
            if ic:
                n.add("ioc", key, f"{key} · {ic['verdict']}", "checked as", tone="crit" if ic["verdict"] == "Malicious" else None)
            _rules(c, n, [key])
            _ip_sources(c, n, key)
        elif t == "subnet":
            try:
                net = ipaddress.ip_network(key, strict=False)
            except ValueError as e:
                raise HTTPException(400, "Not a subnet") from e
            base = str(net.network_address).rsplit(".", 1)[0] + ".%"
            rows = db.rows(c, """SELECT ip, name, edr_status, exposed, lobs FROM asset_registry WHERE ip LIKE ? ORDER BY exposed DESC,
                                 edr_status NOT IN ('Online','Offline') DESC, ip_num LIMIT 40""", (base,))
            tot = _safe(c, f"SELECT COUNT(*) FROM asset_registry WHERE ip LIKE '{base}'")
            no_edr = sum(1 for r in rows if r["edr_status"] not in ("Online", "Offline"))
            props = {"Subnet": key, "Assets": tot, "Without EDR (shown)": no_edr, "LOBs": ", ".join(sorted({r["lobs"] for r in rows if r["lobs"]}))[:200]}
            href = f"/subnets/?q={str(net.network_address)}"
            for r in rows:
                n.add("asset", r["ip"], r["name"] or r["ip"], "in subnet", "in", "crit" if r["exposed"] and r["edr_status"] not in ("Online", "Offline")
                      else "warn" if r["edr_status"] not in ("Online", "Offline") else "good", r["edr_status"])
            n.total("in subnet", tot, len(rows))
        elif t in ("lob", "msp"):
            if t == "lob":
                l = db.one(c, "SELECT id, name, owner, description FROM lobs WHERE LOWER(name)=LOWER(?)", (key,))
                if not l:
                    raise HTTPException(404, f"No LOB {key}")
                like, label = f"%,{l['id']},%", l["name"]
                props = {"LOB": l["name"], "Owner": l["owner"], "Description": l["description"]}
                for m in db.rows(c, "SELECT name FROM msps WHERE lob_id=?", (l["id"],)):
                    n.add("msp", m["name"], m["name"], "works for", "in")
                col = "lob_ids"
            else:
                m = db.one(c, "SELECT m.id, m.name, l.name lob FROM msps m JOIN lobs l ON l.id=m.lob_id WHERE LOWER(m.name)=LOWER(?)", (key,))
                if not m:
                    raise HTTPException(404, f"No MSP {key}")
                like, label = f"%,{m['id']},%", m["name"]
                props = {"MSP": m["name"], "LOB": m["lob"]}
                n.add("lob", m["lob"], m["lob"], "works for")
                col = "msp_ids"
            st = db.one(c, f"""SELECT COUNT(*) n, SUM(edr_status IN ('Online','Offline')) edr, SUM(exposed) exp, SUM(crit) crit,
                               SUM(in_inventory=1 AND edr_applicable=1 AND edr_status='Not Installed') gaps FROM asset_registry WHERE {col} LIKE ?""", (like,))
            props.update({"Assets": st["n"], "With EDR": st["edr"], "EDR gaps": st["gaps"], "Exposed": st["exp"], "Critical VA findings": st["crit"]})
            for r in db.rows(c, f"""SELECT ip, name, edr_status, exposed, crit FROM asset_registry WHERE {col} LIKE ?
                                    ORDER BY exposed DESC, crit DESC LIMIT ?""", (like, LIM)):
                n.add("asset", r["ip"], r["name"] or r["ip"], "owned by" if t == "lob" else "managed by", "in",
                      "crit" if r["exposed"] and r["edr_status"] not in ("Online", "Offline") else "warn" if r["crit"] else None)
            n.total("owned by" if t == "lob" else "managed by", st["n"] or 0, LIM)
        elif t == "user":
            props = {"Account": key}
            hs = db.rows(c, "SELECT aid, hostname, online_state FROM hosts WHERE last_login_user=? LIMIT ?", (key, LIM))
            for h in hs:
                n.add("agent", h["aid"], h["hostname"] or h["aid"], "last logged on", tone="good" if h["online_state"] == "online" else None)
            for d in db.rows(c, "SELECT id, name, severity FROM detections WHERE raw LIKE ? ORDER BY created_at DESC LIMIT ?", (f'%"user_name": "{key}"%', LIM)):
                n.add("detection", d["id"], d["name"], "triggered", tone=_tone_sev(d["severity"]))
            props["Agents"] = len(hs)
        elif t == "detection":
            d = db.one(c, "SELECT * FROM detections WHERE id=?", (key,))
            if not d:
                raise HTTPException(404, "No such detection")
            raw = db.jloads(d["raw"], {}) or {}
            label, tone, href = d["name"], _tone_sev(d["severity"]), "/detections/"
            props = {"Detection": d["name"], "Severity": d["severity"], "Status": d["status"], "Analyst": d.get("assigned_to"), "When": d["created_at"],
                     "Technique": " ".join(x for x in (raw.get("technique_id"), d["technique"]) if x), "Command line": (d["cmdline"] or "")[:200]}
            h = db.one(c, "SELECT hostname FROM hosts WHERE aid=?", (d["aid"],)) or {}
            n.add("agent", d["aid"], h.get("hostname") or d["hostname"] or d["aid"], "fired on")
            if d["tactic"]:
                n.add("tactic", d["tactic"], d["tactic"], "maps to")
            if d["filename"]:
                n.add("file", d["filename"], d["filename"], "involves")
            if raw.get("user_name"):
                n.add("user", raw["user_name"], raw["user_name"], "triggered", "in")
            for i in db.rows(c, "SELECT DISTINCT value, verdict FROM ioc_checks WHERE ? LIKE '%' || value || '%' LIMIT 5", ((d["cmdline"] or "") + " " + (d["filename"] or ""),)):
                n.add("ioc", i["value"], f"{i['value']} · {i['verdict']}", "seen in", "in")
        elif t in ("tactic", "file"):
            col = "tactic" if t == "tactic" else "filename"
            rows = db.rows(c, f"SELECT id, name, severity, hostname, aid FROM detections WHERE {col}=? ORDER BY created_at DESC LIMIT ?", (key, LIM))
            tot = _safe(c, f"SELECT COUNT(*) FROM detections WHERE {col}='{key.replace(chr(39), '')}'")
            props = {TYPES[t][0]: key, "Detections": tot, "Hosts": _safe(c, f"SELECT COUNT(DISTINCT aid) FROM detections WHERE {col}='{key.replace(chr(39), '')}'")}
            for d in rows:
                n.add("detection", d["id"], f"{d['name']} · {d['hostname'] or ''}", "maps to" if t == "tactic" else "involves", "in", _tone_sev(d["severity"]))
            n.total("maps to" if t == "tactic" else "involves", tot, len(rows))
        elif t == "cve":
            key = key.upper()
            s = db.one(c, "SELECT MAX(title) title, MAX(severity) sev, MAX(score) score, MAX(COALESCE(kev,0)) kev, COUNT(DISTINCT aid) agents FROM spotlight_vulns WHERE UPPER(cve)=?", (key,))
            va = _safe(c, f"SELECT COUNT(DISTINCT ip) FROM vuln_findings WHERE status='open' AND UPPER(cve) LIKE '%{re.sub(r'[^A-Z0-9-]', '', key)}%'")
            props = {"CVE": key, "Title": s["title"], "Severity": s["sev"], "CVSS": s["score"], "CISA KEV": "yes" if s["kev"] else "no",
                     "Agents (Spotlight)": s["agents"], "IPs (VA scan)": va}
            tone = "crit" if s["kev"] or (s["sev"] or "").upper() == "CRITICAL" else "warn"
            href = f"/spotlight/?cve={key}"
            for r in db.rows(c, "SELECT DISTINCT s.aid, h.hostname FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid WHERE UPPER(s.cve)=? LIMIT ?", (key, LIM)):
                n.add("agent", r["aid"], r["hostname"] or r["aid"], "vulnerable to", "in")
            n.total("vulnerable to", s["agents"] or 0, LIM)
            for r in db.rows(c, "SELECT DISTINCT ip FROM vuln_findings WHERE status='open' AND UPPER(cve) LIKE ? LIMIT ?", (f"%{key}%", LIM)):
                n.add("ip", r["ip"], r["ip"], "scan finding", "in")
            n.total("scan finding", va, LIM)
        elif t == "policy":
            p = db.one(c, "SELECT * FROM prevention_policies WHERE id=?", (key,))
            if not p:
                raise HTTPException(404, "No such policy")
            label, href = p["name"], "/policies/"
            tot = _safe(c, f"SELECT COUNT(*) FROM hosts WHERE prevention_policy_id='{key.replace(chr(39), '')}'")
            props = {"Policy": p["name"], "Platform": p["platform"], "Enabled": "yes" if p["enabled"] else "no", "Agents": tot}
            for h in db.rows(c, "SELECT aid, hostname FROM hosts WHERE prevention_policy_id=? LIMIT ?", (key, LIM)):
                n.add("agent", h["aid"], h["hostname"] or h["aid"], "enforces", "in")
            n.total("enforces", tot, LIM)
        elif t == "ndr":
            x = db.one(c, "SELECT * FROM ndr_alerts WHERE id=?", (key,))
            if not x:
                raise HTTPException(404, "No such NDR alert")
            label, tone, href = x["name"], _tone_sev(x["severity"]), "/alerts/"
            props = {"Alert": x["name"], "Severity": x["severity"], "Category": x["category"], "When": x["created_at"], "Source": x["src_ip"], "Destination": x["dst_ip"]}
            n.add("ip", x["src_ip"], x["src_ip"], "source")
            n.add("ip", x["dst_ip"], x["dst_ip"], "destination", tone="crit" if _is_public(x["dst_ip"] or "") else None)
        elif t == "netblock":
            w = db.one(c, "SELECT * FROM whois_nets WHERE handle=?", (key,))
            if not w:
                raise HTTPException(404, "No such network block")
            label = w["name"] or key
            props = {"Name": w["name"], "Org": w["org"], "Description": w["descr"], "Range": w["cidr"], "Country": w["country"], "RIR": w["rir"]}
            for r in db.rows(c, "SELECT ip FROM ip_whois WHERE handle=? LIMIT ?", (key, LIM)):
                n.add("ip", r["ip"], r["ip"], "registered to", "in", "crit")
        elif t == "rule":
            r = db.one(c, "SELECT * FROM comm_rules WHERE id=?", (key,))
            if not r:
                raise HTTPException(404, "No such rule")
            label = f"{r['rule_id'] or 'rule'} {r['src'] or ''} → {r['dst'] or ''}"[:70]
            tone = "crit" if r["inbound_internet"] else None
            props = {"Rule": r["rule_id"], "Source": r["src"], "Destination": r["dst"], "Ports": r["ports"], "Protocol": r["protocol"], "Action": r["action"],
                     "Application": r.get("application"), "Inbound from internet": "yes" if r["inbound_internet"] else "no"}
            for side in ("src", "dst"):
                for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r[side] or "")[:6]:
                    n.add("ip", ip, ip, "allows flow" if side == "dst" else "from")
        elif t == "scan":
            sc = db.one(c, "SELECT s.*, l.name lob FROM vuln_scans s JOIN lobs l ON l.id=s.lob_id WHERE s.id=?", (int(key) if key.isdigit() else -1,))
            if not sc:
                raise HTTPException(404, "No such scan")
            label, href = f"{sc['lob']} scan {(sc['scan_date'] or sc['uploaded_at'] or '')[:10]}", "/vulnerabilities/"
            props = {"LOB": sc["lob"], "File": sc["filename"], "Scan date": sc["scan_date"], "Uploaded": sc["uploaded_at"], "Findings": sc["rows"],
                     "Hosts": sc["hosts"], "New": sc["new_findings"], "Fixed": sc["fixed_findings"], "Reopened": sc["reopened"]}
            n.add("lob", sc["lob"], sc["lob"], "for LOB")
            for r in db.rows(c, "SELECT ip FROM vuln_scan_hosts WHERE scan_id=? LIMIT ?", (sc["id"], LIM)):
                n.add("ip", r["ip"], r["ip"], "scanned")
            n.total("scanned", sc["hosts"] or 0, LIM)
        elif t == "vapub":
            v = db.one(c, "SELECT * FROM va_public WHERE id=?", (int(key) if key.isdigit() else -1,))
            if not v:
                raise HTTPException(404, "No such VA public row")
            label, tone, href = f"{v['public_ip'] or '?'} → {v['private_ip'] or 'no private IP'}", "crit", "/vulnerabilities/?section=vapub"
            props = {"Public IP": v["public_ip"], "Private IP": v["private_ip"], "LOB": v["lob"], "MSP": v["msp"], "Node type": v["node_type"],
                     "Application": v["application"], "Path": v["path"], "DMZ": v["dmz"], "Owner": v["owner"], "NIAM": v["niam"]}
            for ip, rel in ((v["public_ip"], "public IP"), (v["private_ip"], "private IP")):
                for x in db.all_ips(ip or "")[:4]:
                    n.add("ip", x, x, rel, tone="crit" if rel == "public IP" else None)
            if v["lob"]:
                n.add("lob", v["lob"], v["lob"], "owned by")
            if v["msp"]:
                n.add("msp", v["msp"], v["msp"], "managed by")
        elif t == "satellite":
            sh = db.one(c, "SELECT * FROM satellite_hosts WHERE host_id=?", (int(key) if key.isdigit() else -1,))
            if not sh:
                raise HTTPException(404, "No such Satellite host")
            label, href = sh["name"], "/patches/"
            tone = "crit" if (sh["installable_security"] or 0) else None
            props = {"Host": sh["name"], "IP": sh["ip"], "OS": sh["os"], "Last check-in": sh["last_checkin"], "Security errata": sh["errata_security"],
                     "Installable security": sh["installable_security"], "MBSS policy": sh["compliance_policy"],
                     "MBSS passed / failed": f"{sh['compliance_passed'] or 0} / {sh['compliance_failed'] or 0}"}
            if sh["ip"]:
                n.add("ip", sh["ip"], sh["ip"], "has IP")
        elif t == "niam":
            nn = db.one(c, "SELECT * FROM niam_nodes WHERE ne_id=? AND present=1", (key,))
            if not nn:
                raise HTTPException(404, "No such NIAM node")
            label = f"{key} · {nn['host'] or ''}".strip(" ·")
            props = {"NE ID": key, "Host": nn["host"], "IP": nn["ip"], "LOB": nn["lobs"], "EDR": nn["edr_status"], "In inventory": "yes" if nn["in_inventory"] else "no"}
            if nn["ip"]:
                n.add("ip", nn["ip"], nn["ip"], "has IP")
        elif t == "exception":
            e = db.one(c, "SELECT * FROM vuln_exceptions WHERE id=?", (int(key) if key.isdigit() else -1,))
            if not e:
                raise HTTPException(404, "No such exception")
            label, href = e["exception_id"] or f"exception {key}", "/exceptions/"
            props = {"Exception": e["exception_id"], "Scope": f"{e['scope']} {e['target'] or ''}".strip(), "Plugin": e["plugin_id"], "CVE": e["cve"],
                     "Vulnerability": e["name"], "Valid till": e["valid_till"], "Approved by": e["approved_by"], "Findings accepted": e["matched"]}
            for cv in re.findall(r"CVE-\d{4}-\d+", e["cve"] or "", re.I)[:6]:
                n.add("cve", cv.upper(), cv.upper(), "accepts")
            if e["scope"] == "IP" and e["target"]:
                n.add("ip", e["target"], e["target"], "covers")
            if e["scope"] == "LOB" and e["lob"]:
                n.add("lob", e["lob"], e["lob"], "covers")
        elif t == "service":
            ip, _, port = key.rpartition(":")
            pr = db.one(c, "SELECT * FROM passive_results WHERE ip=?", (ip,))
            label, tone, href = f"{ip}:{port}", "crit", f"/ip-search/?q={ip}"
            props = {"IP": ip, "Port": port, "Scanned": (pr or {}).get("scanned_at"), "Known CVEs on the IP": len(db.jloads((pr or {}).get("vulns"), []) or []),
                     "Tags": ", ".join(db.jloads((pr or {}).get("tags"), []) or [])}
            n.add("ip", ip, ip, "open port", "in", "crit")
        elif t == "sensor":
            hs = db.rows(c, "SELECT aid, hostname, platform_name FROM hosts WHERE console_state='active' AND agent_version=? LIMIT ?", (key, LIM))
            tot = _safe(c, f"SELECT COUNT(*) FROM hosts WHERE console_state='active' AND agent_version='{key.replace(chr(39), '')}'")
            b = db.one(c, "SELECT * FROM sensor_builds WHERE sensor_version=? OR build=? LIMIT 1", (key, key)) or {}
            label, href = f"sensor {key}", "/sensors/"
            props = {"Version": key, "Level": b.get("tag"), "Stage": b.get("stage"), "Platform": b.get("platform"), "Agents": tot}
            for h in hs:
                n.add("agent", h["aid"], h["hostname"] or h["aid"], "runs", "in")
            n.total("runs", tot, LIM)
        elif t == "loghost":
            h = db.one(c, "SELECT * FROM splunk_hosts WHERE host=?", (key,))
            if not h:
                raise HTTPException(404, "No such Splunk host")
            label, href = f"Splunk: {key}", f"/splunk/?tab=hosts&q={key}"
            props = {"Host": key, "Last event": h["last_seen"], "Events 24 h": h["events_24h"], "Events 7 d": h["events_7d"], "Indexes": h["indexes"],
                     "Sourcetypes": h["sourcetypes"], "Asset": h["asset_name"] or h["asset_ip"], "LOB": h["lob"]}
            if h["asset_ip"]:
                n.add("ip", h["asset_ip"], h["asset_ip"], "logs for")
            for r in db.rows(c, "SELECT event_id, rule, urgency FROM splunk_notables WHERE host=? ORDER BY created_at DESC LIMIT ?", (key, LIM)):
                n.add("notable", r["event_id"], r["rule"], "notable", "in", "crit" if r["urgency"] in ("critical", "high") else "warn")
        elif t == "notable":
            x = db.one(c, "SELECT * FROM splunk_notables WHERE event_id=?", (key,))
            if not x:
                raise HTTPException(404, "No such notable")
            label, href = x["rule"], "/splunk/?tab=notables"
            tone = "crit" if x["urgency"] in ("critical", "high") else "warn"
            props = {"Rule": x["rule"], "Urgency": x["urgency"], "Domain": x["domain"], "When": x["created_at"], "Source": x["src"], "Destination": x["dest"],
                     "User": x["user"], "Status": x["status"], "Owner": x["owner"]}
            if x["host"]:
                n.add("loghost", x["host"], f"Splunk: {x['host']}", "on host")
            if x["asset_ip"]:
                n.add("ip", x["asset_ip"], x["asset_ip"], "about")
            if x["user"]:
                n.add("user", x["user"], x["user"], "user")
        elif t == "ioc":
            i = db.one(c, "SELECT * FROM ioc_checks WHERE value=? ORDER BY id DESC LIMIT 1", (key,))
            if not i:
                raise HTTPException(404, "Not checked yet")
            tone = "crit" if i["verdict"] == "Malicious" else None
            props = {"Value": key, "Type": i["kind"], "Verdict": i["verdict"], "Checked": i["at"]}
            href = f"/ioc/?q={key}"
            for d in db.rows(c, "SELECT id, name, severity FROM detections WHERE cmdline LIKE ? OR filename LIKE ? OR raw LIKE ? LIMIT ?",
                             (f"%{key}%", f"%{key}%", f"%{key}%", LIM)):
                n.add("detection", d["id"], d["name"], "seen in", tone=_tone_sev(d["severity"]))
            if db.is_ip(key):
                n.add("ip", key, key, "is")
    return {"node": {"id": _nid(t, key), "type": t, "label": label, "tone": tone, "href": href, "props": {k: v for k, v in props.items() if v not in (None, "")}},
            "neighbors": n.items, "more": n.more}


def _ip_sources(c, n, ip):
    """What the other sources say about one IP: VA scans, VA public inventory, Satellite, NIAM, ports open to the internet."""
    if not ip:
        return
    for r in db.rows(c, """SELECT s.id, l.name lob, s.scan_date FROM vuln_scan_hosts h JOIN vuln_scans s ON s.id=h.scan_id
                           JOIN lobs l ON l.id=s.lob_id WHERE h.ip=? ORDER BY s.scan_date DESC LIMIT 3""", (ip,)):
        n.add("scan", r["id"], f"{r['lob']} scan {(r['scan_date'] or '')[:10]}", "scanned", "in")
    for r in db.rows(c, "SELECT id, public_ip, private_ip FROM va_public WHERE public_ip LIKE ? OR private_ip LIKE ? LIMIT 3", (f"%{ip}%", f"%{ip}%")):
        if ip in db.all_ips(r["public_ip"] or "") + db.all_ips(r["private_ip"] or ""):
            n.add("vapub", r["id"], f"VA public {r['public_ip'] or ''} → {r['private_ip'] or '–'}", "listed in", "in", "crit")
    for r in db.rows(c, "SELECT host_id, name, installable_security FROM satellite_hosts WHERE ip=? LIMIT 2", (ip,)):
        n.add("satellite", r["host_id"], r["name"], "patched by", "in", "warn" if r["installable_security"] else None)
    for r in db.rows(c, "SELECT ne_id FROM niam_nodes WHERE present=1 AND ip=? LIMIT 3", (ip,)):
        n.add("niam", r["ne_id"], r["ne_id"], "NIAM node", "in")
    try:
        for r in db.rows(c, "SELECT host, last_seen, indexes FROM splunk_hosts WHERE asset_ip=? LIMIT 3", (ip,)):
            n.add("loghost", r["host"], f"Splunk: {r['host']}", "logs to", tone="good" if (r["last_seen"] or "") > db.now_iso()[:10] else "warn")
        for r in db.rows(c, "SELECT event_id, rule, urgency FROM splunk_notables WHERE asset_ip=? ORDER BY created_at DESC LIMIT 6", (ip,)):
            n.add("notable", r["event_id"], r["rule"], "notable", "in", "crit" if r["urgency"] in ("critical", "high") else "warn")
    except Exception:  # noqa: BLE001 - Splunk not synced yet
        pass
    pr = db.one(c, "SELECT ports FROM passive_results WHERE ip=? AND status='ok'", (ip,))
    for p in (db.jloads((pr or {}).get("ports"), []) or [])[:LIM]:
        n.add("service", f"{ip}:{p}", f"port {p}", "open port", tone="crit")


def _rules(c, n, ips):
    try:
        from . import commatrix
        flows = commatrix.flows_for(c, ips)
    except Exception:  # noqa: BLE001
        return
    for f in flows[:LIM]:
        rid = f.get("id")
        if rid is None:
            continue
        other = f["src"] if f.get("role") == "Destination" else f["dst"]
        n.add("rule", rid, f"{'from' if f.get('role') == 'Destination' else 'to'} {(other or 'any')[:30]} {f.get('ports') or ''}".strip(), "allows flow", "in",
              "crit" if f.get("inbound_internet") else None)
    n.total("allows flow", len(flows), min(len(flows), LIM))


@router.get("/api/fabric/node")
def fabric_node(id: str):
    return node(id.strip())


@router.get("/api/fabric/path")
def fabric_path(a: str, b: str, max_depth: int = 6):
    """Shortest connection between two entities: breadth-first from both ends until they meet (bounded)."""
    a, b = a.strip(), b.strip()
    if a == b:
        return {"found": True, "path": [a], "hops": []}
    side = {a: {a: None}, b: {b: None}}  # node -> previous node, per side
    rel = {}
    frontier = {a: [a], b: [b]}
    expanded, depth = 0, 0
    while frontier[a] and frontier[b] and expanded < 400 and depth < max_depth:
        s_ = a if len(frontier[a]) <= len(frontier[b]) else b
        other = b if s_ == a else a
        nxt = []
        for cur in frontier[s_]:
            try:
                res = node(cur)
            except HTTPException:
                continue
            expanded += 1
            for nb in res["neighbors"]:
                nid = nb["id"]
                if nid in side[s_]:
                    continue
                side[s_][nid] = cur
                rel[(cur, nid)] = rel[(nid, cur)] = nb["rel"]
                if nid in side[other]:
                    left, x = [], nid
                    while x:
                        left.append(x)
                        x = side[s_][x]
                    right, x = [], side[other][nid]
                    while x:
                        right.append(x)
                        x = side[other][x]
                    path = left[::-1] + right if s_ == a else right[::-1] + left
                    if path[0] != a:
                        path.reverse()
                    return {"found": True, "path": path, "hops": [{"from": path[i], "to": path[i + 1], "rel": rel.get((path[i], path[i + 1]))}
                                                                  for i in range(len(path) - 1)], "expanded": expanded}
                nxt.append(nid)
            if expanded >= 400:
                break
        frontier[s_] = nxt
        depth += 1
    return {"found": False, "path": [], "hops": [], "expanded": expanded}


@router.get("/api/fabric/search")
def fabric_search(q: str, limit: int = 12):
    q = q.strip()
    if len(q) < 2:
        return {"rows": []}
    like = f"%{q}%"
    out = []
    with db.get_conn() as c:
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}", q):
            out.append({"id": f"subnet:{_subnet(q.split('/')[0])}", "type": "subnet", "label": _subnet(q.split('/')[0])})
        for r in db.rows(c, "SELECT ip, name, edr_status FROM asset_registry WHERE ip LIKE ? OR name LIKE ? ORDER BY name IS NULL, name LIMIT 6", (f"{q}%", like)):
            out.append({"id": f"asset:{r['ip']}", "type": "asset", "label": r["name"] or r["ip"], "sub": f"{r['ip']} · EDR {r['edr_status']}"})
        for r in db.rows(c, "SELECT name FROM lobs WHERE name LIKE ? LIMIT 3", (like,)):
            out.append({"id": f"lob:{r['name']}", "type": "lob", "label": r["name"]})
        for r in db.rows(c, "SELECT name FROM msps WHERE name LIKE ? LIMIT 3", (like,)):
            out.append({"id": f"msp:{r['name']}", "type": "msp", "label": r["name"]})
        for r in db.rows(c, "SELECT DISTINCT last_login_user u FROM hosts WHERE last_login_user LIKE ? LIMIT 3", (like,)):
            out.append({"id": f"user:{r['u']}", "type": "user", "label": r["u"]})
        if re.match(r"(?i)cve-", q):
            for r in db.rows(c, "SELECT DISTINCT cve FROM spotlight_vulns WHERE cve LIKE ? LIMIT 4", (like,)):
                out.append({"id": f"cve:{r['cve']}", "type": "cve", "label": r["cve"]})
        for r in db.rows(c, "SELECT DISTINCT tactic FROM detections WHERE tactic LIKE ? LIMIT 2", (like,)):
            out.append({"id": f"tactic:{r['tactic']}", "type": "tactic", "label": r["tactic"]})
        for r in db.rows(c, "SELECT DISTINCT filename FROM detections WHERE filename LIKE ? LIMIT 3", (like,)):
            out.append({"id": f"file:{r['filename']}", "type": "file", "label": r["filename"]})
        for r in db.rows(c, "SELECT id, name FROM prevention_policies WHERE name LIKE ? LIMIT 2", (like,)):
            out.append({"id": f"policy:{r['id']}", "type": "policy", "label": r["name"]})
        for r in db.rows(c, "SELECT id, name, hostname FROM detections WHERE name LIKE ? ORDER BY created_at DESC LIMIT 3", (like,)):
            out.append({"id": f"detection:{r['id']}", "type": "detection", "label": r["name"], "sub": r["hostname"]})
        for r in db.rows(c, "SELECT DISTINCT value, verdict FROM ioc_checks WHERE value LIKE ? LIMIT 2", (like,)):
            out.append({"id": f"ioc:{r['value']}", "type": "ioc", "label": r["value"], "sub": r["verdict"]})
    return {"rows": out[:limit]}
