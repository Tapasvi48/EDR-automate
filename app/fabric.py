"""Data fabric: one view over everything the console holds, for analysts and for the AI SOC.

  catalog   every data domain (CrowdStrike agents, detections, Spotlight, inventories, VA scans, matrix, exposure, WHOIS, NDR…)
            with its source, row count, freshness and the common (OCSF-style) entity it describes
  context   facts about one entity — asset (IP / hostname / agent ID), detection, CVE, public IP — each fact carrying its source
            and time, so an AI answer can cite where every statement comes from
  graph     the entity and what it is linked to: agents, IPs, subnet, LOB / MSP, NAT IPs, CVEs, detections, matrix peers
  alerts    CrowdStrike detections and NDR alerts in one normalised shape (time, source, severity, class, MITRE, device, user)

Nothing is copied: the fabric reads the console's tables, so it is always as fresh as the last sync / upload. Splunk and NDR plug in
by mapping into the same entity and alert shapes."""
import ipaddress
import re

from fastapi import APIRouter, HTTPException, Request

from . import db

router = APIRouter()

# (domain, label, table, time column, source, entity, description, page)
CATALOG = [
    ("edr_agents", "CrowdStrike agents", "hosts", "db_last_synced", "CrowdStrike Hosts API", "Device", "every sensor, its IPs, OS, sensor version, online state, policy", "/assets/"),
    ("detections", "CrowdStrike detections", "detections", "fetched_at", "CrowdStrike Alerts API", "Detection finding", "alerts with MITRE tactic / technique, process, analyst, status", "/detections/"),
    ("spotlight", "Spotlight vulnerabilities", "spotlight_vulns", "fetched_at", "CrowdStrike Spotlight API", "Vulnerability finding", "CVE, ExPRT, exploit status, KEV per agent", "/spotlight/"),
    ("policies", "Prevention policies", "prevention_policies", "modified_at", "CrowdStrike Policies API", "Policy", "prevention settings per policy, agents per policy", "/policies/"),
    ("sensors", "Sensor builds & OS support", "sensor_builds", "fetched_at", "CrowdStrike Sensor update API", "Software", "N / N-1 / N-2 builds, supported OS and kernels", "/sensors/"),
    ("inventory", "LOB inventories", "inventory_current", None, "LOB uploads (CMDB later)", "Device", "nodes per LOB / MSP, node type, OS, live, EDR claim, feasibility", "/inventory/"),
    ("registry", "Asset registry (joined)", "asset_registry", None, "Console (joined)", "Device", "every IP from every source with EDR, exposure, risk", "/inventory/"),
    ("va", "VA scan findings", "vuln_findings", "last_observed", "Nessus uploads", "Vulnerability finding", "plugin findings per IP / port", "/vulnerabilities/"),
    ("matrix", "Communication matrix", "comm_rules", None, "Matrix workbooks", "Network rule", "allowed flows, NAT, internet-facing rules", "/matrix/"),
    ("exposure", "Internet exposure", "asset_registry", None, "Console (derived)", "Device", "exposed assets with evidence", "/exposure/"),
    ("passive", "Internet DB scans", "passive_results", "scanned_at", "Shodan InternetDB", "Network endpoint", "open ports / CVEs seen from the internet", "/passive-scan/"),
    ("whois", "WHOIS / ownership", "whois_nets", "fetched_at", "RDAP (APNIC, RIPE…)", "Network block", "who an IP block is registered to; enterprise marks", "/surface/"),
    ("niam", "NIAM dump", "niam_nodes", "last_seen_at", "NIAM uploads", "Device", "network elements (NE ID, IP)", "/integrations/"),
    ("ndr", "Seceon NDR alerts", "ndr_alerts", "received_at", "Seceon webhook / uploads", "Network activity", "network detections with source / destination IPs", "/alerts/"),
    ("satellite", "Patching & MBSS", "satellite_hosts", "last_checkin", "Red Hat Satellite", "Device", "errata, compliance per Linux host", "/patches/"),
    ("exceptions", "Risk exceptions (SOD)", "vuln_exceptions", "created_at", "SOD uploads", "Exception", "accepted vulnerabilities with expiry", "/exceptions/"),
    ("mcp", "Falcon MCP calls", "mcp_runs", "at", "Falcon MCP", "API activity", "every live query to CrowdStrike from the console", "/falcon-mcp/?tab=history"),
    ("kb", "Knowledge base", "kb_docs", "created_at", "Your documents + built-ins", "Document", "SOPs, playbooks, MITRE, guides", "/falcon-mcp/?tab=kb"),
    ("chats", "AI SOC conversations", "chat_sessions", "updated_at", "AI SOC", "Case note", "saved hunts and investigations", "/falcon-mcp/"),
]


@router.get("/api/fabric/catalog")
def catalog():
    out = []
    with db.get_conn() as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for dom, label, table, tcol, src, entity, desc, page in CATALOG:
            if table not in tables:
                out.append({"id": dom, "label": label, "rows": 0, "fresh": None, "source": src, "entity": entity, "description": desc, "page": page, "status": "not set up"})
                continue
            where = " WHERE exposed=1" if dom == "exposure" else ""
            n = c.execute(f"SELECT COUNT(*) FROM {table}{where}").fetchone()[0]
            fresh = c.execute(f"SELECT MAX({tcol}) FROM {table}").fetchone()[0] if tcol else None
            out.append({"id": dom, "label": label, "rows": n, "fresh": fresh, "source": src, "entity": entity, "description": desc, "page": page,
                        "status": "connected" if n else "empty"})
        links = {
            "agents_in_inventory": c.execute("SELECT COUNT(DISTINCT matched_aid) FROM inventory_current WHERE matched_aid IS NOT NULL").fetchone()[0],
            "assets": c.execute("SELECT COUNT(*) FROM asset_registry").fetchone()[0],
            "detections_on_known_assets": c.execute("SELECT COUNT(*) FROM detections d WHERE EXISTS (SELECT 1 FROM asset_registry r WHERE r.aid=d.aid)").fetchone()[0],
        }
    return {"rows": out, "links": links}


# ------------------------------------------------------------------ entity context (facts with sources)
def F(label, value, source, at=None, tone=None):
    return {"label": label, "value": value, "source": source, "at": at, "tone": tone}


def asset_context(c, q):
    from .asset360 import profile
    p = profile(c, q)
    s = p["summary"]
    if not s["found"]:
        return None
    ipl = s["ips"]
    a = s["edr_agent"] or {}
    facts = [
        F("Asset", ", ".join(s["hostnames"][:3]) or q, "console"),
        F("IPs", ", ".join(ipl[:6]), "inventory / CrowdStrike"),
        F("LOB / MSP", " / ".join(x for x in (", ".join(s["lobs"]), ", ".join(s["msps"])) if x) or "not in any inventory", "LOB inventory", tone=None if s["lobs"] else "warn"),
        F("EDR", f"{s['edr_status']}" + (f" · sensor {a.get('agent_version')} · last seen {a.get('last_seen')}" if a else ""), "CrowdStrike",
          a.get("last_seen"), "good" if s["edr_status"] == "Online" else "crit"),
        F("OS", s.get("os") or "unknown", s.get("os_source") or "inventory"),
        F("EDR feasible", s.get("feasibility") or "unknown", "EDR feasibility", tone="warn" if s.get("feasibility") in ("No", "To be decided") else None),
        F("Open vulnerabilities (VA)", f"{s['vulns']['Critical']} critical · {s['vulns']['High']} high · {s['vulns']['Medium']} medium", "VA scan",
          s.get("last_scan"), "crit" if s["vulns"]["Critical"] else "warn" if s["vulns"]["High"] else None),
        F("Internet exposed", "yes — " + "; ".join(e.get("text", "") for e in s["exposure"][:3]) if s["exposure"] else "no evidence", "exposure",
          tone="crit" if s["exposure"] else None),
    ]
    aids = [x["aid"] for x in p["agents"]]
    det = spot = None
    if aids:
        ph = ",".join("?" * len(aids))
        det = db.one(c, f"""SELECT COUNT(*) n, SUM(severity IN ('Critical','High')) ch, MAX(created_at) last,
                            SUM(LOWER(COALESCE(status,'new')) NOT IN ('closed','resolved')) open FROM detections WHERE aid IN ({ph})""", aids)
        spot = db.one(c, f"""SELECT COUNT(*) n, SUM(UPPER(severity)='CRITICAL') crit, SUM(COALESCE(kev,0)) kev FROM spotlight_vulns WHERE aid IN ({ph})""", aids)
        pol = db.one(c, f"""SELECT pp.name, h.prevention_applied FROM hosts h LEFT JOIN prevention_policies pp ON pp.id=h.prevention_policy_id
                            WHERE h.aid IN ({ph}) ORDER BY h.online_state='online' DESC LIMIT 1""", aids)
        if det and det["n"]:
            facts.append(F("Detections", f"{det['n']} total · {det['ch'] or 0} critical/high · {det['open'] or 0} open", "CrowdStrike detections", det["last"],
                           "crit" if det["ch"] else None))
        if spot and spot["n"]:
            facts.append(F("Spotlight", f"{spot['n']} open findings · {spot['crit'] or 0} critical · {spot['kev'] or 0} CISA KEV", "CrowdStrike Spotlight",
                           tone="crit" if spot["crit"] else None))
        if pol and pol.get("name"):
            facts.append(F("Prevention policy", pol["name"] + ("" if pol["prevention_applied"] != 0 else " (not applied yet)"), "CrowdStrike policies",
                           tone="warn" if "detect" in pol["name"].lower() or pol["prevention_applied"] == 0 else None))
    if p["flows"]:
        inbound = [f for f in p["flows"] if f.get("inbound_internet")]
        facts.append(F("Communication matrix", f"{len(p['flows'])} rules · {len(inbound)} internet-facing", "matrix", tone="warn" if inbound else None))
    return {"kind": "asset", "id": q, "title": ", ".join(s["hostnames"][:2]) or q, "facts": facts, "ips": ipl, "aids": aids, "summary": s,
            "detections": det, "spotlight": spot}


def detection_context(c, did):
    d = db.one(c, """SELECT d.*, h.connection_ip ip FROM detections d LEFT JOIN hosts h ON h.aid=d.aid WHERE d.id=?""", (did,))
    if not d:
        return None
    raw = db.jloads(d.get("raw"), {}) or {}
    same = db.one(c, """SELECT COUNT(*) n, COUNT(DISTINCT aid) hosts, SUM(LOWER(status) IN ('closed','resolved')) closed,
                        MIN(created_at) first FROM detections WHERE name=? AND id<>?""", (d["name"], did))
    host_other = db.one(c, "SELECT COUNT(*) n, SUM(severity IN ('Critical','High')) ch FROM detections WHERE aid=? AND id<>?", (d["aid"], did))
    facts = [
        F("Detection", d["name"], "CrowdStrike", d["created_at"], "crit" if d["severity"] in ("Critical", "High") else None),
        F("Severity", d["severity"] + (f" · confidence {raw.get('confidence')}" if raw.get("confidence") else ""), "CrowdStrike"),
        F("MITRE", " · ".join(x for x in (raw.get("tactic_id"), d["tactic"], raw.get("technique_id"), d["technique"]) if x) or "–", "CrowdStrike"),
        F("Process", " ".join(x for x in (d.get("filename"), d.get("cmdline")) if x)[:300] or "–", "CrowdStrike"),
        F("Parent process", ((raw.get("parent_details") or {}).get("filename") or "–"), "CrowdStrike"),
        F("Action taken", d.get("disposition") or "–", "CrowdStrike", tone="good" if any(w in (d.get("disposition") or "").lower() for w in ("block", "kill", "quarant", "prevent")) else None),
        F("Status / analyst", f"{d.get('status') or 'new'} · {d.get('assigned_to') or 'unassigned'}", "CrowdStrike", d.get("updated_at")),
        F("Seen before", f"{same['n']} times on {same['hosts']} hosts since {(same['first'] or '')[:10]} · {same['closed'] or 0} closed" if same["n"] else "first time this detection fired",
          "detection history", tone="warn" if not same["n"] else None),
        F("Other detections on this host", f"{host_other['n']} ({host_other['ch'] or 0} critical/high)", "detection history", tone="warn" if host_other["ch"] else None),
    ]
    asset = asset_context(c, d["ip"] or d["hostname"]) if (d["ip"] or d["hostname"]) else None
    return {"kind": "detection", "id": did, "title": d["name"], "facts": facts, "detection": d, "raw": raw, "asset": asset, "same": same}


def cve_context(c, cve):
    cve = cve.upper()
    s = db.one(c, """SELECT COUNT(DISTINCT aid) hosts, MAX(title) title, MAX(description) descr, MAX(score) score, MAX(exprt) exprt,
                     MAX(exploit_status) exploit, MAX(COALESCE(kev,0)) kev, MAX(severity) sev FROM spotlight_vulns WHERE UPPER(cve)=?""", (cve,))
    va = db.one(c, """SELECT COUNT(DISTINCT ip) ips, MAX(name) name FROM vuln_findings WHERE status='open' AND (',' || REPLACE(UPPER(cve),' ','') || ',') LIKE ?""",
                 (f"%,{cve},%",))
    exposed = c.execute("""SELECT COUNT(DISTINCT r.ip) FROM asset_registry r WHERE r.exposed=1 AND (r.aid IN (SELECT aid FROM spotlight_vulns WHERE UPPER(cve)=?)
                           OR r.ip IN (SELECT ip FROM vuln_findings WHERE status='open' AND (',' || REPLACE(UPPER(cve),' ','') || ',') LIKE ?))""",
                        (cve, f"%,{cve},%")).fetchone()[0]
    if not (s["hosts"] or va["ips"]):
        return None
    facts = [F("Vulnerability", s["title"] or va["name"] or cve, "Spotlight / VA scan"),
             F("Severity", f"{s['sev'] or '–'} · CVSS {s['score'] or '–'} · ExPRT {s['exprt'] or '–'}", "CrowdStrike Spotlight"),
             F("Exploit", (s["exploit"] or "–") + (" · on the CISA KEV list" if s["kev"] else ""), "CrowdStrike Spotlight", tone="crit" if s["kev"] else None),
             F("Affected", f"{s['hosts']} agents (Spotlight) · {va['ips']} IPs (VA scan)", "Spotlight / VA scan"),
             F("Internet-exposed affected assets", str(exposed), "exposure", tone="crit" if exposed else None)]
    if s["descr"]:
        facts.append(F("Description", s["descr"][:500], "CrowdStrike Spotlight"))
    return {"kind": "cve", "id": cve, "title": f"{cve} {s['title'] or va['name'] or ''}".strip(), "facts": facts, "exposed": exposed}


def ip_context(c, ip):
    from .whois import class_map, whois_map
    reg = db.one(c, "SELECT * FROM asset_registry WHERE ip=?", (ip,))
    w = whois_map(c, [ip]).get(ip) or {}
    cls = class_map(c).get(ip)
    pv = db.one(c, "SELECT ports, vulns, scanned_at FROM passive_results WHERE ip=?", (ip,))
    facts = [F("IP", ip, "input")]
    if reg:
        facts.append(F("Known asset", f"{reg['name'] or 'unnamed'} · {reg['lobs'] or 'no LOB'} · EDR {reg['edr_status']}", "asset registry"))
        if reg["exposed"]:
            facts.append(F("Internet exposed", "yes", "exposure", tone="crit"))
    if w.get("whois_name"):
        facts.append(F("Registered to", f"{w['whois_name']} — {w.get('whois_descr') or w.get('whois_org') or ''} ({w.get('whois_country') or ''})", "WHOIS / RDAP"))
    if cls:
        facts.append(F("Marked", cls, "enterprise marks"))
    if pv:
        facts.append(F("Seen from the internet", f"ports {', '.join(map(str, db.jloads(pv['ports'], [])[:10])) or 'none'} · CVEs {len(db.jloads(pv['vulns'], []))}",
                       "Shodan InternetDB", pv["scanned_at"]))
    return {"kind": "ip", "id": ip, "title": ip, "facts": facts}


def context(kind, ident):
    with db.get_conn() as c:
        if kind == "detection":
            return detection_context(c, ident)
        if kind == "cve":
            return cve_context(c, ident)
        if kind == "ip" and db.is_ip(ident) and not db.one(c, "SELECT 1 x FROM asset_registry WHERE ip=? AND (in_inventory=1 OR in_edr=1)", (ident,)):
            return ip_context(c, ident)
        return asset_context(c, ident)


@router.get("/api/fabric/context")
def fabric_context(kind: str = "asset", id: str = ""):
    ctx = context(kind, id.strip())
    if not ctx:
        raise HTTPException(404, f"Nothing known about {id}")
    return {k: v for k, v in ctx.items() if k not in ("raw", "summary")}


# ------------------------------------------------------------------ relationship graph
@router.get("/api/fabric/graph")
def fabric_graph(q: str):
    """The asset and what it is linked to, as nodes / edges (for the graph view and for AI context)."""
    with db.get_conn() as c:
        ctx = asset_context(c, q.strip())
        if not ctx:
            raise HTTPException(404, f"No asset found for {q}")
        s = ctx["summary"]
        nodes, edges = [], []

        def node(nid, kind, label, tone=None, href=None):
            if not any(n["id"] == nid for n in nodes):
                nodes.append({"id": nid, "kind": kind, "label": label, "tone": tone, "href": href})
            return nid
        root = node("asset", "asset", ctx["title"], "crit" if s["exposure"] else None, f"/ip-search/?q={q}")
        for a in (s.get("edr_agent") and [s["edr_agent"]] or []):
            edges.append((root, node(f"agent:{a['aid']}", "agent", f"Agent · {a.get('online_state') or a.get('console_state')}",
                                     "good" if a.get("online_state") == "online" else "warn"), "runs"))
        for ip in ctx["ips"][:6]:
            edges.append((root, node(f"ip:{ip}", "ip", ip, href=f"/ip-search/?q={ip}"), "has IP"))
            try:
                net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                edges.append((f"ip:{ip}", node(f"net:{net}", "subnet", net, href=f"/subnets/?q={ip}"), "in subnet"))
            except ValueError:
                pass
            for r in db.rows(c, "SELECT public_ips FROM asset_registry WHERE ip=?", (ip,)):
                for pub in (r["public_ips"] or "").split(", ")[:3]:
                    if pub:
                        edges.append((f"ip:{ip}", node(f"ip:{pub}", "public", f"{pub} (NAT)", "crit", f"/ip-search/?q={pub}"), "NAT"))
        for l in s["lobs"][:3]:
            edges.append((root, node(f"lob:{l}", "lob", l), "belongs to"))
        for m in s["msps"][:3]:
            edges.append((root, node(f"msp:{m}", "msp", m), "managed by"))
        if ctx["aids"]:
            ph = ",".join("?" * len(ctx["aids"]))
            for v in db.rows(c, f"""SELECT cve, MAX(severity) sev, MAX(COALESCE(kev,0)) kev FROM spotlight_vulns WHERE aid IN ({ph})
                                    GROUP BY cve ORDER BY MAX(score) DESC LIMIT 6""", ctx["aids"]):
                edges.append((root, node(f"cve:{v['cve']}", "cve", v["cve"], "crit" if v["kev"] or v["sev"] == "CRITICAL" else "warn", f"/spotlight/?cve={v['cve']}"), "vulnerable to"))
            for d in db.rows(c, f"""SELECT id, name, severity FROM detections WHERE aid IN ({ph}) ORDER BY created_at DESC LIMIT 5""", ctx["aids"]):
                edges.append((root, node(f"det:{d['id']}", "detection", d["name"][:40], "crit" if d["severity"] in ("Critical", "High") else "warn", "/detections/?from=all"), "detected"))
        from . import commatrix
        for f in commatrix.flows_for(c, ctx["ips"])[:6]:
            other = f["src"] if f["role"] == "Destination" else f["dst"]
            lbl = (other or "any")[:28]
            edges.append((root, node(f"peer:{lbl}", "peer", lbl, "crit" if f.get("inbound_internet") else None),
                          ("inbound from" if f["role"] == "Destination" else "talks to") + f" {f.get('ports') or ''}".rstrip()))
    return {"nodes": nodes, "edges": [{"from": a, "to": b, "label": l} for a, b, l in edges], "facts": ctx["facts"], "title": ctx["title"]}


# ------------------------------------------------------------------ one alert shape (OCSF-style) across sources
SEV_ID = {"informational": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


@router.get("/api/fabric/alerts")
def fabric_alerts(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    with db.get_conn() as c:
        rows = [{"time": r["created_at"], "source": "CrowdStrike", "class": "Detection Finding", "severity": r["severity"],
                 "severity_id": SEV_ID.get((r["severity"] or "").lower(), 0), "title": r["name"], "status": r["status"] or "new",
                 "device": {"hostname": r["hostname"], "ip": r["ip"], "aid": r["aid"]}, "actor": r["assigned_to"],
                 "mitre": {"tactic": r["tactic"], "technique": r["technique"]}, "src_ip": None, "dst_ip": None, "id": r["id"]}
                for r in db.rows(c, """SELECT d.*, h.connection_ip ip FROM detections d LEFT JOIN hosts h ON h.aid=d.aid ORDER BY d.created_at DESC LIMIT 5000""")]
        rows += [{"time": r["created_at"], "source": "Seceon NDR", "class": "Network Activity", "severity": r["severity"],
                  "severity_id": SEV_ID.get((r["severity"] or "").lower(), 0), "title": r["name"], "status": r["status"] or "new",
                  "device": {"hostname": r["host"], "ip": r["src_ip"], "aid": None}, "actor": None, "mitre": {"tactic": r["category"], "technique": None},
                  "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "id": r["id"]}
                 for r in db.rows(c, "SELECT * FROM ndr_alerts ORDER BY created_at DESC LIMIT 5000")]
    rows.sort(key=lambda r: r["time"] or "", reverse=True)
    if p.get("source"):
        rows = [r for r in rows if r["source"] in db.multi(p, "source")]
    if p.get("severity"):
        rows = [r for r in rows if (r["severity"] or "") in db.multi(p, "severity")]
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size]}



# ------------------------------------------------------------------ entity resolution (names in a question -> known entities)
_IDX = {"gen": None, "names": {}, "lobs": {}, "msps": {}, "users": {}}


def _norm(v):
    return re.sub(r"[^a-z0-9.-]", "", str(v or "").lower())


def index():
    """Every hostname / inventory node name / NE ID / IP, LOB, MSP and user the console knows, rebuilt when data changes."""
    if _IDX["gen"] == db.GEN[0]:
        return _IDX
    names, lobs, msps, users = {}, {}, {}, {}
    with db.get_conn() as c:
        for r in c.execute("SELECT hostname, connection_ip FROM hosts WHERE COALESCE(hostname,'')<>''"):
            names.setdefault(_norm(r[0]), r[0])
        for r in c.execute("SELECT node_name, ip FROM inventory_current WHERE COALESCE(node_name,'')<>''"):
            names.setdefault(_norm(r[0]), r[0])
        for r in c.execute("SELECT ne_id, ip FROM niam_nodes WHERE COALESCE(ne_id,'')<>''"):
            names.setdefault(_norm(r[0]), r[1] or r[0])
        for r in c.execute("SELECT id, name FROM lobs"):
            lobs[r[1].lower()] = r[1]
        for r in c.execute("SELECT name FROM msps"):
            msps[r[0].lower()] = r[0]
        for r in c.execute("SELECT DISTINCT last_login_user FROM hosts WHERE COALESCE(last_login_user,'')<>'' LIMIT 20000"):
            users[r[0].lower()] = r[0]
    _IDX.update(gen=db.GEN[0], names=names, lobs=lobs, msps=msps, users=users)
    return _IDX


def resolve(text):
    """{host, lob, msp, user} found in free text by exact (case-insensitive) match against the index — no guessing."""
    idx, out, low = index(), {}, (text or "").lower()
    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]{2,62}", text or ""):
        hit = idx["names"].get(_norm(tok))
        if hit and not db.is_ip(tok):
            out.setdefault("host", hit)
    for k, src in (("lob", idx["lobs"]), ("msp", idx["msps"])):
        for name_low, name in sorted(src.items(), key=lambda x: -len(x[0])):
            if re.search(rf"\b{re.escape(name_low)}\b", low):
                out.setdefault(k, name)
                break
    m = re.search(r"\b(?:user|account)\s+([\w.@\\$-]+)", text or "", re.I)
    if m and m.group(1).lower() in idx["users"]:
        out["user"] = idx["users"][m.group(1).lower()]
    return out


# ------------------------------------------------------------------ questions answered from the fabric itself (no CrowdStrike call)
def _lob_where(args, col="r.lob_ids"):
    if not args.get("lob"):
        return "", []
    with db.get_conn() as c:
        r = c.execute("SELECT id FROM lobs WHERE LOWER(name)=LOWER(?)", (args["lob"],)).fetchone()
    return (f" AND {col} LIKE ?", [f"%,{r[0]},%"]) if r else (" AND 1=0", [])


def local_exposed_no_edr(c, a):
    w, p = _lob_where(a)
    return db.rows(c, f"""SELECT r.ip, r.name, r.lobs, r.edr_status, r.crit, r.high, r.exposure_src FROM asset_registry r
                          WHERE r.exposed=1 AND r.edr_status NOT IN ('Online','Offline'){w} ORDER BY r.crit DESC, r.high DESC LIMIT 500""", p)


def local_exposed_assets(c, a):
    """Every internet-exposed asset, whatever its EDR state: own public IP / ISP-direct, private behind a public / NAT IP, or
    private exposed by a rule / zone / mark — with EDR, LOB, public IPs and the evidence."""
    w, p = _lob_where(a)
    edr = (a.get("edr") or "").lower()
    if edr in ("with", "yes", "installed"):
        w += " AND r.edr_status IN ('Online','Offline')"
    elif edr in ("without", "no", "missing"):
        w += " AND r.edr_status NOT IN ('Online','Offline')"
    kind = (a.get("ip_kind") or "").lower()
    if kind.startswith("pub"):
        w += " AND r.is_public=1"
    elif kind.startswith("nat"):
        w += " AND r.is_public=0 AND r.public_ips IS NOT NULL"
    elif kind.startswith("priv"):
        w += " AND r.is_public=0"
    return db.rows(c, f"""SELECT r.ip, r.name, CASE WHEN r.is_public=1 THEN 'Public IP' WHEN r.public_ips IS NOT NULL THEN 'Private behind NAT'
                          ELSE 'Private (rule / zone)' END address_type, r.public_ips, r.lobs, r.edr_status, r.crit, r.high, r.exposure_src
                          FROM asset_registry r WHERE r.exposed=1{w} ORDER BY r.edr_status NOT IN ('Online','Offline') DESC, r.crit DESC, r.high DESC LIMIT 2000""", p)


def local_coverage_gaps(c, a):
    w, p = _lob_where(a)
    return db.rows(c, f"""SELECT r.ip, r.name, r.lobs, r.msps, r.node_type, r.os, r.exposed FROM asset_registry r
                          WHERE r.in_inventory=1 AND r.edr_applicable=1 AND r.edr_status='Not Installed'{w} ORDER BY r.exposed DESC, r.name LIMIT 1000""", p)


def local_kev_exposed(c, a):
    return db.rows(c, """SELECT s.hostname, COALESCE(NULLIF(h.connection_ip,''), s.ip) ip, s.cve, COALESCE(NULLIF(s.title,''), s.cve || COALESCE(' · ' || s.product, '')) title, s.severity, s.exprt, s.kev,
                         (SELECT r.lobs FROM asset_registry r WHERE r.aid=s.aid LIMIT 1) lobs FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid
                         WHERE (s.kev=1 OR UPPER(s.severity)='CRITICAL') AND EXISTS (SELECT 1 FROM asset_registry r WHERE r.aid=s.aid AND r.exposed=1)
                         ORDER BY s.kev DESC, s.score DESC LIMIT 500""")


def local_riskiest(c, a):
    w, p = ("", [])
    if a.get("lob"):
        w, p = " AND l.name=?", [a["lob"]]
    return db.rows(c, f"""SELECT r.ip, (SELECT name FROM asset_registry g WHERE g.ip=r.ip) name, l.name lob, r.score, r.level, r.factors
                          FROM asset_risk r JOIN lobs l ON l.id=r.lob_id WHERE 1=1{w} ORDER BY r.score DESC LIMIT 50""", p)


def local_lob_posture(c, a):
    return db.rows(c, """SELECT l.name lob, COUNT(*) assets, SUM(r.edr_status IN ('Online','Offline')) with_edr,
                         SUM(r.in_inventory=1 AND r.edr_applicable=1 AND r.edr_status='Not Installed') gaps, SUM(r.exposed) exposed,
                         SUM(r.exposed AND r.edr_status NOT IN ('Online','Offline')) exposed_no_edr, SUM(r.crit) crit_vulns
                         FROM lobs l JOIN asset_registry r ON r.lob_ids LIKE '%,' || l.id || ',%' GROUP BY l.id ORDER BY gaps DESC""")


def local_owner(c, a):
    ctx = asset_context(c, a.get("host") or a.get("ip") or "")
    if not ctx:
        return []
    s = ctx["summary"]
    return [{"asset": ctx["title"], "ips": ", ".join(ctx["ips"]), "lob": ", ".join(s["lobs"]) or "not in inventory", "msp": ", ".join(s["msps"]) or "–",
             "edr": s["edr_status"], "os": s.get("os") or "–", "exposed": "yes" if s["exposure"] else "no"}]


def timeline(c, q, days=30):
    ctx = asset_context(c, q)
    if not ctx:
        return []
    aids, ips = ctx["aids"], ctx["ips"]
    ev = []
    if aids:
        ph = ",".join("?" * len(aids))
        ev += [{"at": r["created_at"], "kind": "detection", "what": f"{r['severity']} · {r['name']}", "source": "CrowdStrike"}
               for r in db.rows(c, f"SELECT created_at, severity, name FROM detections WHERE aid IN ({ph}) ORDER BY created_at DESC LIMIT 100", aids)]
        ev += [{"at": r["ts"], "kind": "agent", "what": f"{r['event']} {r['details'] or ''}"[:160], "source": "CrowdStrike sync"}
               for r in db.rows(c, f"SELECT ts, event, details FROM host_events WHERE aid IN ({ph}) ORDER BY ts DESC LIMIT 100", aids)]
        ev += [{"at": r["created_at"], "kind": "vulnerability", "what": f"Spotlight {r['cve']} {r['severity']}", "source": "CrowdStrike Spotlight"}
               for r in db.rows(c, f"SELECT created_at, cve, severity FROM spotlight_vulns WHERE aid IN ({ph}) ORDER BY created_at DESC LIMIT 50", aids)]
    if ips:
        ph = ",".join("?" * len(ips))
        ev += [{"at": r["scanned_at"], "kind": "scan", "what": f"VA scan ({r['lob']})", "source": "VA scan"}
               for r in db.rows(c, f"SELECT sh.scanned_at, l.name lob FROM vuln_scan_hosts sh JOIN lobs l ON l.id=sh.lob_id WHERE sh.ip IN ({ph})", ips)]
        ev += [{"at": r["created_at"], "kind": "ndr", "what": f"{r['severity']} · {r['name']}", "source": "Seceon NDR"}
               for r in db.rows(c, f"SELECT created_at, severity, name FROM ndr_alerts WHERE src_ip IN ({ph}) OR dst_ip IN ({ph}) ORDER BY created_at DESC LIMIT 50", ips + ips)]
    ev = [e for e in ev if e["at"]]
    ev.sort(key=lambda e: e["at"], reverse=True)
    return ev[:300]


def local_timeline(c, a):
    return timeline(c, a.get("host") or a.get("ip") or "", int(a.get("days") or 30))


LOCAL = {"exposed_assets": local_exposed_assets, "exposed_no_edr": local_exposed_no_edr, "coverage_gaps": local_coverage_gaps, "kev_exposed": local_kev_exposed,
         "riskiest_assets": local_riskiest, "lob_posture": local_lob_posture, "asset_owner": local_owner, "asset_timeline": local_timeline}


def run_local(name, args):
    with db.get_conn() as c:
        return LOCAL[name](c, args)


@router.get("/api/fabric/timeline")
def fabric_timeline(q: str, days: int = 30):
    with db.get_conn() as c:
        return {"rows": timeline(c, q.strip(), days)}


@router.get("/api/fabric/resolve")
def fabric_resolve(text: str):
    return resolve(text)
