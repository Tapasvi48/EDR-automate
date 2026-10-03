"""NIAM dump integration: a sheet of Host (IP) -> NE ID.

Every upload is a full snapshot. Nodes in the file are "present"; nodes from earlier dumps that are missing are kept with
present=0 (removed_at set), so nothing is lost. Each node is matched to the LOB inventories, CrowdStrike (live, removed and
old EDR imports) and vulnerability scans; the match is stored on the row and rebuilt after every sync / upload."""
import json
import re

from fastapi import APIRouter, Body, Request

from . import db, inventory
from .exporter import xlsx_response

router = APIRouter()

FIELDS = [("host", "Host (IP)", True), ("ne_id", "NE ID", True), ("ne_name", "NE Name", False), ("ne_type", "NE Type", False),
          ("vendor", "Vendor", False), ("circle", "Circle / Region", False), ("site", "Site", False), ("status", "Status", False)]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "host": ["host", "hostip", "ip", "ipaddress", "neip", "managementip", "mgmtip", "nodeip", "hostaddress", "ipv4", "ipv6"],
    "ne_id": ["neid", "ne", "networkelementid", "neidentifier", "elementid", "nodeid"],
    "ne_name": ["nename", "networkelementname", "elementname", "nodename", "hostname"],
    "ne_type": ["netype", "elementtype", "nodetype", "devicetype", "type"],
    "vendor": ["vendor", "oem", "make", "manufacturer"],
    "circle": ["circle", "region", "zone", "state"],
    "site": ["site", "sitename", "location"],
    "status": ["status", "nestatus", "state", "adminstatus"],
}
EDR_ORDER = {"Online": 0, "Offline": 1, "Hidden": 2, "Removed": 3, "Old EDR import": 4, "Not Installed": 5}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    from .filetemplates import custom_aliases
    custom = custom_aliases("niam")
    for f in KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == alias), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def build(parsed, mapping):
    if not mapping.get("host") or not mapping.get("ne_id"):
        raise ValueError("Map both Host (IP) and NE ID")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    mapped = set(v for v in mapping.values() if v)
    out, warnings, bad_ip, dups = {}, [], 0, 0
    for r in parsed["rows"]:
        v = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        if not v["host"] and not v["ne_id"]:
            continue
        ip = db.canon_ip(v["host"]) if db.is_ip(v["host"]) else ""
        if v["host"] and not ip:
            bad_ip += 1
        key = (v["ne_id"], ip or v["host"].lower())
        if key in out:
            dups += 1
            continue
        extra = {h: r[idx[h]] for h in parsed["headers"] if r[idx[h]] and h not in mapped}
        extra.update({lbl: v[k] for k, lbl, _ in FIELDS if k not in ("host", "ne_id") and v[k]})
        out[key] = {"ne_id": v["ne_id"], "host": v["host"], "ip": ip, "ip_num": db.ip_to_num(ip),
                    "hostname_norm": "" if ip else db.norm_hostname(v["host"]), "extra": extra}
    if bad_ip:
        warnings.append(f"{bad_ip} Host values are not IPv4/IPv6 addresses; they are matched by hostname instead")
    if dups:
        warnings.append(f"{dups} repeated Host + NE ID rows were ignored")
    return list(out.values()), warnings


def _key(n):
    return (n["ne_id"], n["ip"] or (n["host"] or "").lower())


def plan(c, nodes):
    cur = {(r["ne_id"], r["host_key"]): r for r in db.rows(c, "SELECT rowid, * FROM niam_nodes")}
    new_keys = {_key(n) for n in nodes}
    added = [n for n in nodes if _key(n) not in cur or not cur[_key(n)]["present"]]
    changed = [n for n in nodes if _key(n) in cur and cur[_key(n)]["present"]
               and json.dumps(n["extra"], sort_keys=True) != json.dumps(db.jloads(cur[_key(n)]["extra"], {}), sort_keys=True)]
    removed = [r for k, r in cur.items() if r["present"] and k not in new_keys]
    return cur, added, changed, removed


# ------------------------------------------------------------------ matching
def refresh(c):
    """Match every NIAM node to inventory, EDR and vulnerability data."""
    nodes = db.rows(c, "SELECT rowid rid, ip, hostname_norm FROM niam_nodes")
    if not nodes:
        return
    inv_ip, inv_hn = {}, {}
    for r in db.rows(c, """SELECT ic.ip, LOWER(ic.node_name) nn, ic.node_name, ic.node_type, ic.msp, ic.coverage_status, l.id lob_id, l.name lob
                          FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id"""):
        if r["ip"]:
            inv_ip.setdefault(r["ip"], []).append(r)
        if r["nn"]:
            inv_hn.setdefault(db.norm_hostname(r["nn"]), []).append(r)
    from .asset360 import agent_rank, agent_status
    agents_ip, agents_hn = {}, {}
    for h in db.rows(c, """SELECT aid, hostname, hostname_norm, connection_ip, console_state, online_state, removal_type, last_seen FROM hosts
                          WHERE console_state<>'hidden'"""):
        st = agent_status(h)
        if h["connection_ip"]:  # CrowdStrike assets by connection IP
            agents_ip.setdefault(h["connection_ip"], []).append((st, h))
        if h["hostname_norm"]:
            agents_hn.setdefault(h["hostname_norm"], []).append((st, h))
    hist = {}
    for r in db.rows(c, """SELECT ih.ip, h.aid, h.hostname, h.hostname_norm, h.connection_ip, h.console_state, h.online_state, h.removal_type,
                          h.last_seen FROM ip_history ih JOIN hosts h ON h.aid=ih.aid WHERE ih.kind='connection' AND h.console_state<>'hidden'"""):
        hist.setdefault(r["ip"], []).append((agent_status(r), r))
    vul = {r["ip"]: r for r in db.rows(c, """SELECT ip, SUM(crit) crit, SUM(high) high, SUM(med) med, SUM(low) low,
                                             MAX(last_scanned_at) last_scan FROM vuln_assets GROUP BY ip""")}

    def best(cands):
        return sorted(cands, key=lambda x: agent_rank(x[1]))[0] if cands else None

    upd = []
    for n in nodes:
        ip, hn = n["ip"], n["hostname_norm"]
        inv = inv_ip.get(ip, []) if ip else inv_hn.get(hn, [])
        cand = (agents_ip.get(ip) or hist.get(ip) or []) if ip else agents_hn.get(hn, [])
        b = best(cand)
        v = vul.get(ip) if ip else None
        upd.append((
            1 if inv else 0,
            ", ".join(sorted({r["lob"] for r in inv})) or None,
            ", ".join(sorted({r["msp"] for r in inv if r["msp"]})) or None,
            inv[0]["node_name"] if inv else None, inv[0]["node_type"] if inv else None,
            inv[0]["coverage_status"] if inv else None,
            b[1]["aid"] if b else None, b[1]["hostname"] if b else None, b[0] if b else "Not Installed", b[1]["last_seen"] if b else None,
            (v["crit"] or 0) if v else 0, (v["high"] or 0) if v else 0, (v["med"] or 0) if v else 0, (v["low"] or 0) if v else 0,
            v["last_scan"] if v else None, n["rid"]))
    c.executemany("""UPDATE niam_nodes SET in_inventory=?, lobs=?, msps=?, node_name=?, node_type=?, inv_status=?, aid=?, hostname=?,
                     edr_status=?, edr_last_seen=?, crit=?, high=?, med=?, low=?, last_scan=? WHERE rowid=?""", upd)


def commit(c, nodes, filename="", note="", uploaded_by="", mapping=None, warnings=None):
    cur, added, changed, removed = plan(c, nodes)
    now = db.now_iso()
    uid = c.execute("""INSERT INTO niam_uploads(filename, note, uploaded_by, uploaded_at, rows, added, removed, changed, mapping, warnings)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (filename, note, uploaded_by, now, len(nodes), len(added), len(removed), len(changed),
                     json.dumps(mapping or {}), json.dumps(warnings or []))).lastrowid
    c.executemany("""INSERT INTO niam_nodes(ne_id, host_key, host, ip, ip_num, hostname_norm, extra, upload_id, first_upload_id, first_seen_at,
                     last_seen_at, present, removed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,NULL)
                     ON CONFLICT(ne_id, host_key) DO UPDATE SET host=excluded.host, ip=excluded.ip, ip_num=excluded.ip_num,
                     hostname_norm=excluded.hostname_norm, extra=excluded.extra, upload_id=excluded.upload_id,
                     last_seen_at=excluded.last_seen_at, present=1, removed_at=NULL""",
                  [(n["ne_id"], _key(n)[1], n["host"], n["ip"], n["ip_num"], n["hostname_norm"], json.dumps(n["extra"]), uid, uid, now, now)
                   for n in nodes])
    c.executemany("UPDATE niam_nodes SET present=0, removed_at=? WHERE rowid=?", [(now, r["rowid"]) for r in removed])
    from .inventory import refresh_soon  # full re-join (includes niam.refresh, risk and the asset registry)
    refresh_soon(c)
    return {"upload_id": uid, "rows": len(nodes), "added": len(added), "removed": len(removed), "changed": len(changed)}


# ------------------------------------------------------------------ queries
SORTS = {"ne_id": "n.ne_id COLLATE NOCASE", "ip": "n.ip_num", "edr_status": "n.edr_status", "lobs": "n.lobs", "crit": "n.crit",
         "high": "n.high", "last_scan": "n.last_scan", "edr_last_seen": "n.edr_last_seen", "last_seen_at": "n.last_seen_at"}


def nodes_query(p):
    w, params = [], []
    present = p.get("present", "1")
    if present in ("0", "1"):
        w.append("n.present=?")
        params.append(int(present))
    if p.get("in_inventory") in ("0", "1"):
        w.append("n.in_inventory=?")
        params.append(int(p["in_inventory"]))
    if p.get("edr_status"):
        vals = p["edr_status"].split("|")
        w.append(f"n.edr_status IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("no_edr") == "1":
        w.append("n.edr_status NOT IN ('Online','Offline')")
    if p.get("vulnerable") == "1":
        w.append("(n.crit + n.high + n.med + n.low) > 0")
    if p.get("crit_high") == "1":
        w.append("(n.crit + n.high) > 0")
    if p.get("lob"):
        w.append("(', ' || n.lobs || ', ') LIKE ?")
        params.append(f"%, {p['lob']}, %")
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            ph = ",".join("?" * len(terms))
            w.append(f"(n.ip IN ({ph}) OR n.ne_id IN ({ph}))")
            params += [db.canon_ip(t) for t in terms] + terms
        elif db.is_range_query(q):
            w.append("ip_in(n.ip, ?)")
            params.append(q)
        else:
            like = f"%{q}%"
            ip = db.canon_ip(q) if db.is_ip(q) else q
            w.append("(n.ip LIKE ? OR n.ne_id LIKE ? OR n.host LIKE ? OR n.hostname LIKE ? OR n.node_name LIKE ? OR n.extra LIKE ?)")
            params += [ip + "%", like, like, like, like, like]
    sort = SORTS.get(p.get("sort") or "", "n.ne_id COLLATE NOCASE")
    direction = "DESC" if (p.get("dir") or "asc") == "desc" else "ASC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return where, params, f"ORDER BY {sort} {direction}, n.ip_num"


def summary(c):
    s = db.one(c, """SELECT COUNT(*) nodes, COUNT(DISTINCT ne_id) ne_ids, SUM(in_inventory=1) in_inventory, SUM(in_inventory=0) not_in_inventory,
        SUM(edr_status='Online') online, SUM(edr_status='Offline') offline, SUM(edr_status NOT IN ('Online','Offline')) no_edr,
        SUM(edr_status IN ('Removed','Hidden','Old EDR import')) edr_removed, SUM(edr_status='Not Installed') never_installed,
        SUM(crit + high > 0) crit_high, SUM(crit + high > 0 AND edr_status NOT IN ('Online','Offline')) crit_high_no_edr,
        SUM(last_scan IS NOT NULL) scanned FROM niam_nodes WHERE present=1""")
    gone = c.execute("SELECT COUNT(*) FROM niam_nodes WHERE present=0").fetchone()[0]
    by_lob = db.rows(c, """SELECT COALESCE(lobs, 'Not in any inventory') lob, COUNT(*) nodes, SUM(edr_status IN ('Online','Offline')) edr,
        SUM(edr_status NOT IN ('Online','Offline')) no_edr, SUM(crit + high > 0) crit_high FROM niam_nodes WHERE present=1
        GROUP BY 1 ORDER BY nodes DESC""")
    last = db.one(c, "SELECT * FROM niam_uploads ORDER BY id DESC LIMIT 1")
    return {**{k: (v or 0) for k, v in s.items()}, "gone": gone, "by_lob": by_lob, "last_upload": last}


# ------------------------------------------------------------------ routes
def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    nodes, warnings = build(parsed, mapping)
    if not nodes:
        raise ValueError("No NIAM rows found with this mapping")
    return parsed, mapping, nodes, warnings


@router.post("/api/niam/parse")
def niam_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/niam/preview")
def niam_preview(data: dict = Body(...)):
    _, _, nodes, warnings = _load(data)
    with db.get_conn() as c:
        cur, added, changed, removed = plan(c, nodes)
        ips = {n["ip"] for n in nodes if n["ip"]}
        edr_ips = {r[0] for r in c.execute("SELECT connection_ip FROM hosts WHERE console_state='active' AND connection_ip<>''")}
        inv_ips = {r[0] for r in c.execute("SELECT ip FROM inventory_current WHERE ip<>''")}
    return {"rows": len(nodes), "ne_ids": len({n["ne_id"] for n in nodes}), "added": len(added), "changed": len(changed),
            "removed": len(removed), "first": not cur, "warnings": warnings,
            "with_edr": len(ips & edr_ips), "in_inventory": len(ips & inv_ips), "ipv6": sum(1 for i in ips if ":" in i),
            "sample": [{"ne_id": n["ne_id"], "host": n["host"], "ip": n["ip"]} for n in (added or nodes)[:50]]}


@router.post("/api/niam/commit")
def niam_commit(data: dict = Body(...)):
    parsed, mapping, nodes, warnings = _load(data)
    with db.get_conn() as c:
        return commit(c, nodes, filename=parsed["filename"], note=data.get("note", ""), uploaded_by=data.get("uploaded_by", ""),
                      mapping=mapping, warnings=warnings)


@router.get("/api/niam/summary")
def niam_summary():
    with db.get_conn() as c:
        return summary(c)


@router.get("/api/niam/nodes")
def niam_nodes(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params, order = nodes_query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM niam_nodes n {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT n.rowid id, n.* FROM niam_nodes n {where} {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    for r in rows:
        r["extra"] = db.jloads(r["extra"], {})
    return {"total": total, "rows": rows}


EXPORT = [("ne_id", "NE ID"), ("host", "Host"), ("ip", "IP (normalised)"), ("present", "In latest dump"), ("in_inventory", "In inventory"),
          ("lobs", "LOB"), ("msps", "MSP"), ("node_name", "Inventory Node Name"), ("node_type", "Node Type"), ("inv_status", "Inventory EDR Status"),
          ("edr_status", "EDR Status"), ("hostname", "Falcon Hostname"), ("aid", "Agent ID"), ("edr_last_seen", "EDR Last Seen"),
          ("crit", "Critical"), ("high", "High"), ("med", "Medium"), ("low", "Low"), ("last_scan", "Last Scan"),
          ("first_seen_at", "First in NIAM"), ("last_seen_at", "Last in NIAM"), ("removed_at", "Dropped from NIAM"), ("extra_text", "Other NIAM columns")]


@router.get("/api/niam/nodes/export")
def niam_export(request: Request):
    where, params, order = nodes_query(dict(request.query_params))
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT n.* FROM niam_nodes n {where} {order}", params)
    for r in rows:
        r["present"] = "Yes" if r["present"] else "No"
        r["in_inventory"] = "Yes" if r["in_inventory"] else "No"
        r["extra_text"] = " · ".join(f"{k}: {v}" for k, v in db.jloads(r["extra"], {}).items())
    return xlsx_response([("NIAM nodes", EXPORT, rows)], "niam_nodes")


@router.get("/api/niam/uploads")
def niam_uploads():
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT id, filename, note, uploaded_by, uploaded_at, rows, added, removed, changed FROM niam_uploads ORDER BY id DESC")}


@router.delete("/api/niam")
def niam_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM niam_nodes")
        c.execute("DELETE FROM niam_uploads")
        from .inventory import refresh_soon
        refresh_soon(c)
    return {"ok": True}
