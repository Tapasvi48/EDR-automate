"""Recent CrowdStrike detections (Alerts API), shown per asset on Asset 360 with a date filter.

The `detections` table holds the alerts created in the last `detections_days` days (default 30): re-read in full once a
day, and between those only the alerts created or updated since the previous sync are fetched. Needs the API scope "Alerts: Read"; without it the sync carries on and says so."""
import json
from datetime import datetime, timedelta, timezone

from fastapi import Body, APIRouter, Query, Request

from . import db

router = APIRouter()

SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1, "Info": 1}


def _sev_name(a):
    name = a.get("severity_name")
    if name:
        return name
    s = a.get("severity") or 0  # 0-100 on the Alerts API
    return "Critical" if s >= 80 else "High" if s >= 60 else "Medium" if s >= 40 else "Low" if s >= 20 else "Informational"


def _row(a, now):
    dev = a.get("device") or {}
    return (a.get("composite_id") or a.get("id"), dev.get("device_id") or a.get("agent_id") or "", dev.get("hostname") or "",
            _sev_name(a), a.get("display_name") or a.get("name") or "", a.get("tactic") or "", a.get("technique") or "",
            a.get("status") or "", a.get("created_timestamp") or a.get("timestamp") or "",
            (a.get("description") or "")[:2000], a.get("filename") or "", (a.get("cmdline") or "")[:2000],
            a.get("pattern_disposition_description") or "", a.get("product") or "", now,
            a.get("assigned_to_name") or a.get("assigned_to_uid") or "", a.get("updated_timestamp") or "", json.dumps(a, default=str)[:30000])


COLS = "id, aid, hostname, severity, name, tactic, technique, status, created_at, description, filename, cmdline, disposition, product, fetched_at, assigned_to, updated_at, raw"


ISO = "%Y-%m-%dT%H:%M:%SZ"
MAX_PAGE = 10000  # the Alerts API refuses offset + limit > 10,000


def _iso(dt):
    return dt.strftime(ISO)


def _ids(client, field, start, end, extra=""):
    """IDs of alerts with start < field <= end (end None = now). A window holding more than 10,000 alerts is split in
    half until each part fits, since the API cannot page past 10,000."""
    flt = f"{field}:>'{_iso(start)}'" + (f"+{field}:<='{_iso(end)}'" if end else "") + (f"+{extra}" if extra else "")
    body = client._call(client.alerts.query_alerts_v2, "Detections", filter=flt, limit=MAX_PAGE, offset=0, sort=f"{field}.desc")
    res = body.get("resources") or []
    total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
    stop = end or datetime.now(timezone.utc)
    if total <= len(res) or stop - start < timedelta(minutes=1):
        return res
    mid = start + (stop - start) / 2
    return _ids(client, field, mid, end, extra) + _ids(client, field, start, mid, extra)


INFO_SEV = ("Informational", "Info")


def include_info():
    return (db.get_settings().get("detections_include_info") or "0") == "1"


def fetch(client, days=30):
    """Alerts of the last `days` days into the detections table. Returns a one-line summary.
    The window is read in full only the first time (or when the window / informational setting changes); every later sync
    asks only for alerts created or updated since the last fetch (new detections plus status / analyst changes)."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    st = db.get_settings()
    last, last_full = st.get("detections_last_fetch"), st.get("detections_last_full")
    info = (st.get("detections_include_info") or "0") == "1"
    full = (not last or not last_full or st.get("detections_days_fetched") != str(days)
            or st.get("detections_info_fetched", "0") != ("1" if info else "0"))
    sev = "" if info else "severity:>=20"  # informational (severity < 20 on the Alerts API's 0-100 scale) not fetched
    if full:
        ids = _ids(client, "created_timestamp", since, None, extra=sev)
    else:
        start = datetime.strptime(last, ISO).replace(tzinfo=timezone.utc) - timedelta(minutes=15)
        ids = _ids(client, "updated_timestamp", start, None, extra="+".join(x for x in (f"created_timestamp:>'{_iso(since)}'", sev) if x))
    stamp, rows = db.now_iso(), []
    for i in range(0, len(ids), 1000):
        body = client._call(client.alerts.get_alerts_v2, "Detection details", composite_ids=ids[i:i + 1000])
        rows += [_row(a, stamp) for a in body.get("resources") or []]
    with db.get_conn() as c:
        if full:
            c.execute("DELETE FROM detections WHERE created_at > ?", (_iso(since),))
        c.executemany(f"INSERT OR REPLACE INTO detections({COLS}) VALUES ({','.join('?' * 18)})", rows)
        c.execute("DELETE FROM detections WHERE created_at < ?", (_iso(now - timedelta(days=180)),))  # keep 180 days at most
        if not info:  # stored before informational was switched off
            c.execute(f"DELETE FROM detections WHERE severity IN ({','.join('?' * len(INFO_SEV))})", INFO_SEV)
        upd = {"detections_last_fetch": _iso(now), "detections_days_fetched": str(days), "detections_info_fetched": "1" if info else "0"}
        if full:
            upd["detections_last_full"] = _iso(now)
        c.executemany("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", list(upd.items()))
    if full:
        return f"{len(rows):,} detections in the last {days} days"
    return f"{len(rows):,} detections new or updated since the last sync"


@router.get("/api/asset/detections")
def asset_detections(aids: str = "", hostnames: str = "", date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to")):
    """Detections for an asset's agents (AIDs, or hostnames for agents that left the console) in a date range
    (default: the last 7 days)."""
    aid_l = [a for a in aids.split(",") if a]
    hn_l = [db.norm_hostname(h) for h in hostnames.split(",") if h]
    if not aid_l and not hn_l:
        return {"rows": [], "counts": {}, "from": date_from, "to": date_to}
    now = datetime.now(timezone.utc)
    d_from = date_from or (now - timedelta(days=7)).strftime("%Y-%m-%d")
    d_to = date_to or now.strftime("%Y-%m-%d")
    w, params = [], []
    if aid_l:
        w.append(f"aid IN ({','.join('?' * len(aid_l))})")
        params += aid_l
    if hn_l:
        w.append(f"LOWER(hostname) IN ({','.join('?' * len(hn_l))})")
        params += hn_l
    with db.get_conn() as c:
        info_sql = "" if include_info() else f" AND COALESCE(severity,'') NOT IN ({','.join(repr(x) for x in INFO_SEV)})"
        rows = db.rows(c, f"""SELECT {COLS} FROM detections WHERE ({' OR '.join(w)}) AND substr(created_at,1,10) BETWEEN ? AND ?{info_sql}
                              ORDER BY created_at DESC LIMIT 1000""", params + [d_from, d_to])
        fetched = db.one(c, "SELECT MAX(fetched_at) at, COUNT(*) n FROM detections")
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return {"rows": rows, "counts": counts, "from": d_from, "to": d_to, "fetched_at": fetched["at"], "stored": fetched["n"]}


# ------------------------------------------------------------------ CrowdStrike → Detections page
SEV_SQL = "CASE d.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"
OPEN_SQL = "LOWER(COALESCE(d.status,'new')) NOT IN ('closed','resolved','true_positive','false_positive','ignored')"
LIST_COLS = """d.id, d.aid, d.hostname, d.severity, d.name, d.tactic, d.technique, d.status, d.created_at, d.updated_at, d.description,
    d.filename, d.cmdline, d.disposition, d.product, d.assigned_to, h.connection_ip ip, h.platform_name, h.online_state,
    (SELECT GROUP_CONCAT(DISTINCT l.name) FROM host_map hm JOIN lobs l ON l.id=hm.lob_id WHERE hm.aid=d.aid) lob,
    (SELECT MAX(r.exposed) FROM asset_registry r WHERE r.aid=d.aid) exposed"""
FROM = "detections d LEFT JOIN hosts h ON h.aid=d.aid"


def _where(p):
    now = datetime.now(timezone.utc)
    d_from = p.get("from") or (now - timedelta(days=6)).strftime("%Y-%m-%d")
    w, params = ["substr(d.created_at,1,10) >= ?"], [d_from]
    if p.get("to"):
        w.append("substr(d.created_at,1,10) <= ?")
        params.append(p["to"])
    # informational left out unless switched on, or asked for by the severity filter
    if not include_info() and not any(x in INFO_SEV for x in (p.get("severity") or "").split("|")):
        w.append(f"COALESCE(d.severity,'') NOT IN ({','.join('?' * len(INFO_SEV))})")
        params += list(INFO_SEV)
    for key, col in (("severity", "d.severity"), ("status", "LOWER(COALESCE(d.status,'new'))"), ("tactic", "d.tactic")):
        if p.get(key):
            vals = [v.lower() if key == "status" else v for v in p[key].split("|")]
            w.append(f"{col} IN ({','.join('?' * len(vals))})")
            params += vals
    if p.get("open") == "1":
        w.append(OPEN_SQL)
    if p.get("unassigned") == "1":
        w.append("COALESCE(d.assigned_to,'')=''")
    if p.get("aid"):
        w.append("d.aid=?")
        params.append(p["aid"])
    if db.multi(p, "lob"):
        lobs = [int(x) for x in db.multi(p, "lob")]
        w.append(f"EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=d.aid AND hm.lob_id IN ({','.join('?' * len(lobs))}))")
        params += lobs
    if p.get("exposed") == "1":
        w.append("EXISTS (SELECT 1 FROM asset_registry r WHERE r.aid=d.aid AND r.exposed=1)")
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(d.name LIKE ? OR d.hostname LIKE ? OR h.connection_ip LIKE ? OR d.technique LIKE ? OR d.filename LIKE ? "
                 "OR d.cmdline LIKE ? OR d.assigned_to LIKE ? OR d.description LIKE ?)")
        params += [like] * 8
    return "WHERE " + " AND ".join(w), params


@router.get("/api/detections")
def detections_list(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    where, params = _where(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {FROM} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {LIST_COLS} FROM {FROM} {where} ORDER BY d.created_at DESC LIMIT ? OFFSET ?",
                       params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@router.post("/api/detections/informational")
def detections_informational(data: dict = Body(...)):
    """Switch informational detections on / off. Off: stored informational detections are removed at once and the next syncs do
    not fetch them; on: the next sync re-reads the window with them."""
    on = bool(data.get("include"))
    with db.get_conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('detections_include_info', ?)", ("1" if on else "0",))
        removed = 0 if on else c.execute(f"DELETE FROM detections WHERE severity IN ({','.join('?' * len(INFO_SEV))})", INFO_SEV).rowcount
    return {"ok": True, "include": on, "removed": removed,
            "message": ("Informational detections will be fetched from the next sync" if on
                        else f"Informational detections switched off · {removed:,} removed; the next syncs do not fetch them")}


@router.get("/api/detections/summary")
def detections_summary(request: Request):
    """Counts for the selected date range (filters other than the date do not apply, so the tiles stay a fixed frame)."""
    p = {k: v for k, v in request.query_params.items() if k in ("from", "to")}
    where, params = _where(p)
    with db.get_conn() as c:
        s = db.one(c, f"""SELECT COUNT(*) total, COUNT(DISTINCT d.aid) hosts, SUM(d.severity='Critical') critical, SUM(d.severity='High') high,
            SUM(d.severity='Medium') medium, SUM(d.severity IN ('Low','Informational','Info')) low, SUM({OPEN_SQL}) open,
            SUM({OPEN_SQL} AND COALESCE(d.assigned_to,'')='') unassigned,
            SUM(EXISTS (SELECT 1 FROM asset_registry r WHERE r.aid=d.aid AND r.exposed=1)) exposed FROM {FROM} {where}""", params)
        tactics = db.rows(c, f"""SELECT COALESCE(NULLIF(d.tactic,''),'(none)') tactic, COUNT(*) n FROM {FROM} {where}
                                 GROUP BY 1 ORDER BY n DESC LIMIT 12""", params)
        statuses = db.rows(c, f"SELECT LOWER(COALESCE(NULLIF(d.status,''),'new')) status, COUNT(*) n FROM {FROM} {where} GROUP BY 1 ORDER BY n DESC", params)
        top_hosts = db.rows(c, f"""SELECT d.aid, MAX(d.hostname) hostname, MAX(h.connection_ip) ip, COUNT(*) n,
                                   SUM(d.severity IN ('Critical','High')) crit_high FROM {FROM} {where}
                                   GROUP BY d.aid ORDER BY crit_high DESC, n DESC LIMIT 8""", params)
        by_day = db.rows(c, f"""SELECT substr(d.created_at,1,10) day, COUNT(*) n, SUM(d.severity IN ('Critical','High')) crit_high
                                FROM {FROM} {where} GROUP BY 1 ORDER BY 1""", params)
        stored = db.one(c, "SELECT COUNT(*) n, MIN(created_at) oldest, MAX(fetched_at) fetched_at FROM detections")
        lobs = db.rows(c, """SELECT DISTINCT l.id, l.name FROM detections d JOIN host_map hm ON hm.aid=d.aid JOIN lobs l ON l.id=hm.lob_id
                             ORDER BY l.name""")
    st = db.get_settings()
    return {**{k: v or 0 for k, v in s.items()}, "tactics": tactics, "statuses": statuses, "top_hosts": top_hosts, "by_day": by_day,
            "stored": stored, "lobs": lobs, "days": int(st.get("detections_days") or 30), "include_info": include_info(),
            "last_full": st.get("detections_last_full"), "last_fetch": st.get("detections_last_fetch")}


EXPORT = [("created_at", "Created (UTC)"), ("severity", "Severity"), ("name", "Detection"), ("tactic", "Tactic"), ("technique", "Technique"),
          ("status", "Status"), ("assigned_to", "Analyst"), ("hostname", "Hostname"), ("ip", "Connection IP"), ("lob", "LOB"),
          ("filename", "File"), ("cmdline", "Command line"), ("disposition", "Action taken"), ("description", "Description"),
          ("updated_at", "Updated (UTC)"), ("aid", "Agent ID"), ("id", "Detection ID")]


@router.get("/api/detections/export")
def detections_export(request: Request):
    from .exporter import xlsx_response
    p = dict(request.query_params)
    where, params = _where(p)
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT {LIST_COLS} FROM {FROM} {where} ORDER BY d.created_at DESC LIMIT 200000", params)
    return xlsx_response([("CrowdStrike detections", EXPORT, rows)], "crowdstrike_detections")


# ------------------------------------------------------------------ one detection, in full
def _g(d, *path):
    for k in path:
        d = d.get(k) if isinstance(d, dict) else None
    return d


def _proc(p):
    if not isinstance(p, dict) or not p:
        return None
    return {k: v for k, v in {"file": p.get("filename"), "path": p.get("filepath"), "command line": p.get("cmdline"), "sha256": p.get("sha256"),
                              "md5": p.get("md5"), "user": p.get("user_name"), "process id": p.get("process_id") or p.get("local_process_id")}.items() if v}


@router.get("/api/detections/item")
def detection_item(id: str):
    """Everything stored for one detection: what fired (MITRE, pattern, severity, confidence), the process tree, the host,
    status and analyst, and the raw record from the Alerts API."""
    with db.get_conn() as c:
        d = db.one(c, f"""SELECT {LIST_COLS}, d.raw FROM {FROM} WHERE d.id=?""", (id,))
        if not d:
            from fastapi import HTTPException
            raise HTTPException(404, "Detection not found")
        same = db.rows(c, """SELECT id, name, severity, status, created_at FROM detections WHERE aid=? AND id<>? ORDER BY created_at DESC LIMIT 15""",
                       (d["aid"], id))
        host = db.one(c, """SELECT aid, hostname, connection_ip, local_ip, external_ip, platform_name, os_version, agent_version, online_state,
                            last_seen, machine_domain, site_name, last_login_user, containment_status FROM hosts WHERE aid=?""", (d["aid"],))
    raw = db.jloads(d.pop("raw", None), {}) or {}
    what = {k: v for k, v in {
        "Detection": d["name"], "Description": d["description"], "Severity": d["severity"], "Confidence": raw.get("confidence"),
        "Tactic": " · ".join(x for x in (raw.get("tactic_id"), d["tactic"]) if x), "Technique": " · ".join(x for x in (raw.get("technique_id"), d["technique"]) if x),
        "Objective": raw.get("objective"), "Scenario": raw.get("scenario"), "Pattern ID": raw.get("pattern_id"), "Type": raw.get("type"),
        "Product": d["product"], "Action taken": d["disposition"], "IOC": " ".join(str(x) for x in (raw.get("ioc_type"), raw.get("ioc_value")) if x),
    }.items() if v not in (None, "", [])}
    process = _proc(raw) or {k: v for k, v in {"file": d["filename"], "command line": d["cmdline"]}.items() if v}
    tree = [x for x in (("Grandparent", _proc(raw.get("grandparent_details"))), ("Parent", _proc(raw.get("parent_details"))), ("Process", process)) if x[1]]
    state = {k: v for k, v in {"Status": d["status"], "Analyst": d["assigned_to"], "Created": d["created_at"], "Updated": d["updated_at"],
                               "Falcon link": raw.get("falcon_host_link"), "Tags": ", ".join(raw.get("tags") or []) if isinstance(raw.get("tags"), list) else None,
                               "Detection ID": d["id"]}.items() if v}
    return {"detection": d, "what": what, "tree": tree, "state": state, "host": host, "same_host": same, "raw": raw}
