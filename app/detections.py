"""Recent CrowdStrike detections (Alerts API), shown per asset on Asset 360 with a date filter.

The `detections` table holds the alerts created in the last `detections_days` days (default 30): re-read in full once a
day, and between those only the alerts created or updated since the previous sync are fetched. Needs the API scope "Alerts: Read"; without it the sync carries on and says so."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query, Request

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
            a.get("assigned_to_name") or a.get("assigned_to_uid") or "", a.get("updated_timestamp") or "")


COLS = "id, aid, hostname, severity, name, tactic, technique, status, created_at, description, filename, cmdline, disposition, product, fetched_at, assigned_to, updated_at"


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


def fetch(client, days=30):
    """Alerts of the last `days` days into the detections table. Returns a one-line summary.
    Once a day the whole window is re-read; the syncs in between only ask for alerts created or updated since the last
    fetch (status / analyst changes included), which is a small fraction of the calls."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    st = db.get_settings()
    last, last_full = st.get("detections_last_fetch"), st.get("detections_last_full")
    full = not last or not last_full or last_full < _iso(now - timedelta(hours=24)) or st.get("detections_days_fetched") != str(days)
    if full:
        ids = _ids(client, "created_timestamp", since, None)
    else:
        start = datetime.strptime(last, ISO).replace(tzinfo=timezone.utc) - timedelta(minutes=15)
        ids = _ids(client, "updated_timestamp", start, None, extra=f"created_timestamp:>'{_iso(since)}'")
    stamp, rows = db.now_iso(), []
    for i in range(0, len(ids), 1000):
        body = client._call(client.alerts.get_alerts_v2, "Detection details", composite_ids=ids[i:i + 1000])
        rows += [_row(a, stamp) for a in body.get("resources") or []]
    with db.get_conn() as c:
        if full:
            c.execute("DELETE FROM detections WHERE created_at > ?", (_iso(since),))
        c.executemany(f"INSERT OR REPLACE INTO detections({COLS}) VALUES ({','.join('?' * 17)})", rows)
        c.execute("DELETE FROM detections WHERE created_at < ?", (_iso(now - timedelta(days=180)),))  # keep 180 days at most
        upd = {"detections_last_fetch": _iso(now), "detections_days_fetched": str(days)}
        if full:
            upd["detections_last_full"] = _iso(now)
        c.executemany("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", list(upd.items()))
    if full:
        return f"{len(rows):,} detections in the last {days} days"
    return f"{len(rows):,} detections new or updated since the last sync (full {days}-day re-read once a day)"


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
        rows = db.rows(c, f"""SELECT {COLS} FROM detections WHERE ({' OR '.join(w)}) AND substr(created_at,1,10) BETWEEN ? AND ?
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
    if p.get("lob"):
        w.append("EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=d.aid AND hm.lob_id=?)")
        params.append(int(p["lob"]))
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
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params = _where(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {FROM} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {LIST_COLS} FROM {FROM} {where} ORDER BY d.created_at DESC LIMIT ? OFFSET ?",
                       params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


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
            "stored": stored, "lobs": lobs, "days": int(st.get("detections_days") or 30),
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
