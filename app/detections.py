"""Recent CrowdStrike detections (Alerts API), shown per asset on Asset 360 with a date filter.

Every sync fetches the alerts created in the last `detections_days` days (default 30) and replaces that window in the
`detections` table. Needs the API scope "Alerts: Read"; without it the sync carries on and says so."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

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


def fetch(client, days=30):
    """Pull the alerts of the last `days` days into the detections table. Returns a one-line summary."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids, offset = [], 0
    while True:
        body = client._call(client.alerts.query_alerts_v2, "Detections", filter=f"created_timestamp:>'{since}'",
                            limit=10000, offset=offset, sort="created_timestamp.desc")
        res = body.get("resources") or []
        ids += res
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
        offset += len(res)
        if not res or offset >= total or offset >= 50000:
            break
    now, rows = db.now_iso(), []
    for i in range(0, len(ids), 1000):
        body = client._call(client.alerts.get_alerts_v2, "Detection details", composite_ids=ids[i:i + 1000])
        rows += [_row(a, now) for a in body.get("resources") or []]
    with db.get_conn() as c:
        c.execute("DELETE FROM detections WHERE created_at > ?", (since,))
        c.executemany(f"INSERT OR REPLACE INTO detections({COLS}) VALUES ({','.join('?' * 17)})", rows)
        c.execute("DELETE FROM detections WHERE created_at < ?",  # keep 180 days at most
                  ((datetime.now(timezone.utc) - timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
    return f"{len(rows):,} detections in the last {days} days"


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
