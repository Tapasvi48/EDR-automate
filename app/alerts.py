"""Alerts: one feed of recent alerts from CrowdStrike (Alerts API, stored on each sync), Seceon NDR (webhook / upload,
stored) and Splunk Enterprise Security notable events (asked live, cached for a minute; simulated in sample mode).
Each alert is linked to the asset it concerns (hostname / agent / IP -> the asset registry: name, LOB, internet exposure)."""
import hashlib
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query, Request

from . import config, db, splunk
from .exporter import xlsx_response

router = APIRouter()
SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
_splunk_cache = {}


def _range(d_from, d_to, days=7):
    now = datetime.now(timezone.utc)
    return d_from or (now - timedelta(days=days - 1)).strftime("%Y-%m-%d"), d_to or now.strftime("%Y-%m-%d")


def _splunk_rows(d_from, d_to):
    """Notables in the range: [(time, rule, urgency, category, src, dest, host, status, owner)] or (None, reason)."""
    key = (d_from, d_to)
    hit = _splunk_cache.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1], hit[2]
    cfg = splunk.settings()
    rows, err = [], None
    if config.DEMO:
        with db.get_conn() as c:
            hosts = db.rows(c, "SELECT hostname, connection_ip FROM hosts WHERE console_state='active' ORDER BY aid LIMIT 400")
        start = datetime.strptime(d_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        span = max(1, (datetime.strptime(d_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) - start).days + 1)
        now = datetime.now(timezone.utc)
        for k in range(min(400, span * 9)):
            h = int(hashlib.md5(f"{d_from}{k}".encode()).hexdigest(), 16)
            host = hosts[h % len(hosts)] if hosts else {"hostname": "", "connection_ip": ""}
            rule, urg, cat = splunk.DEMO_RULES[(h >> 5) % len(splunk.DEMO_RULES)]
            t = start + timedelta(minutes=(h >> 11) % (span * 1440))
            if t > now:
                continue
            rows.append({"created_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "name": rule, "severity": urg.title(), "category": cat,
                         "src": "", "dest": host["connection_ip"], "host": host["hostname"], "status": ["New", "In Progress", "Closed"][(h >> 3) % 3],
                         "owner": ["", "Rahul Verma", "Neha Kapoor", "Vikram Rao"][(h >> 7) % 4]})
    elif not cfg["url"]:
        err = "Splunk is not connected"
    else:
        spl = ('search index=notable | eval t=strftime(_time, "%Y-%m-%dT%H:%M:%SZ") '
               "| table t rule_name urgency security_domain src dest host status_label owner | head 2000")
        try:
            for r in splunk._search_window(cfg, spl, d_from, d_to):
                rows.append({"created_at": r.get("t"), "name": r.get("rule_name"), "severity": str(r.get("urgency") or "").title(),
                             "category": r.get("security_domain"), "src": r.get("src"), "dest": r.get("dest"), "host": r.get("host"),
                             "status": r.get("status_label"), "owner": r.get("owner")})
        except Exception as e:  # noqa: BLE001
            err = str(e)
    _splunk_cache[key] = (time.time(), rows, err)
    return rows, err


def collect(d_from, d_to):
    """All alerts in the range, newest first, each with its asset (name, IP, LOB, internet exposure)."""
    out = []
    with db.get_conn() as c:
        reg_ip = {r["ip"]: r for r in db.rows(c, "SELECT ip, name, lobs, exposed, aid FROM asset_registry WHERE ip IS NOT NULL")}
        reg_aid = {r["aid"]: r for r in reg_ip.values() if r["aid"]}
        by_name = {}
        for r in reg_ip.values():
            for n in (r["name"] or "").split(", "):
                if n:
                    by_name.setdefault(db.norm_hostname(n), r)
        for r in db.rows(c, """SELECT id, aid, hostname, severity, name, tactic, technique, status, created_at, assigned_to, filename
                               FROM detections WHERE substr(created_at,1,10) BETWEEN ? AND ?""", (d_from, d_to)):
            a = reg_aid.get(r["aid"]) or by_name.get(db.norm_hostname(r["hostname"])) or {}
            out.append({"source": "CrowdStrike", "id": r["id"], "created_at": r["created_at"], "severity": r["severity"], "name": r["name"],
                        "detail": " · ".join(x for x in (r["tactic"], r["technique"], r["filename"]) if x), "host": r["hostname"],
                        "ip": a.get("ip"), "asset": a.get("name") or r["hostname"], "lobs": a.get("lobs"), "exposed": a.get("exposed"),
                        "status": (r["status"] or "new").replace("_", " "), "owner": r["assigned_to"]})
        for r in db.rows(c, """SELECT id, created_at, severity, name, category, src_ip, dst_ip, host, status FROM ndr_alerts
                               WHERE substr(created_at,1,10) BETWEEN ? AND ?""", (d_from, d_to)):
            a = reg_ip.get(r["dst_ip"]) or reg_ip.get(r["src_ip"]) or by_name.get(db.norm_hostname(r["host"])) or {}
            out.append({"source": "Seceon NDR", "id": r["id"], "created_at": r["created_at"], "severity": r["severity"], "name": r["name"],
                        "detail": " · ".join(x for x in (r["category"], f"{r['src_ip'] or '?'} → {r['dst_ip'] or '?'}") if x), "host": r["host"],
                        "ip": a.get("ip") or r["dst_ip"] or r["src_ip"], "asset": a.get("name") or r["host"], "lobs": a.get("lobs"),
                        "exposed": a.get("exposed"), "status": r["status"], "owner": None})
    sp, sp_err = _splunk_rows(d_from, d_to)
    for i, r in enumerate(sp):
        a = reg_ip.get(r.get("dest") or "") or reg_ip.get(r.get("src") or "") or by_name.get(db.norm_hostname(r.get("host"))) or {}
        out.append({"source": "Splunk", "id": f"splunk:{i}:{r['created_at']}", "created_at": r["created_at"], "severity": r["severity"],
                    "name": r["name"], "detail": " · ".join(x for x in (r.get("category"), r.get("src") and f"src {r['src']}", r.get("dest") and f"dest {r['dest']}") if x),
                    "host": r.get("host"), "ip": a.get("ip") or r.get("dest") or r.get("src"), "asset": a.get("name") or r.get("host"),
                    "lobs": a.get("lobs"), "exposed": a.get("exposed"), "status": r.get("status"), "owner": r.get("owner")})
    out.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return out, sp_err


def _filter(rows, p):
    if p.get("source"):
        rows = [r for r in rows if r["source"] in p["source"].split("|")]
    if p.get("severity"):
        rows = [r for r in rows if r["severity"] in p["severity"].split("|")]
    if p.get("open") == "1":
        rows = [r for r in rows if not any(w in str(r["status"] or "").lower() for w in ("closed", "resolved"))]
    if p.get("exposed") == "1":
        rows = [r for r in rows if r["exposed"]]
    if p.get("q"):
        q = p["q"].lower()
        rows = [r for r in rows if q in f"{r['name']} {r['host'] or ''} {r['ip'] or ''} {r['asset'] or ''} {r['lobs'] or ''} {r['owner'] or ''}".lower()]
    return rows


@router.get("/api/alerts")
def alerts(request: Request, date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to")):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(500, max(1, int(p.get("size") or 50)))
    d_from, d_to = _range(date_from, date_to)
    allr, sp_err = collect(d_from, d_to)
    rows = _filter(allr, p)
    by_src, by_sev, by_day = {}, {}, {}
    for r in allr:
        by_src[r["source"]] = by_src.get(r["source"], 0) + 1
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        d = (r["created_at"] or "")[:10]
        x = by_day.setdefault(d, {"day": d, "CrowdStrike": 0, "Splunk": 0, "Seceon NDR": 0})
        x[r["source"]] = x.get(r["source"], 0) + 1
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size], "from": d_from, "to": d_to,
            "summary": {"total": len(allr), "by_source": by_src, "by_severity": by_sev,
                        "open": sum(1 for r in allr if not any(w in str(r["status"] or "").lower() for w in ("closed", "resolved"))),
                        "exposed": sum(1 for r in allr if r["exposed"]), "crit_high": sum(1 for r in allr if r["severity"] in ("Critical", "High"))},
            "by_day": sorted(by_day.values(), key=lambda x: x["day"]), "splunk_error": sp_err, "demo": config.DEMO}


@router.get("/api/alerts/export")
def alerts_export(request: Request, date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to")):
    d_from, d_to = _range(date_from, date_to)
    rows = _filter(collect(d_from, d_to)[0], dict(request.query_params))
    for r in rows:
        r["exposed_text"] = "Yes" if r["exposed"] else ""
    return xlsx_response([("Alerts", [("created_at", "Time (UTC)"), ("source", "Source"), ("severity", "Severity"), ("name", "Alert"), ("detail", "Detail"),
                                      ("asset", "Asset"), ("ip", "IP"), ("lobs", "LOB"), ("exposed_text", "Internet exposed"), ("status", "Status"),
                                      ("owner", "Analyst")], rows)], f"alerts_{d_from}_{d_to}")


# ------------------------------------------------------------------ why is a source empty?
@router.get("/api/alerts/status")
def alerts_status():
    """Per source: is it set up, what is stored, when it was last fetched, and what the last sync said about it."""
    from . import falcon
    with db.get_conn() as c:
        d = db.one(c, "SELECT COUNT(*) n, MAX(created_at) newest, MAX(fetched_at) fetched FROM detections")
        run = db.one(c, "SELECT id, started_at, status FROM sync_runs WHERE mode<>'sample' ORDER BY id DESC LIMIT 1")
        step = db.one(c, "SELECT level, message, ts FROM sync_log WHERE run_id=? AND step='detections' ORDER BY id DESC LIMIT 1",
                      (run["id"],)) if run else None
        n = db.one(c, "SELECT COUNT(*) n, MAX(created_at) newest, MAX(received_at) received FROM ndr_alerts")
    cfg = splunk.settings()
    cs_ok = falcon.is_configured()
    cs_reason = (None if d["n"] else "CrowdStrike is not connected (Sync & settings)" if not cs_ok and not config.DEMO
                 else "No sync has run yet" if not run and not config.DEMO
                 else f"Last sync: {step['message']}" if step and step["level"] in ("warn", "warning", "error")
                 else "The last sync fetched no alerts: the console had none in the window, or the API client lacks Alerts: Read" if not config.DEMO else None)
    return {"crowdstrike": {"configured": cs_ok or config.DEMO, "stored": d["n"] or 0, "newest": d["newest"], "fetched_at": d["fetched"],
                            "last_step": step, "last_sync": run, "reason": cs_reason},
            "splunk": {"configured": bool(cfg["url"]) or config.DEMO, "reason": None if cfg["url"] or config.DEMO else "Splunk is not connected (Integrations)"},
            "ndr": {"configured": bool(db.get_settings().get("seceon_webhook_token")) or (n["n"] or 0) > 0 or config.DEMO, "stored": n["n"] or 0,
                    "newest": n["newest"], "received_at": n["received"],
                    "reason": None if n["n"] else "No Seceon alert received yet: set up the webhook or upload an export (Integrations)"},
            "demo": config.DEMO}


@router.post("/api/alerts/fetch")
def alerts_fetch():
    """Pull CrowdStrike alerts now (no full sync) and say exactly what happened."""
    from . import detections, falcon
    if config.DEMO:
        return {"ok": True, "message": "Sample data mode: alerts are simulated, nothing to fetch"}
    if not falcon.is_configured():
        return {"ok": False, "message": "CrowdStrike is not connected: add the API client under Sync & settings"}
    days = int(db.get_settings().get("detections_days") or 30)
    try:
        msg = detections.fetch(falcon.get_client(), days)
        return {"ok": True, "message": msg}
    except Exception as e:  # noqa: BLE001
        text = str(e)
        if "403" in text or "denied" in text.lower():
            text += " — add the 'Alerts: Read' scope to the API client in Falcon (Support and resources → API clients and keys)"
        return {"ok": False, "message": text}
