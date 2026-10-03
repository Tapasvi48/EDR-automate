import base64
import json
import logging
import re
import time
import secrets
import threading
from contextlib import asynccontextmanager

import anyio

from fastapi import Body, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import asset360, commatrix, config, cs_posture, db, detections, satellite, seceon, splunk, falcon, feasibility, sensor_support, filetemplates, sod, inventory, legacy, niam, posture, queries, registry, sync, threats, passive, surface, alerts, intel, spotlight, subnets, vulns
from .exporter import xlsx_response
from .extra import router as extra_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    if config.DEMO:
        from . import demo
        with db.get_conn() as c:
            if demo.seed(c):
                c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('match_rev', ?)", (inventory.MATCH_REV,))
    with db.get_conn() as c:
        settings = db.get_settings(c)
        sync.compute_devices(c, settings)  # columns / matching rules may be new after an upgrade
        sync.detect_reinstalls(c, settings, emit_events=False)
        inventory.tag_duplicates(c)
        if settings.get("match_rev") != inventory.MATCH_REV:  # matching rules changed in this release
            inventory.refresh_matches(c)
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('match_rev', ?)", (inventory.MATCH_REV,))
    if not config.DEMO:
        sync.start_scheduler()
    yield


app = FastAPI(title="EDR Asset Dashboard", lifespan=lifespan)


# ------------------------------------------------------------------ API response cache
# Overview, dashboards, coverage and the big lists aggregate every host and inventory row; at 1 lakh rows that is seconds of
# SQL per page. Answers are kept until the data changes (db.GEN moves on every write), so a click on a page whose data has
# not changed is served at once. Hot pages are recomputed in the background after each change (see _warm_loop).
# Live answers (status, sync, Splunk / alert feeds, internet look-ups) and file downloads are never cached.
_NO_CACHE = re.compile(r"status|/sync|/export|download|/template|/connection|/falcon/|/settings|/alerts|/analysts|/splunk|/seceon"
                       r"|/intel|/job|/refresh|/asset/passive")
_CACHE, _HOT, _INFLIGHT = {}, {}, {}
_CACHE_TTL, _CACHE_MAX, _CACHE_BODY_MAX = 900, 400, 8 << 20


@app.middleware("http")
async def api_cache(request: Request, call_next):
    path = request.url.path
    if request.method != "GET" or not path.startswith("/api/") or _NO_CACHE.search(path):
        return await call_next(request)
    # pages that show a running scan job read it from memory: a job starting or ending is a different answer
    live = f"|{int(surface.JOB['running'])}{int(passive.JOB['running'])}"
    key = path + "?" + "&".join(sorted(request.url.query.split("&"))) + live
    gen, now = db.GEN[0], time.time()
    warm = request.headers.get("x-cache-warm") == "1"
    if not warm:
        _HOT[key] = (now, _HOT.get(key, (0, 0))[1] + 1)
    ev = _INFLIGHT.get(key)
    if ev and ev[0] == gen and not warm:  # the same answer is being computed (e.g. by the warmer): wait for it
        await anyio.to_thread.run_sync(lambda: ev[1].wait(120))
    hit = _CACHE.get(key)
    if hit and hit[0] == db.GEN[0] and now - hit[1] < _CACHE_TTL and not warm:
        return Response(hit[2], media_type="application/json", headers={"x-cache": "hit"})
    done = threading.Event()
    _INFLIGHT[key] = (gen, done)
    try:
        resp = await call_next(request)
        if resp.status_code != 200 or "json" not in (resp.headers.get("content-type") or ""):
            return resp
        body = b"".join([chunk async for chunk in resp.body_iterator])
        if len(body) <= _CACHE_BODY_MAX and gen == db.GEN[0]:  # data did not change while computing
            if len(_CACHE) >= _CACHE_MAX:
                for k in sorted(_CACHE, key=lambda k: _CACHE[k][1])[:_CACHE_MAX // 4]:
                    _CACHE.pop(k, None)
            _CACHE[key] = (gen, now, body)
        return Response(body, media_type="application/json", headers={"x-cache": "miss"})
    finally:
        done.set()
        if _INFLIGHT.get(key, (None, None))[1] is done:
            _INFLIGHT.pop(key, None)


def _warm_loop():
    """After the data changes (sync, upload, re-match), recompute the pages people looked at in the last two hours, so
    their next click is instant. Waits until the data has been quiet for a few seconds and no re-match / sync is running."""
    import asyncio
    warmed, seen, quiet_since = -1, db.GEN[0], time.time()  # -1: warm once after startup too
    hdrs = [(b"host", b"localhost"), (b"x-cache-warm", b"1")]
    if config.APP_USERNAME and config.APP_PASSWORD:
        hdrs.append((b"authorization", b"Basic " + base64.b64encode(f"{config.APP_USERNAME}:{config.APP_PASSWORD}".encode())))

    async def get(key):
        path, _, query = key.rpartition("|")[0].partition("?")
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET", "scheme": "http",
                 "path": path, "raw_path": path.encode(), "query_string": query.encode(), "headers": hdrs,
                 "client": ("127.0.0.1", 0), "server": ("127.0.0.1", 80), "root_path": ""}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(_):
            pass
        await app(scope, receive, send)

    while True:
        time.sleep(2)
        g = db.GEN[0]
        if g != seen:
            seen, quiet_since = g, time.time()
            continue
        if g == warmed or time.time() - quiet_since < 3 or inventory.REFRESH["running"] or sync.STATUS["running"]:
            continue
        cutoff = time.time() - 7200
        for k in [k for k, (t, _) in list(_HOT.items()) if t <= cutoff]:
            _HOT.pop(k, None)
        keys = sorted(_HOT, key=lambda k: -_HOT[k][1])[:40]  # most visited first (Overview, the shared /api/meta, ...)
        for k in keys:
            if db.GEN[0] != g:
                break
            try:
                asyncio.run(get(k))
            except Exception:  # noqa: BLE001 - warming is best effort
                logging.getLogger("cache").debug("warm %s failed", k, exc_info=True)
        if db.GEN[0] == g:
            warmed = g


for _k in ("/api/meta?", "/api/overview?"):  # every session opens these: warm right after a restart
    _HOT[_k + "|00"] = (time.time(), 1)
threading.Thread(target=_warm_loop, daemon=True, name="cache-warm").start()
# compress JSON and the UI bundle (the larger JS chunks shrink ~4x); small responses are sent as they are
from starlette.middleware.gzip import GZipMiddleware  # noqa: E402
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if config.APP_USERNAME and config.APP_PASSWORD:
        hdr = request.headers.get("authorization", "")
        ok = False
        if hdr.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
                ok = secrets.compare_digest(user, config.APP_USERNAME) and secrets.compare_digest(pw, config.APP_PASSWORD)
            except ValueError:
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="EDR Dashboard"'})
    return await call_next(request)


@app.exception_handler(ValueError)
async def value_error(_, exc):
    return JSONResponse({"detail": str(exc)}, status_code=400)


def _page(p):
    page = max(1, int(p.get("page") or 1))
    size = min(1000, max(1, int(p.get("size") or 50)))
    return page, size


def _params(request: Request):
    return dict(request.query_params)


# ------------------------------------------------------------------ meta / settings / sync
@app.get("/api/meta")
def meta():
    with db.get_conn() as c:
        def distinct(col, where="console_state<>'removed'"):
            return [r[0] for r in c.execute(f"SELECT DISTINCT {col} FROM hosts WHERE {where} AND {col}<>'' ORDER BY 1 COLLATE NOCASE")]
        return {
            "connected": falcon.is_configured(),
            "demo": config.DEMO,
            "inventory_fields": config.INVENTORY_FIELDS,
            "key_fields": inventory.KEY_FIELDS,
            "platforms": distinct("platform_name"),
            "os": distinct("os_version"),
            "product_types": distinct("product_type_desc"),
            "domains": distinct("machine_domain"),
            "sites": distinct("site_name"),
            "agent_versions": sorted(distinct("agent_version"), key=queries.version_key, reverse=True),
            "chassis": distinct("chassis_type_desc"),
            "lobs": db.rows(c, "SELECT id, name FROM lobs ORDER BY name COLLATE NOCASE"),
            "msps": db.rows(c, "SELECT id, name, lob_id FROM msps ORDER BY name COLLATE NOCASE"),
            "node_types": [r[0] for r in c.execute("""SELECT DISTINCT t FROM (
                SELECT NULLIF(node_type,'') t FROM inventory_current UNION SELECT NULLIF(product_type_desc,'') FROM hosts
                WHERE console_state='active') WHERE t IS NOT NULL ORDER BY 1 COLLATE NOCASE""")],
            "templates": db.rows(c, "SELECT id, name, key_field FROM templates ORDER BY name COLLATE NOCASE"),
            "settings": db.public_settings(c),
        }


CONNECTION_KEYS = {"falcon_client_id", "falcon_client_secret", "falcon_base_url", "falcon_member_cid"}


@app.get("/api/settings")
def get_settings():
    return db.public_settings()


@app.put("/api/settings")
def put_settings(values: dict = Body(...)):
    db.set_settings({k: v for k, v in values.items() if k not in CONNECTION_KEYS})
    with db.get_conn() as c:
        settings = db.get_settings(c)
        sync.detect_reinstalls(c, settings)
        sync.compute_devices(c, settings)
        inventory.refresh_soon(c, label="Applying the new settings")
    return db.public_settings()


# ------------------------------------------------------------------ CrowdStrike connection
def _connection_info():
    c = falcon.credentials()
    secret = c["client_secret"] or ""
    return {
        "configured": bool(c["client_id"] and secret),
        "source": c["source"],
        "client_id": c["client_id"] or "",
        "secret_set": bool(secret),
        "secret_hint": ("•" * 8 + secret[-4:]) if len(secret) > 8 else ("•" * len(secret)),
        "base_url": c["base_url"] or "us-1",
        "member_cid": c["member_cid"] or "",
        "clouds": falcon.CLOUDS,
    }


def _creds_from(data):
    saved = falcon.credentials()
    return (
        (data.get("client_id") or saved["client_id"] or "").strip(),
        (data.get("client_secret") or saved["client_secret"] or "").strip(),
        (data.get("base_url") or saved["base_url"] or "us-1").strip(),
        (data.get("member_cid") if data.get("member_cid") is not None else saved["member_cid"] or "").strip(),
    )


@app.get("/api/connection")
def get_connection():
    return _connection_info()


@app.post("/api/connection/test")
def test_connection(data: dict = Body(default={})):
    cid, secret, base, member = _creds_from(data)
    if not cid or not secret:
        raise ValueError("Enter the API client ID and secret")
    return falcon.test_connection(cid, secret, base, member)


# every CrowdStrike API feature the console uses: scope, what it feeds, last sync result and how much data it brought
FALCON_FEATURES = [
    ("hosts", "Hosts: Read", "Asset list, OS, connection / external IP, sensor version", "list", "SELECT COUNT(*) n, MAX(db_last_synced) at FROM hosts WHERE source='falcon'"),
    ("online", "Hosts: Read", "Online / offline status", "online", None),
    ("hidden", "Hosts: Read", "Hidden hosts (left out everywhere)", "hidden", "SELECT COUNT(*) n, NULL at FROM hosts WHERE console_state='hidden'"),
    ("nic", "Hosts: Read", "Connection-IP history (matching inventory rows to agents)", "nic", "SELECT COUNT(*) n, MAX(last_seen) at FROM ip_history WHERE kind='connection'"),
    ("detections", "Alerts: Read", "Recent detections (Asset 360, Top riskiest assets)", "detections", "SELECT COUNT(*) n, MAX(fetched_at) at FROM detections"),
    ("analysts", "Alerts: Read", "Analyst workload (who worked on which alert)", "detections",
     "SELECT COUNT(*) n, MAX(fetched_at) at FROM detections WHERE COALESCE(assigned_to,'')<>''"),
    ("spotlight", "Vulnerabilities: Read", "Spotlight vulnerabilities (Asset 360 → EDR & logging)", "posture", "SELECT COUNT(*) n, MAX(fetched_at) at FROM spotlight_vulns"),
    ("prevention", "Prevention policies: Read", "Prevention policy names", "posture", "SELECT COUNT(*) n, MAX(modified_at) at FROM prevention_policies"),
    ("sensors", "Sensor update policies: Read", "Sensor builds N / N-1 / N-2 and supported OS (EDR feasibility)", "sensors",
     "SELECT COUNT(*) n, MAX(fetched_at) at FROM sensor_builds"),
]
CHECK_FOR = {"hosts": "Hosts: list", "online": "Hosts: online state", "hidden": "Hosts: hidden hosts", "nic": "Hosts: NIC / IP history",
             "detections": "Alerts: recent detections", "analysts": "Alerts: analyst assignment (Analyst workload)",
             "spotlight": "Vulnerabilities: Spotlight", "prevention": "Prevention policies: read", "sensors": "Sensor update policies: builds (N / N-1 / N-2)"}


@app.get("/api/falcon/features")
def falcon_features():
    """Per feature: the scope it needs, what the last sync said for its step, and the data now in the console."""
    out = []
    with db.get_conn() as c:
        last_run = db.one(c, "SELECT id, started_at, status FROM sync_runs WHERE mode<>'sample' ORDER BY id DESC LIMIT 1")
        for key, scope, what, step, sql in FALCON_FEATURES:
            log = db.one(c, "SELECT level, message, ts FROM sync_log WHERE run_id=? AND step=? ORDER BY id DESC LIMIT 1",
                         (last_run["id"], step)) if last_run else None
            data = db.one(c, sql) if sql else None
            status = ("error" if log and log["level"] == "error" else "warning" if log and log["level"] in ("warn", "warning") else
                      "ok" if log else "not run")
            if key == "analysts" and data is not None and not data["n"]:
                status = "warning" if status == "ok" else status
            out.append({"key": key, "scope": scope, "feature": what, "status": status, "detail": log["message"] if log else None,
                        "at": log["ts"] if log else None, "count": data["n"] if data else None, "data_at": data["at"] if data else None,
                        "check": CHECK_FOR.get(key)})
    return {"features": out, "configured": falcon.is_configured(), "demo": config.DEMO, "last_run": last_run}


@app.post("/api/falcon/features/test")
def falcon_features_test():
    """Live check of every feature with the saved credentials (read-only calls)."""
    if config.DEMO:
        raise HTTPException(400, "Sample data mode: there is no CrowdStrike connection to test")
    cid, secret, base, member = _creds_from({})
    if not cid or not secret:
        raise HTTPException(400, "CrowdStrike is not connected: add the API client under Sync & settings")
    return falcon.test_connection(cid, secret, base, member)


@app.put("/api/connection")
def save_connection(data: dict = Body(...)):
    cid, secret, base, member = _creds_from(data)
    if not cid or not secret:
        raise ValueError("Enter the API client ID and secret")
    db.set_settings({"falcon_client_id": cid, "falcon_client_secret": secret, "falcon_base_url": base, "falcon_member_cid": member})
    started = False
    if data.get("sync_now"):
        started = _start_sync("first sync" if not _has_synced() else "manual")
    return {**_connection_info(), "sync_started": started}


@app.delete("/api/connection")
def delete_connection():
    db.set_settings({"falcon_client_id": "", "falcon_client_secret": "", "falcon_base_url": "", "falcon_member_cid": ""})
    return _connection_info()


def _has_synced():
    with db.get_conn() as c:
        return bool(c.execute("SELECT 1 FROM sync_runs WHERE status='ok' LIMIT 1").fetchone())


def _start_sync(trigger):
    if config.DEMO or sync.STATUS["running"] or not falcon.is_configured():
        return False
    threading.Thread(target=sync.run_sync, kwargs={"trigger": trigger}, daemon=True).start()
    return True


@app.post("/api/sync")
def trigger_sync():
    if config.DEMO:
        return {"ok": False, "message": "Sample data mode: syncing is off. Start without --demo to use your CrowdStrike tenant."}
    if not falcon.is_configured():
        return {"ok": False, "message": "Connect CrowdStrike first (Sync & settings → Connection)"}
    if sync.STATUS["running"]:
        return {"ok": False, "message": "A sync is already running"}
    _start_sync("manual")
    return {"ok": True, "message": "Sync started"}


@app.get("/api/sync/status")
def sync_status():
    with db.get_conn() as c:
        runs = db.rows(c, "SELECT * FROM sync_runs ORDER BY id DESC LIMIT 50")
        tail = db.rows(c, "SELECT ts, level, step, message FROM sync_log WHERE run_id=? ORDER BY id DESC LIMIT 12",
                       (sync.STATUS["run_id"],)) if sync.STATUS["run_id"] else []
    return {**sync.STATUS, "runs": runs, "log_tail": list(reversed(tail)), "configured": falcon.is_configured(), "demo": config.DEMO,
            "refresh": inventory.REFRESH,
            "interval_minutes": int(db.get_settings().get("sync_interval_minutes") or 0), "next_sync_at": sync.next_sync_at()}


@app.get("/api/sync/runs/{run_id}/log")
def sync_run_log(run_id: int):
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT ts, level, step, message FROM sync_log WHERE run_id=? ORDER BY id", (run_id,))}


@app.post("/api/admin/clear-falcon-data")
def clear_falcon_data():
    """Removes all synced Falcon data (e.g. after switching tenant). LOB inventories and settings are kept."""
    if sync.STATUS["running"]:
        raise ValueError("Wait for the running sync to finish")
    with db.get_conn() as c:
        for t in ("hosts", "ip_history", "host_events", "sync_runs", "sync_log", "daily_stats", "host_map", "agent_tags"):
            c.execute(f"DELETE FROM {t}")
        inventory.refresh_soon(c)
    return {"ok": True}


# ------------------------------------------------------------------ dashboard
@app.get("/api/dashboard")
def dashboard():
    with db.get_conn() as c:
        return queries.dashboard(c, db.get_settings(c))


@app.get("/api/overview")
def overview():
    with db.get_conn() as c:
        return queries.overview(c, db.get_settings(c))


# ------------------------------------------------------------------ hosts
def _host_query(c, p):
    settings = db.get_settings(c)
    if p.get("outdated") == "1" or p.get("sensor_level"):
        queries.prepare_outdated_temp(c)
    return queries.build_host_query(p, settings)


@app.get("/api/hosts")
def hosts(request: Request):
    p = _params(request)
    page, size = _page(p)
    with db.get_conn() as c:
        frm, where, params, order = _host_query(c, p)
        if _JOINED.search(where + " " + order):  # filter / sort on duplicate or inventory columns: the full join decides
            total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
            rows = db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {frm} {where} {order} LIMIT ? OFFSET ?",
                           params + [size, (page - 1) * size])
        else:
            # count and page on hosts alone (indexes), then join duplicates / inventory / LOB for the rows on this page only;
            # building those joins for 1 lakh agents to show 50 of them took seconds per click
            settings = db.get_settings(c)
            wp = params[queries.from_param_count(settings):]
            total = c.execute(f"SELECT COUNT(*) FROM hosts h {where}", wp).fetchone()[0]
            aids = [r[0] for r in c.execute(f"SELECT h.aid FROM hosts h {where} {order} LIMIT ? OFFSET ?", wp + [size, (page - 1) * size])]
            rows = []
            if aids:
                pfrm, pp = queries.page_from(c, aids, settings)
                rows = db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {pfrm} {order}", pp)
    return {"total": total, "page": page, "size": size, "rows": rows}


_JOINED = re.compile(r"\b(d|rc|inv|hm)\.|dup_count|inv_lobs|inv_msps|node_type")


@app.get("/api/hosts/export")
def hosts_export(request: Request):
    p = _params(request)
    with db.get_conn() as c:
        frm, where, params, order = _host_query(c, p)
        rows = db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {frm} {where} {order}", params)
    for r in rows:
        r["niam_text"] = "Yes" if r["niam_ne_ids"] else "No"
        r["exposed_text"] = "Yes" if r.get("internet_exposed") else "No"
    return xlsx_response([("Hosts", queries.HOST_EXPORT_COLUMNS, rows)], p.get("name") or "edr_hosts")


@app.get("/api/hosts/{aid}")
def host_detail(aid: str):
    with db.get_conn() as c:
        h = db.one(c, "SELECT * FROM hosts WHERE aid=?", (aid,))
        if not h:
            raise HTTPException(404, "Host not found")
        settings = db.get_settings(c)
        h["raw"] = db.get_raw(c, aid) or db.jloads(h["raw"], {})
        h["reinstall_of"] = db.jloads(h["reinstall_of"], [])
        ips = db.rows(c, "SELECT ip, kind, source, mac, first_seen, last_seen FROM ip_history WHERE aid=? ORDER BY last_seen DESC", (aid,))
        events = db.rows(c, "SELECT ts, event, details FROM host_events WHERE aid=? ORDER BY id DESC LIMIT 200", (aid,))
        for e in events:
            e["details"] = db.jloads(e["details"], {})
        same_ip = []
        excl = sync.exclusion_patterns(settings)
        if h["connection_ip"] and h["local_ip"] and not (sync.ip_excluded(h["connection_ip"], excl) or sync.ip_excluded(h["local_ip"], excl)):
            same_ip = db.rows(c, """SELECT aid, hostname, local_ip, connection_ip, console_state, online_state, first_seen, last_seen,
                                   platform_name FROM hosts WHERE connection_ip=? AND local_ip=? AND aid<>? ORDER BY last_seen DESC""",
                              (h["connection_ip"], h["local_ip"], aid))
        same_hn = db.rows(c, """SELECT aid, hostname, local_ip, console_state, online_state, first_seen, last_seen, platform_name
                               FROM hosts WHERE hostname_norm=? AND hostname_norm<>'' AND aid<>? ORDER BY last_seen DESC""",
                          (h["hostname_norm"], aid))
        # later AIDs that replaced this one
        replaced_by = [r for r in db.rows(c, "SELECT aid, hostname, local_ip, connection_ip, first_seen, reinstall_of FROM hosts WHERE is_reinstall=1 AND first_seen > ?",
                                          (h["first_seen"] or "",))
                       if aid in (r.pop("reinstall_of") or "")]
        inv = db.rows(c, """SELECT l.name lob, l.id lob_id, v.version_no, v.uploaded_at, v.filename, ic.* FROM inventory_current ic
                            JOIN lobs l ON l.id=ic.lob_id LEFT JOIN inventory_versions v ON v.id=l.current_version_id
                            WHERE ic.matched_aid=? AND ic.edr_state<>'Not Installed'""", (aid,))
        for r in inv:
            r["extra"] = db.jloads(r.get("extra"), {})
        niam = db.rows(c, """SELECT ne_id, host, ip, extra, first_seen_at, last_seen_at FROM niam_nodes
                             WHERE present=1 AND ip=? AND ip<>''""", (h["connection_ip"] or "",))
        for n in niam:
            n["extra"] = db.jloads(n["extra"], {})
        vulns, scans = [], []
        if h["connection_ip"]:  # CrowdStrike asset IP = connection IP
            vulns = db.rows(c, """SELECT f.id, l.name lob, f.severity, f.sev_rank, f.name, f.plugin_id, f.port, f.protocol, f.cve,
                f.exploit_ease, f.first_discovered, f.last_observed, f.status, f.fixed_at FROM vuln_findings f
                JOIN lobs l ON l.id=f.lob_id WHERE f.ip=? ORDER BY f.status='open' DESC, f.sev_rank DESC LIMIT 500""", (h["connection_ip"],))
            scans = db.rows(c, """SELECT l.name lob, sh.scanned_at FROM vuln_scan_hosts sh JOIN lobs l ON l.id=sh.lob_id
                WHERE sh.ip=? ORDER BY sh.scanned_at DESC""", (h["connection_ip"],))
    return {"host": h, "ip_history": ips, "events": events, "same_ip": same_ip, "same_hostname": same_hn,
            "replaced_by": replaced_by, "inventory": inv, "vulns": vulns, "scans": scans, "niam": niam}


@app.post("/api/hosts/{aid}/nic-refresh")
def host_nic_refresh(aid: str):
    hist = falcon.get_client().get_nic_history([aid])
    sync.store_nic_history(hist, [aid])
    return {"ok": True, "entries": len(hist.get(aid, []))}


# ------------------------------------------------------------------ search / duplicates / events
@app.get("/api/search/ip")
def search_ip(q: str = ""):
    with db.get_conn() as c:
        return queries.ip_search(c, q)


@app.get("/api/search/ip/export")
def search_ip_export(q: str = ""):
    with db.get_conn() as c:
        r = queries.ip_search(c, q)
    return xlsx_response([
        ("Current hosts", [("hostname", "Hostname"), ("aid", "Agent ID"), ("local_ip", "Local IP"), ("external_ip", "External IP"),
                           ("console_state", "Console State"), ("online_state", "Online"), ("platform_name", "Platform"),
                           ("os_version", "OS"), ("first_seen", "First Seen"), ("last_seen", "Last Seen")], r["current"]),
        ("IP history", [("ip", "IP"), ("kind", "Kind"), ("source", "Source"), ("mac", "MAC"), ("ip_first_seen", "IP First Seen"),
                        ("ip_last_seen", "IP Last Seen"), ("hostname", "Hostname"), ("aid", "Agent ID"),
                        ("current_ip", "Current IP"), ("console_state", "Console State"), ("last_seen", "Host Last Seen")], r["history"]),
        ("Inventory", [("lob", "LOB"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("live", "Live"),
                       ("edr_installed", "EDR Installed (claimed)"), ("edr_actual", "EDR Actual"), ("verification", "Verification")],
         r["inventory"]),
    ], "ip_search")


@app.get("/api/duplicates")
def duplicates(kind: str = "duplicate", q: str = "", include_removed: int = 0, page: int = 1, size: int = 100):
    with db.get_conn() as c:
        return queries.duplicate_groups(c, db.get_settings(c), kind, q, bool(include_removed), size, (page - 1) * size)


@app.get("/api/duplicates/members")
def duplicate_members(connection_ip: str, local_ip: str, include_removed: int = 0):
    with db.get_conn() as c:
        return {"rows": queries.duplicate_members(c, connection_ip, local_ip, bool(include_removed))}


@app.get("/api/duplicates/export")
def duplicates_export(kind: str = "duplicate", q: str = "", include_removed: int = 0):
    with db.get_conn() as c:
        g = queries.duplicate_groups(c, db.get_settings(c), kind, q, bool(include_removed), 100000, 0)
        members = []
        for grp in g["rows"]:
            for m in queries.duplicate_members(c, grp["connection_ip"], grp["local_ip"], bool(include_removed)):
                members.append({"group_size": grp["n"], **m})
    cols = [("connection_ip", "Connection IP"), ("local_ip", "Local IP"), ("group_size", "Group Size"), ("hostname", "Hostname"),
            ("aid", "Agent ID"), ("console_state", "Console State"), ("online_state", "Online"), ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"), ("platform_name", "Platform"), ("os_version", "OS"), ("agent_version", "Sensor"),
            ("serial_number", "Serial"), ("mac_address", "MAC")]
    name = "routing_conflicts" if kind == "routing" else "duplicate_agents"
    return xlsx_response([("Routing conflicts" if kind == "routing" else "Duplicate agents", cols, members)], name)


EVENT_COLS = [("ts", "Time (UTC)"), ("event", "Event"), ("hostname", "Hostname"), ("aid", "Agent ID"), ("local_ip", "IP"),
              ("details", "Details")]


def _events(c, p, limit=None, offset=0):
    w, params = [], []
    if p.get("event"):
        vals = p["event"].split("|")
        w.append(f"e.event IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("from"):
        w.append("e.ts >= ?")
        params.append(p["from"])
    if p.get("to"):
        w.append("e.ts < date(?, '+1 day')")
        params.append(p["to"])
    if p.get("q"):
        w.append("(h.hostname LIKE ? OR h.connection_ip LIKE ? OR e.aid = ?)")
        params += [f"%{p['q']}%", p["q"] + "%", p["q"]]
    where = ("WHERE " + " AND ".join(w)) if w else ""
    total = c.execute(f"SELECT COUNT(*) FROM host_events e LEFT JOIN hosts h ON h.aid=e.aid {where}", params).fetchone()[0]
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"""SELECT e.ts, e.event, e.details, e.aid, h.hostname, h.local_ip FROM host_events e
                          LEFT JOIN hosts h ON h.aid=e.aid {where} ORDER BY e.id DESC {lim}""", params)
    return total, rows


@app.get("/api/events")
def events(request: Request):
    p = _params(request)
    page, size = _page(p)
    with db.get_conn() as c:
        total, rows = _events(c, p, size, (page - 1) * size)
    for r in rows:
        r["details"] = db.jloads(r["details"], {})
    return {"total": total, "rows": rows, "page": page, "size": size}


@app.get("/api/events/export")
def events_export(request: Request):
    with db.get_conn() as c:
        _, rows = _events(c, _params(request))
    return xlsx_response([("Events", EVENT_COLS, rows)], "host_events")


@app.get("/api/series")
def series(kind: str = "installs", start: str = "", end: str = ""):
    """Daily counts for a date range: installs | offline | removed"""
    if not start or not end:
        raise ValueError("start and end are required (YYYY-MM-DD)")
    with db.get_conn() as c:
        if kind == "installs":
            rows = db.rows(c, """SELECT substr(first_seen,1,10) day, COUNT(*) n, SUM(is_reinstall) reinstalls,
                SUM(console_state='active') still_active FROM hosts
                WHERE first_seen >= ? AND first_seen < date(?, '+1 day') GROUP BY 1 ORDER BY 1""", (start, end))
        elif kind == "offline":
            rows = db.rows(c, """SELECT substr(last_seen,1,10) day, COUNT(*) n FROM hosts
                WHERE console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen >= ? AND last_seen < date(?, '+1 day')
                GROUP BY 1 ORDER BY 1""", (start, end))
        elif kind == "removed":
            rows = db.rows(c, """SELECT substr(removed_at,1,10) day, COUNT(*) n, SUM(removal_type='auto_inactive') auto,
                SUM(removal_type='deleted') deleted, SUM(removal_type='hidden') hidden FROM hosts
                WHERE console_state<>'active' AND removed_at >= ? AND removed_at < date(?, '+1 day') GROUP BY 1 ORDER BY 1""", (start, end))
        else:
            raise ValueError("unknown series")
    return {"rows": rows}


# ------------------------------------------------------------------ LOBs
@app.get("/api/lobs")
def lobs():
    with db.get_conn() as c:
        return {"rows": queries.lob_summaries(c)}


@app.post("/api/lobs")
def create_lob(data: dict = Body(...)):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Name is required")
    with db.get_conn() as c:
        if db.one(c, "SELECT id FROM lobs WHERE name=? COLLATE NOCASE", (name,)):
            raise ValueError("A LOB with this name already exists")
        tid = data.get("default_template_id") or db.standard_template_id(c)
        lid = c.execute("INSERT INTO lobs(name, description, owner, default_template_id, created_at) VALUES (?,?,?,?,?)",
                        (name, data.get("description", ""), data.get("owner", ""), tid, db.now_iso())).lastrowid
    return {"id": lid}


@app.put("/api/lobs/{lob_id}")
def update_lob(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        c.execute("UPDATE lobs SET name=COALESCE(?, name), description=COALESCE(?, description), owner=COALESCE(?, owner), "
                  "default_template_id=? WHERE id=?",
                  (data.get("name"), data.get("description"), data.get("owner"), data.get("default_template_id"), lob_id))
    return {"ok": True}


@app.delete("/api/lobs/{lob_id}")
def delete_lob(lob_id: int):
    with db.get_conn() as c:
        vids = [r[0] for r in c.execute("SELECT id FROM inventory_versions WHERE lob_id=?", (lob_id,))]
        c.executemany("DELETE FROM inventory_rows WHERE version_id=?", [(v,) for v in vids])
        for t in ("inventory_changes", "inventory_current", "inventory_versions", "msps", "agent_tags", "lob_types",
                  "vuln_findings", "vuln_scans", "vuln_scan_hosts", "vuln_assets", "asset_risk", "msp_daily"):
            c.execute(f"DELETE FROM {t} WHERE lob_id=?", (lob_id,))
        c.execute("DELETE FROM lobs WHERE id=?", (lob_id,))
        inventory.refresh_soon(c)  # full re-join after LOB / MSP / tag changes
    return {"ok": True}


@app.get("/api/lobs/{lob_id}")
def lob_detail(lob_id: int):
    with db.get_conn() as c:
        lob = db.one(c, "SELECT * FROM lobs WHERE id=?", (lob_id,))
        if not lob:
            raise HTTPException(404, "LOB not found")
        settings = db.get_settings(c)
        summary = next((s for s in queries.lob_summaries(c, settings) if s["id"] == lob_id), {})
        msps = queries.msp_summaries(c, settings, lob_id)

        def dist(col):
            return db.rows(c, f"SELECT COALESCE(NULLIF({col},''),'(blank)') label, COUNT(*) n FROM inventory_current WHERE lob_id=? GROUP BY 1 ORDER BY n DESC", (lob_id,))
        facets = {k: dist(k) for k in ("coverage_status", "verification", "edr_actual", "change_tag", "live", "edr_feasible",
                                       "edr_installed", "node_type", "domain", "os", "match_method")}
        node_types = db.rows(c, """SELECT COALESCE(NULLIF(node_type,''),'(blank)') label, COUNT(*) nodes, SUM(applicable=1) applicable,
            SUM(applicable=1 AND edr_state IN ('Online','Offline')) installed, SUM(applicable=1 AND edr_state='Offline') offline,
            SUM(applicable=1 AND edr_state NOT IN ('Online','Offline')) pending
            FROM inventory_current WHERE lob_id=? GROUP BY 1 ORDER BY nodes DESC""", (lob_id,))
        current = db.one(c, "SELECT * FROM inventory_versions WHERE id=?", (lob["current_version_id"],)) if lob["current_version_id"] else None
        d = db.one(c, """SELECT COUNT(DISTINCT CASE WHEN ic.dup_ip>1 THEN ic.ip END) dup_ips,
            COUNT(DISTINCT CASE WHEN EXISTS (SELECT 1 FROM inventory_current x WHERE x.ip=ic.ip AND x.lob_id<>ic.lob_id) THEN ic.ip END) cross_lob_ips
            FROM inventory_current ic WHERE ic.lob_id=? AND COALESCE(ic.ip,'')<>''""", (lob_id,))
        summary = {**summary, "dup_ips": d["dup_ips"] or 0, "cross_lob_ips": d["cross_lob_ips"] or 0,
                   "dup_rows": c.execute("SELECT COUNT(*) FROM inventory_current WHERE lob_id=? AND file_dups>0", (lob_id,)).fetchone()[0]}
        types = _lob_types(c, lob_id)
    return {"lob": lob, "summary": summary, "facets": facets, "current_version": current, "msps": msps, "node_types": node_types,
            "types": types}


def _lob_types(c, lob_id):
    return db.rows(c, """SELECT t.id, t.name, t.description, t.created_at, v.version_no current_version, v.uploaded_at, v.uploaded_by,
        v.filename, (SELECT COUNT(*) FROM inventory_current ic WHERE ic.lob_id=t.lob_id AND ic.type_id=t.id) nodes,
        (SELECT COUNT(*) FROM inventory_versions x WHERE x.type_id=t.id) versions
        FROM lob_types t LEFT JOIN inventory_versions v ON v.id=t.current_version_id WHERE t.lob_id=? ORDER BY t.name""", (lob_id,))


@app.get("/api/lobs/{lob_id}/types")
def lob_types(lob_id: int):
    with db.get_conn() as c:
        return {"rows": _lob_types(c, lob_id)}


@app.post("/api/lobs/{lob_id}/types")
def create_lob_type(lob_id: int, data: dict = Body(...)):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Type name is required")
    with db.get_conn() as c:
        if not db.one(c, "SELECT id FROM lobs WHERE id=?", (lob_id,)):
            raise HTTPException(404, "LOB not found")
        if db.one(c, "SELECT id FROM lob_types WHERE lob_id=? AND name=? COLLATE NOCASE", (lob_id, name)):
            raise ValueError(f"Type '{name}' already exists in this LOB")
        tid = c.execute("INSERT INTO lob_types(lob_id, name, description, created_at) VALUES (?,?,?,?)",
                        (lob_id, name, data.get("description", ""), db.now_iso())).lastrowid
    return {"id": tid, "name": name}


@app.put("/api/types/{type_id}")
def update_lob_type(type_id: int, data: dict = Body(...)):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Type name is required")
    with db.get_conn() as c:
        t = db.one(c, "SELECT * FROM lob_types WHERE id=?", (type_id,))
        if not t:
            raise HTTPException(404, "Type not found")
        c.execute("UPDATE lob_types SET name=?, description=? WHERE id=?", (name, data.get("description", ""), type_id))
        # the type name is the node type of its rows
        c.execute("UPDATE inventory_current SET node_type=? WHERE type_id=?", (name, type_id))
    return {"ok": True}


@app.delete("/api/types/{type_id}")
def delete_lob_type(type_id: int):
    """Deletes the type with its whole version history and its rows in the current inventory."""
    with db.get_conn() as c:
        t = db.one(c, "SELECT * FROM lob_types WHERE id=?", (type_id,))
        if not t:
            raise HTTPException(404, "Type not found")
        vids = [r[0] for r in c.execute("SELECT id FROM inventory_versions WHERE type_id=?", (type_id,))]
        for v in vids:
            c.execute("DELETE FROM inventory_rows WHERE version_id=?", (v,))
            c.execute("DELETE FROM inventory_changes WHERE version_id=?", (v,))
        c.execute("DELETE FROM inventory_versions WHERE type_id=?", (type_id,))
        c.execute("DELETE FROM inventory_current WHERE type_id=?", (type_id,))
        c.execute("DELETE FROM lob_types WHERE id=?", (type_id,))
        inventory.tag_duplicates(c, t["lob_id"])
        inventory.refresh_soon(c)  # full re-join after LOB / MSP / tag changes
    return {"ok": True}


# ------------------------------------------------------------------ MSPs
@app.get("/api/lobs/{lob_id}/msps")
def lob_msps(lob_id: int):
    with db.get_conn() as c:
        return {"rows": queries.msp_summaries(c, db.get_settings(c), lob_id)}


@app.post("/api/lobs/{lob_id}/msps")
def create_msp(lob_id: int, data: dict = Body(...)):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("MSP name is required")
    with db.get_conn() as c:
        if db.one(c, "SELECT id FROM msps WHERE lob_id=? AND name=? COLLATE NOCASE", (lob_id, name)):
            raise ValueError("This LOB already has an MSP with that name")
        mid = c.execute("INSERT INTO msps(lob_id, name, description, contact, created_at) VALUES (?,?,?,?,?)",
                        (lob_id, name, data.get("description", ""), data.get("contact", ""), db.now_iso())).lastrowid
    return {"id": mid}


@app.put("/api/msps/{msp_id}")
def update_msp(msp_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        m = db.one(c, "SELECT * FROM msps WHERE id=?", (msp_id,))
        if not m:
            raise HTTPException(404)
        name = (data.get("name") or m["name"]).strip()
        c.execute("UPDATE msps SET name=?, description=?, contact=? WHERE id=?",
                  (name, data.get("description", m["description"]), data.get("contact", m["contact"]), msp_id))
        # inventory rows carry the MSP name; keep them in step with a rename
        c.execute("UPDATE inventory_current SET msp=? WHERE msp_id=?", (name, msp_id))
    return {"ok": True}


@app.delete("/api/msps/{msp_id}")
def delete_msp(msp_id: int):
    with db.get_conn() as c:
        n = c.execute("SELECT COUNT(*) FROM inventory_current WHERE msp_id=?", (msp_id,)).fetchone()[0]
        if n:
            raise ValueError(f"{n} inventory nodes still belong to this MSP. Upload an inventory without them first.")
        c.execute("DELETE FROM agent_tags WHERE msp_id=?", (msp_id,))
        c.execute("DELETE FROM msps WHERE id=?", (msp_id,))
        inventory.refresh_soon(c)  # full re-join after LOB / MSP / tag changes
    return {"ok": True}


@app.get("/api/lobs/{lob_id}/cross-msp-duplicates")
def lob_cross_msp_dups(lob_id: int):
    with db.get_conn() as c:
        return {"rows": queries.cross_msp_duplicates(c, lob_id)}


# ------------------------------------------------------------------ agent tags (AID + MSP sheet)
def _tag_input(c, lob_id, data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return parsed, inventory.tag_rows(c, lob_id, parsed, data.get("id_col"), data.get("msp_col"), data.get("msp_id"))


@app.post("/api/lobs/{lob_id}/tags/preview")
def tags_preview(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        _, (rows, summary) = _tag_input(c, lob_id, data)
    return {**summary, "rows": rows[:500]}


@app.post("/api/lobs/{lob_id}/tags/commit")
def tags_commit(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        parsed, (rows, summary) = _tag_input(c, lob_id, data)
        scope = data.get("replace")  # None | 'lob' | 'msp'
        replace_scope = "lob" if scope == "lob" else (data.get("msp_id") if scope == "msp" and data.get("msp_id") else None)
        n = inventory.commit_tags(c, lob_id, rows, parsed["filename"], replace_scope)
        inventory.refresh_soon(c)  # tags change LOB / MSP attribution everywhere
    return {**summary, "tagged": n}


@app.get("/api/lobs/{lob_id}/tags")
def tags_list(lob_id: int, request: Request):
    p = _params(request)
    page, size = _page(p)
    w, params = ["t.lob_id=?"], [lob_id]
    if p.get("msp"):
        w.append("t.msp_id IS NULL" if p["msp"] == "none" else "t.msp_id=?")
        params += [] if p["msp"] == "none" else [int(p["msp"])]
    if p.get("q"):
        w.append("(h.hostname LIKE ? OR h.connection_ip LIKE ? OR t.aid=?)")
        params += [f"%{p['q']}%", p["q"] + "%", p["q"].lower()]
    sql = f"""FROM agent_tags t LEFT JOIN hosts h ON h.aid=t.aid LEFT JOIN msps m ON m.id=t.msp_id WHERE {' AND '.join(w)}"""
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) {sql}", params).fetchone()[0]
        rows = db.rows(c, f"""SELECT t.aid, t.msp_id, COALESCE(m.name,'Unassigned') msp, t.source, t.tagged_at, h.hostname, h.local_ip,
            h.console_state, h.online_state, h.last_seen, h.os_version,
            EXISTS (SELECT 1 FROM inventory_current ic WHERE ic.lob_id=t.lob_id AND ic.matched_aid=t.aid AND ic.edr_state<>'Not Installed') in_inventory
            {sql} ORDER BY h.hostname COLLATE NOCASE LIMIT ? OFFSET ?""", params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@app.post("/api/lobs/{lob_id}/tags/remove")
def tags_remove(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        if data.get("all"):
            if data.get("msp_id"):
                c.execute("DELETE FROM agent_tags WHERE lob_id=? AND msp_id=?", (lob_id, data["msp_id"]))
            else:
                c.execute("DELETE FROM agent_tags WHERE lob_id=?", (lob_id,))
        else:
            c.executemany("DELETE FROM agent_tags WHERE lob_id=? AND aid=?", [(lob_id, a) for a in data.get("aids", [])])
        inventory.refresh_soon(c)  # full re-join after LOB / MSP / tag changes
    return {"ok": True}


INV_BASE_COLS = [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("domain", "Domain"),
                 ("live", "Live/Non Live"), ("os", "OS"), ("edr_feasible", "EDR Feasible"),
                 ("edr_installed", "EDR Installed (Inventory)"), ("remarks", "Remarks"), ("niam_integrated", "NIAM Integrated (Inventory)"),
                 ("ne_id", "NE ID (Inventory)")]
INV_STATUS_COLS = [("coverage_status", "EDR Status"), ("exposed_text", "Internet Exposed"), ("exposure_text", "Exposure Evidence"), ("os_resolved", "OS (resolved)"), ("os_source", "OS Source"),
                   ("feasible", "EDR Feasible (decided)"), ("feasible_reason", "Feasibility Reason"), ("niam_text", "NIAM Integrated (effective)"), ("niam_ne_ids", "NE ID (effective)"), ("niam_src_text", "NIAM Source"), ("last_scan", "Last Vulnerability Scan"), ("change_tag", "Change Tag"), ("first_version_no", "First Seen in Version"),
                   ("last_changed_version_no", "Last Changed in Version"), ("edr_actual", "EDR Actual Status"),
                   ("verification", "Verification"), ("match_method", "Match Method"), ("cs_hostname", "Falcon Hostname"),
                   ("cs_last_seen", "Falcon Last Seen"), ("cs_agent_version", "Sensor Version"), ("cs_os", "Falcon OS"),
                   ("matched_aid", "Matched Agent ID"), ("match_count", "Active AIDs Matched"),
                   ("file_dups", "Duplicate Rows in File"), ("dup_ip", "Rows Sharing IP"), ("dup_name", "Rows Sharing Node Name")]
INV_SORTS = {"ip": "ic.ip", "node_name": "ic.node_name COLLATE NOCASE", "node_type": "ic.node_type", "domain": "ic.domain",
             "live": "ic.live", "os": "ic.os", "edr_feasible": "ic.edr_feasible", "edr_installed": "ic.edr_installed",
             "verification": "ic.verification", "edr_actual": "ic.edr_actual", "change_tag": "ic.change_tag",
             "cs_last_seen": "ic.cs_last_seen", "lob": "l.name", "remarks": "ic.remarks", "msp": "ic.msp COLLATE NOCASE",
             "coverage_status": "ic.coverage_status", "os_resolved": "ic.os_resolved COLLATE NOCASE", "feasible": "ic.feasible",
             "dup": "(ic.file_dups>0) + (ic.dup_ip>1) + (ic.dup_name>1)"}


def _inventory_query(p, lob_id):
    w, params = [], []
    version_id = p.get("version_id")
    if version_id:  # historical snapshot
        frm = "inventory_rows ic JOIN inventory_versions v ON v.id=ic.version_id JOIN lobs l ON l.id=v.lob_id"
        w.append("ic.version_id=?")
        params.append(int(version_id))
        cols = "l.name lob, ic.*"
    else:
        frm = "inventory_current ic JOIN lobs l ON l.id=ic.lob_id"
        cols = """l.name lob, ic.*,
            (SELECT GROUP_CONCAT(n.ne_id, ', ') FROM niam_nodes n WHERE n.present=1 AND n.ip=ic.ip AND COALESCE(ic.ip,'')<>'') niam_dump_ne_ids,
            CASE WHEN """ + queries.NIAM_EFF + """ THEN 'Yes' ELSE 'No' END niam_eff,
            CASE WHEN COALESCE(ic.niam_integrated,'')<>'' THEN 'inventory' ELSE 'dump' END niam_src,
            (SELECT MAX(s.scanned_at) FROM vuln_scan_hosts s WHERE s.lob_id=ic.lob_id AND s.ip=ic.ip) last_scan,
            (SELECT r.exposed FROM asset_registry r WHERE r.ip=ic.ip AND COALESCE(ic.ip,'')<>'') internet_exposed,
            (SELECT r.exposure FROM asset_registry r WHERE r.ip=ic.ip AND COALESCE(ic.ip,'')<>'' AND r.exposed=1) exposure_why"""  # msp name is on the row
        if lob_id:
            w.append("ic.lob_id=?")
            params.append(lob_id)
    q = (p.get("q") or "").strip()
    if q:
        import re as _re
        terms = [t for t in _re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            ph = ",".join("?" * len(terms))
            w.append(f"(ic.ip IN ({ph}) OR LOWER(ic.node_name) IN ({ph}))")
            params += [db.canon_ip(t) for t in terms] + [t.lower() for t in terms]
        elif db.is_range_query(q) and ("/" in q or ":" in q):
            w.append("ip_in(ic.ip, ?)")
            params.append(q)
        elif db.is_ip(q):  # exact IP (any IPv4 / IPv6 spelling)
            w.append("ic.ip = ?")
            params.append(db.canon_ip(q))
        else:
            like = f"%{q}%"
            w.append("(ic.ip LIKE ? OR ic.node_name LIKE ? OR ic.remarks LIKE ? OR ic.extra LIKE ?"
                     + ("" if version_id else " OR ic.cs_hostname LIKE ?") + ")")
            params += [q + "%", like, like, like] + ([] if version_id else [like])
    filt = ["node_type", "domain", "live", "os", "edr_feasible", "edr_installed"]
    if not version_id and p.get("exposed") in ("0", "1"):
        w.append(("" if p["exposed"] == "1" else "NOT ") + "EXISTS (SELECT 1 FROM asset_registry r WHERE r.ip=ic.ip AND r.exposed=1)")
    if not version_id:
        filt += ["verification", "edr_actual", "change_tag", "match_method", "coverage_status", "edr_state", "feasible", "os_source"]
        if p.get("os_resolved"):
            w.append("ic.os_resolved=?")
            params.append(p["os_resolved"])
        if p.get("type"):
            if p["type"] == "main":
                w.append("ic.type_id IS NULL")
            else:
                w.append("ic.type_id=?")
                params.append(int(p["type"]))
        if p.get("msp"):
            if p["msp"] == "none":
                w.append("ic.msp_id IS NULL")
            else:
                w.append("ic.msp_id=?")
                params.append(int(p["msp"]))
        niam_x = queries.NIAM_EFF  # inventory column first, NIAM dump when it is blank
        scan_x = "EXISTS (SELECT 1 FROM vuln_scan_hosts s WHERE s.lob_id=ic.lob_id AND s.ip=ic.ip)"
        if p.get("niam") in ("0", "1"):
            w.append(niam_x if p["niam"] == "1" else f"NOT {niam_x}")
        if p.get("scanned") in ("0", "1"):
            w.append(scan_x if p["scanned"] == "1" else f"NOT {scan_x} AND COALESCE(ic.live,'')<>'Non Live'")
        gap = p.get("gap")
        if gap == "edr":
            w.append("ic.applicable=1 AND ic.edr_state NOT IN ('Online','Offline')")
        elif gap == "niam":
            w.append(f"NOT {niam_x}")
        elif gap == "scan":
            w.append(f"NOT {scan_x} AND COALESCE(ic.live,'')<>'Non Live'")
        elif gap == "any":
            w.append(f"""((ic.applicable=1 AND ic.edr_state NOT IN ('Online','Offline')) OR NOT {niam_x}
                         OR (NOT {scan_x} AND COALESCE(ic.live,'')<>'Non Live'))""")
        if p.get("pending") == "1":
            w.append("ic.applicable=1 AND ic.edr_state IN ('Not Installed','Hidden','Removed')")
        if p.get("installed") == "1":
            w.append("ic.applicable=1 AND ic.edr_state IN ('Online','Offline')")
        if p.get("installed_na") == "1":
            w.append("ic.applicable=0 AND ic.edr_state IN ('Online','Offline')")
        if p.get("claimed_missing") == "1":
            w.append("ic.edr_installed='Yes' AND ic.applicable=1 AND ic.edr_state NOT IN ('Online','Offline')")
        if p.get("marked_no") == "1":
            w.append("ic.edr_installed='No' AND ic.edr_state IN ('Online','Offline')")
        dup = p.get("dup")
        if dup == "any":
            w.append("(ic.file_dups>0 OR ic.dup_ip>1 OR ic.dup_name>1)")
        elif dup == "ip":
            w.append("ic.dup_ip>1")
        elif dup == "name":
            w.append("ic.dup_name>1")
        elif dup == "cross_lob":
            w.append("""COALESCE(ic.ip,'')<>'' AND EXISTS (SELECT 1 FROM inventory_current x WHERE x.ip=ic.ip AND x.lob_id<>ic.lob_id)""")
        if p.get("cross_msp_dup") == "1" or dup == "cross_msp":
            w.append("""EXISTS (SELECT 1 FROM inventory_current x WHERE x.lob_id=ic.lob_id AND x.ip=ic.ip AND COALESCE(x.ip,'')<>''
                        AND COALESCE(x.msp_id,0)<>COALESCE(ic.msp_id,0))""")
    for f in filt:
        v = p.get(f)
        if v is not None and v != "":
            vals = v.split("|")
            conds = []
            for x in vals:
                if x == "(blank)":
                    conds.append(f"COALESCE(ic.{f},'')=''")
                else:
                    conds.append(f"ic.{f}=?")
                    params.append(x)
            w.append("(" + " OR ".join(conds) + ")")
    if p.get("lob") and not lob_id:
        w.append("l.id=?")
        params.append(int(p["lob"]))
    if p.get("dup") == "file":
        w.append("ic.file_dups>0")
    if p.get("applicable") in ("0", "1") or p.get("in_scope") == "1":
        if version_id:  # snapshots keep only the inventory sheet's own feasibility column
            ok = "COALESCE(ic.edr_feasible,'')<>'No'"
            w.append(ok if p.get("applicable") != "0" else f"NOT ({ok})")
        else:
            w.append("ic.applicable=?")
            params.append(0 if p.get("applicable") == "0" else 1)
    if p.get("mismatch") == "1" and not version_id:
        w.append("ic.verification IN ('Claimed - Not Found','Claimed - Removed from Console','Installed - Marked No','Installed - Marked Not Feasible')")
    # offline split: the agent is in the console, it left the console, or it is only in the old EDR upload
    ok = p.get("offline_kind")
    if ok in ("console", "removed", "import"):
        w.append("ic.applicable=1 AND ic.edr_state='Offline'")
        if ok == "console":
            w.append("ic.edr_actual IN ('Offline','Inactive')")
        else:
            w.append("ic.edr_actual IN ('Removed','Hidden')")
            w.append(("EXISTS" if ok == "import" else "NOT EXISTS")
                     + " (SELECT 1 FROM hosts hx WHERE hx.aid=ic.matched_aid AND hx.removal_type='imported')")
    sort = INV_SORTS.get(p.get("sort") or "", "ic.rowid")
    if version_id and sort.startswith(("(ic.file_dups", "ic.verification", "ic.edr_actual", "ic.change_tag", "ic.cs_")):
        sort = "ic.rowid"
    direction = "DESC" if (p.get("dir") or "asc").lower() == "desc" else "ASC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return cols, frm, where, params, f"ORDER BY {sort} {direction}"


@app.get("/api/inventory/facets")
def inventory_facets(lob: int = 0, msp: str = ""):
    """Value counts for the inventory filter dropdowns (current inventory, one LOB or all)."""
    w, params = [], []
    if lob:
        w.append("lob_id=?")
        params.append(lob)
    if msp:
        w.append("msp_id IS NULL" if msp == "none" else "msp_id=?")
        params += [] if msp == "none" else [int(msp)]
    where = ("WHERE " + " AND ".join(w)) if w else ""
    with db.get_conn() as c:
        def dist(col):
            return db.rows(c, f"SELECT COALESCE(NULLIF({col},''),'(blank)') label, COUNT(*) n FROM inventory_current {where} "
                              "GROUP BY 1 ORDER BY n DESC", params)
        out = {k: dist(k) for k in ("coverage_status", "live", "edr_feasible", "edr_installed", "node_type", "domain", "os",
                                    "os_resolved", "feasible", "os_source")}
        d = db.one(c, f"""SELECT COUNT(*) total, SUM(file_dups>0 OR dup_ip>1 OR dup_name>1) any_dup, SUM(file_dups>0) file_dup,
                          SUM(dup_ip>1) ip_dup, SUM(dup_name>1) name_dup FROM inventory_current {where}""", params)
    out["dup"] = {k: d[k] or 0 for k in ("any_dup", "file_dup", "ip_dup", "name_dup")}
    out["total"] = d["total"]
    return out


@app.get("/api/lobs/{lob_id}/inventory")
def lob_inventory(lob_id: int, request: Request):
    p = _params(request)
    page, size = _page(p)
    with db.get_conn() as c:
        cols, frm, where, params, order = _inventory_query(p, lob_id)
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {cols} FROM {frm} {where} {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    for r in rows:
        r["extra"] = db.jloads(r.get("extra"), {})
        r["exposure_why"] = [e.get("text") for e in db.jloads(r.get("exposure_why"), []) or []]
        r["niam_ne_ids"] = r.get("ne_id") or r.get("niam_dump_ne_ids")
    return {"total": total, "rows": rows, "page": page, "size": size}


@app.get("/api/lobs/{lob_id}/inventory/export")
def lob_inventory_export(lob_id: int, request: Request):
    p = _params(request)
    with db.get_conn() as c:
        cols, frm, where, params, order = _inventory_query(p, lob_id)
        rows = db.rows(c, f"SELECT {cols} FROM {frm} {where} {order}", params)
        name = "all_lobs" if not lob_id else (db.one(c, "SELECT name FROM lobs WHERE id=?", (lob_id,)) or {}).get("name", "lob")
    extra_keys = []
    for r in rows:
        ex = db.jloads(r.get("extra"), {})
        for k in ex:
            if k not in extra_keys:
                extra_keys.append(k)
            r["x::" + k] = ex[k]
        r["niam_text"] = r.get("niam_eff") or ("Yes" if r.get("niam_ne_ids") else "No")
        r["niam_ne_ids"] = r.get("ne_id") or r.get("niam_dump_ne_ids") or r.get("niam_ne_ids")
        r["niam_src_text"] = {"inventory": "Inventory column", "dump": "NIAM dump (IP match)"}.get(r.get("niam_src"), "")
        r["exposed_text"] = "Yes" if r.get("internet_exposed") else "No"
        r["exposure_text"] = "; ".join(e.get("text", "") for e in db.jloads(r.get("exposure_why"), []) or [])
    columns = INV_BASE_COLS + ([] if p.get("version_id") else INV_STATUS_COLS) + [("x::" + k, k) for k in extra_keys]
    return xlsx_response([("Inventory", columns, rows)], f"inventory_{name}".replace(" ", "_"))


# ------------------------------------------------------------------ edit inventory values in place
# The inventory's own claims can be corrected without re-uploading: in the table (one cell) or for one column in Excel
# (download, change, upload). Edits apply to the current version and show in the item's history; the next inventory
# upload for that LOB replaces them with whatever the new file says.
EDITABLE = {"edr_installed": ("EDR Installed (Inventory)", ("Yes", "No", "")), "live": ("Live/Non Live", ("Live", "Non Live", "")),
            "edr_feasible": ("EDR Feasible (Inventory)", ("Yes", "No", "")), "remarks": ("Remarks", None)}


def _edit_value(field, value):
    v = str(value if value is not None else "").strip()
    if field in ("edr_installed", "edr_feasible"):
        v = inventory.norm_yes_no(v)
    elif field == "live":
        v = inventory.norm_live(v)
    allowed = EDITABLE[field][1]
    if allowed is not None and v not in allowed:
        raise ValueError(f"{EDITABLE[field][0]} must be one of: {', '.join(x or '(blank)' for x in allowed)}")
    return v


def _apply_edits(c, edits):
    """edits: [(lob_id, item_key, field, new value)] -> number changed. Logged as 'edited' in the item history."""
    changed, lobs = 0, set()
    for lob_id, key, field, val in edits:
        cur = db.one(c, f"SELECT {field} v FROM inventory_current WHERE lob_id=? AND item_key=?", (lob_id, key))
        if not cur or (cur["v"] or "") == val:
            continue
        c.execute(f"UPDATE inventory_current SET {field}=? WHERE lob_id=? AND item_key=?", (val, lob_id, key))
        ver = db.one(c, "SELECT current_version_id v FROM lobs WHERE id=?", (lob_id,))
        c.execute("""INSERT INTO inventory_changes(lob_id, version_id, item_key, change_type, field, old_value, new_value)
                     VALUES (?,?,?,?,?,?,?)""", (lob_id, (ver or {}).get("v") or 0, key, "edited", field, cur["v"] or "", val))
        changed += 1
        lobs.add(lob_id)
    for lob_id in lobs:  # claims feed the claim check; Live / feasibility feed nothing heavier
        inventory.refresh_soon(c, lob_id)
    return changed


@app.patch("/api/lobs/{lob_id}/inventory/{item_key}")
def inventory_edit(lob_id: int, item_key: str, data: dict = Body(...)):
    field = data.get("field")
    if field not in EDITABLE:
        raise HTTPException(400, "This column cannot be edited here")
    try:
        val = _edit_value(field, data.get("value"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db.get_conn() as c:
        n = _apply_edits(c, [(lob_id, item_key, field, val)])
        row = db.one(c, "SELECT * FROM inventory_current WHERE lob_id=? AND item_key=?", (lob_id, item_key))
    return {"ok": True, "changed": n, "row": row}


@app.get("/api/lobs/{lob_id}/inventory/column-sheet")
def inventory_column_sheet(lob_id: int, request: Request):
    """One editable column (plus what identifies the row and what CrowdStrike says), for the rows the table shows."""
    p = _params(request)
    field = p.pop("field", "edr_installed")
    if field not in EDITABLE:
        raise HTTPException(400, "This column cannot be edited here")
    with db.get_conn() as c:
        cols, frm, where, params, order = _inventory_query(p, lob_id)
        rows = db.rows(c, f"SELECT {cols} FROM {frm} {where} {order}", params)
    label = EDITABLE[field][0]
    out = [{"lob": r["lob"], "key": f"{r['lob_id']}|{r['item_key']}", "ip": r["ip"], "node_name": r["node_name"], "msp": r["msp"],
            "node_type": r["node_type"], "falcon": r.get("coverage_status"), "check": r.get("verification"), "value": r.get(field) or ""}
           for r in rows]
    columns = [("lob", "LOB"), ("ip", "IP"), ("node_name", "Node Name"), ("msp", "MSP"), ("node_type", "Node Type"),
               ("falcon", "EDR Status (CrowdStrike)"), ("check", "Inventory Claim Check"), ("value", label), ("key", "Row Key (do not edit)")]
    allowed = EDITABLE[field][1]
    guide = [{"t": f"Change only the '{label}' column" + (f" ({' / '.join(x for x in allowed if x)} or blank)" if allowed else "") +
              ", keep 'Row Key' as it is, then upload the file on the same page (Upload edited column)."},
             {"t": "Only rows whose value changed are updated. The next inventory upload for a LOB replaces these edits."}]
    return xlsx_response([(label[:31], columns, out), ("How to use", [("t", "")], guide)], f"edit_{field}")


@app.post("/api/lobs/{lob_id}/inventory/column-sheet")
async def inventory_column_upload(lob_id: int, file: UploadFile = File(...)):
    book = inventory.read_xlsx(await file.read(), all_sheets=True)
    rows = next(iter(book.values()), [])
    if not rows:
        raise HTTPException(400, "The file is empty")
    head = [str(h or "").strip() for h in rows[0]]
    field = next((f for f, (lbl, _) in EDITABLE.items() if lbl in head), None)
    if not field or "Row Key (do not edit)" not in head:
        raise HTTPException(400, "Use a sheet downloaded with 'Edit a column in Excel' (it needs the Row Key column)")
    ki, vi = head.index("Row Key (do not edit)"), head.index(EDITABLE[field][0])
    edits, bad = [], []
    for r in rows[1:]:
        key = str(r[ki] or "")
        if "|" not in key:
            continue
        lid, item = key.split("|", 1)
        try:
            edits.append((int(lid), item, field, _edit_value(field, inventory._cell(r[vi]))))
        except ValueError:
            bad.append(f"{item}: {r[vi]}")
    with db.get_conn() as c:
        n = _apply_edits(c, edits)
    return {"ok": True, "field": field, "rows": len(edits), "changed": n, "invalid": bad[:20], "invalid_count": len(bad)}


@app.get("/api/lobs/{lob_id}/versions")
def lob_versions(lob_id: int):
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT v.*, t.name template_name, lt.name type_name,
                             (v.id = COALESCE(lt.current_version_id, l.current_version_id)) is_current
                             FROM inventory_versions v JOIN lobs l ON l.id=v.lob_id LEFT JOIN templates t ON t.id=v.template_id
                             LEFT JOIN lob_types lt ON lt.id=v.type_id
                             WHERE v.lob_id=? ORDER BY v.uploaded_at DESC, v.id DESC""", (lob_id,))
    for r in rows:
        r["warnings"] = db.jloads(r["warnings"], [])
        r["mapping"] = db.jloads(r["mapping"], {})
    return {"rows": rows}


def _changes(c, lob_id, version_id, p, limit=None, offset=0):
    w, params = ["ch.lob_id=?"], [lob_id]
    if version_id:
        w.append("ch.version_id=?")
        params.append(version_id)
    if p.get("change_type"):
        w.append("ch.change_type=?")
        params.append(p["change_type"])
    if p.get("field"):
        w.append("ch.field=?")
        params.append(p["field"])
    if p.get("q"):
        w.append("ch.item_key LIKE ?")
        params.append(f"%{p['q'].lower()}%")
    where = " AND ".join(w)
    total = c.execute(f"SELECT COUNT(*) FROM inventory_changes ch WHERE {where}", params).fetchone()[0]
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"""SELECT ch.*, v.version_no, v.uploaded_at, lt.name type_name,
            COALESCE(r.node_name, pr.node_name) node_name, COALESCE(r.ip, pr.ip) ip
            FROM inventory_changes ch JOIN inventory_versions v ON v.id=ch.version_id
            LEFT JOIN lob_types lt ON lt.id=v.type_id
            LEFT JOIN inventory_rows r ON r.version_id=ch.version_id AND r.item_key=ch.item_key
            LEFT JOIN inventory_rows pr ON ch.change_type='removed' AND pr.item_key=ch.item_key AND pr.version_id=(
                SELECT MAX(v2.id) FROM inventory_versions v2 WHERE v2.lob_id=ch.lob_id AND v2.type_id IS v.type_id AND v2.id < ch.version_id)
            WHERE {where} ORDER BY v.uploaded_at DESC, v.id DESC, ch.change_type, ch.item_key {lim}""", params)
    fl = dict(config.INVENTORY_FIELDS)
    for r in rows:
        r["field_label"] = fl.get(r["field"], r["field"])
    return total, rows


@app.get("/api/lobs/{lob_id}/changes")
def lob_changes(lob_id: int, request: Request):
    p = _params(request)
    page, size = _page(p)
    with db.get_conn() as c:
        total, rows = _changes(c, lob_id, int(p["version_id"]) if p.get("version_id") else None, p, size, (page - 1) * size)
        fields = [r[0] for r in c.execute("SELECT DISTINCT field FROM inventory_changes WHERE lob_id=? AND field IS NOT NULL", (lob_id,))]
    return {"total": total, "rows": rows, "fields": fields}


@app.get("/api/lobs/{lob_id}/changes/export")
def lob_changes_export(lob_id: int, request: Request):
    p = _params(request)
    with db.get_conn() as c:
        _, rows = _changes(c, lob_id, int(p["version_id"]) if p.get("version_id") else None, p)
    cols = [("version_no", "Version"), ("uploaded_at", "Uploaded"), ("change_type", "Change"), ("item_key", "Key"),
            ("ip", "IP"), ("node_name", "Node Name"), ("field_label", "Field"), ("old_value", "Old Value"), ("new_value", "New Value")]
    return xlsx_response([("Changes", cols, rows)], f"inventory_changes_lob{lob_id}")


@app.get("/api/lobs/{lob_id}/items/{item_key}/history")
def item_history(lob_id: int, item_key: str):
    with db.get_conn() as c:
        ch = db.rows(c, """SELECT ch.change_type, ch.field, ch.old_value, ch.new_value, v.version_no, v.uploaded_at, v.filename
                           FROM inventory_changes ch JOIN inventory_versions v ON v.id=ch.version_id
                           WHERE ch.lob_id=? AND ch.item_key=? ORDER BY v.version_no DESC""", (lob_id, item_key))
        present = db.rows(c, """SELECT v.version_no FROM inventory_rows r JOIN inventory_versions v ON v.id=r.version_id
                                WHERE v.lob_id=? AND r.item_key=? ORDER BY v.version_no""", (lob_id, item_key))
        cur = db.one(c, "SELECT * FROM inventory_current WHERE lob_id=? AND item_key=?", (lob_id, item_key))
    fl = dict(config.INVENTORY_FIELDS)
    for r in ch:
        r["field_label"] = fl.get(r["field"], r["field"])
    if cur:
        cur["extra"] = db.jloads(cur["extra"], {})
    return {"changes": ch, "versions_present": [r["version_no"] for r in present], "current": cur}


@app.get("/api/lobs/{lob_id}/compare")
def lob_compare(lob_id: int, v_from: int, v_to: int):
    with db.get_conn() as c:
        return inventory.compare_versions(c, lob_id, v_from, v_to)


@app.post("/api/lobs/{lob_id}/versions/{version_id}/restore")
def lob_restore(lob_id: int, version_id: int, data: dict = Body(default={})):
    with db.get_conn() as c:
        return inventory.restore_version(c, lob_id, version_id, data.get("uploaded_by", ""), data.get("note", ""))


# ------------------------------------------------------------------ uploads
@app.post("/api/uploads")
async def upload_file(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("File too large (max 100 MB)")
    token = inventory.save_upload(file.filename, data)
    return _parse_response(token)


def _parse_response(token, sheet=None, header_row=None, template_id=None, lob_id=None):
    parsed = inventory.parse_upload(token, sheet, header_row)
    template = None
    with db.get_conn() as c:
        if not template_id and lob_id:
            lob = db.one(c, "SELECT default_template_id FROM lobs WHERE id=?", (lob_id,))
            template_id = (lob and lob["default_template_id"]) or db.standard_template_id(c)
        if template_id:
            template = db.one(c, "SELECT * FROM templates WHERE id=?", (template_id,))
    mapping = inventory.suggest_mapping(parsed["headers"], template)
    return {"token": token, "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:8], "mapping": mapping, "template_id": template["id"] if template else None,
            "key_field": template["key_field"] if template else "ip"}


@app.post("/api/uploads/{token}/sheets")
def upload_sheets(token: str, data: dict = Body(default={})):
    """Every sheet of the workbook with its own suggested mapping; sheets that look like inventory are pre-selected."""
    with db.get_conn() as c:
        tid = data.get("template_id")
        if not tid and data.get("lob_id"):
            lob = db.one(c, "SELECT default_template_id FROM lobs WHERE id=?", (data["lob_id"],))
            tid = (lob and lob["default_template_id"]) or db.standard_template_id(c)
        template = db.one(c, "SELECT * FROM templates WHERE id=?", (tid,)) if tid else None
    return {"sheets": inventory.sheets_info(token, template)}


@app.post("/api/uploads/{token}/parse")
def reparse(token: str, data: dict = Body(default={})):
    return _parse_response(token, data.get("sheet"), data.get("header_row"), data.get("template_id"), data.get("lob_id"))


@app.post("/api/lobs/{lob_id}/upload/preview")
def upload_preview(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        return inventory.preview_upload(c, lob_id, data["token"], data.get("mapping") or {}, data.get("key_field") or "ip",
                                        data.get("sheet"), data.get("header_row"), _scope_name(c, lob_id, data), data.get("type_id"),
                                        sheets=data.get("sheets"))


def _scope_name(c, lob_id, data):
    if not data.get("scope_msp_id"):
        return None
    m = db.one(c, "SELECT name FROM msps WHERE id=? AND lob_id=?", (data["scope_msp_id"], lob_id))
    if not m:
        raise ValueError("MSP not found in this LOB")
    return m["name"]


@app.post("/api/lobs/{lob_id}/upload/commit")
def upload_commit(lob_id: int, data: dict = Body(...)):
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    key_field = data.get("key_field") or "ip"
    sheets = [s for s in (data.get("sheets") or []) if s.get("include", True)]
    if sheets:  # several sheets of one workbook, each with its own mapping
        mapping = {k: v for k, v in (sheets[0].get("mapping") or {}).items() if v}
    elif "ip" not in mapping and "node_name" not in mapping:
        raise ValueError("Map at least the IP or Node Name column before committing")
    parsed = inventory.parse_upload(data["token"], sheets[0]["sheet"] if sheets else data.get("sheet"),
                                    sheets[0].get("header_row") if sheets else data.get("header_row"))
    with db.get_conn() as c:
        lob = db.one(c, "SELECT * FROM lobs WHERE id=?", (lob_id,))
        if not lob:
            raise HTTPException(404, "LOB not found")
        scope = _scope_name(c, lob_id, data)
        if sheets:
            _, items, warnings = inventory.multi_items(c, lob, data["token"], sheets, key_field, scope, data.get("type_id"))
            if len(sheets) > 1:
                warnings.insert(0, f"{len(sheets)} sheets merged: " + ", ".join(s["sheet"] for s in sheets))
        else:
            _, items, warnings = inventory.scoped_items(c, lob, parsed, mapping, key_field, scope, data.get("type_id"))
        if not items:
            raise ValueError("No usable rows found with this mapping")
        template_id = data.get("template_id")
        if data.get("save_template_name"):
            template_id = _save_template(c, {"name": data["save_template_name"], "key_field": key_field, "mapping": mapping,
                                             "sheet_name": parsed["sheet"], "header_row": parsed["header_row"]})
        defer = len(items) > inventory.DEFER_ROWS
        res = inventory.commit_version(c, lob_id, items, filename=parsed["filename"], note=data.get("note", ""),
                                       uploaded_by=data.get("uploaded_by", ""), template_id=template_id,
                                       key_field=key_field, mapping=mapping, warnings=warnings, scope_msp=scope,
                                       type_id=data.get("type_id"), defer_refresh=defer)
        if data.get("set_default_template") and template_id:
            c.execute("UPDATE lobs SET default_template_id=? WHERE id=?", (template_id, lob_id))
    if defer:  # the version is saved; matching with CrowdStrike, exposure and risk follow in the background
        inventory.refresh_async(f"Matching {len(items):,} inventory rows with CrowdStrike")
    return {**res, "warnings": warnings, "matching": defer}


@app.get("/api/refresh/status")
def refresh_status():
    return inventory.REFRESH


# ------------------------------------------------------------------ templates
def _save_template(c, data, tid=None):
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Template name is required")
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if k in config.INVENTORY_FIELD_KEYS and v}
    now = db.now_iso()
    if tid:
        c.execute("""UPDATE templates SET name=?, description=?, key_field=?, mapping=?, sheet_name=?, header_row=?, updated_at=?
                     WHERE id=?""", (name, data.get("description", ""), data.get("key_field") or "ip", json.dumps(mapping),
                                     data.get("sheet_name"), data.get("header_row"), now, tid))
        return tid
    existing = db.one(c, "SELECT id FROM templates WHERE name=? COLLATE NOCASE", (name,))
    if existing:
        return _save_template(c, data, existing["id"])
    return c.execute("""INSERT INTO templates(name, description, key_field, mapping, sheet_name, header_row, created_at, updated_at)
                        VALUES (?,?,?,?,?,?,?,?)""", (name, data.get("description", ""), data.get("key_field") or "ip",
                                                      json.dumps(mapping), data.get("sheet_name"), data.get("header_row"), now, now)).lastrowid


@app.get("/api/templates")
def templates():
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT t.*, (SELECT GROUP_CONCAT(name) FROM lobs WHERE default_template_id=t.id) used_by
                             FROM templates t ORDER BY name COLLATE NOCASE""")
    for r in rows:
        r["mapping"] = db.jloads(r["mapping"], {})
    return {"rows": rows}


@app.post("/api/templates")
def create_template(data: dict = Body(...)):
    with db.get_conn() as c:
        return {"id": _save_template(c, data)}


@app.put("/api/templates/{tid}")
def update_template(tid: int, data: dict = Body(...)):
    with db.get_conn() as c:
        return {"id": _save_template(c, data, tid)}


@app.delete("/api/templates/{tid}")
def delete_template(tid: int):
    with db.get_conn() as c:
        if tid == db.standard_template_id(c):
            raise ValueError("The Standard template is built in and cannot be deleted (you can still edit its column names)")
        c.execute("UPDATE lobs SET default_template_id=NULL WHERE default_template_id=?", (tid,))
        c.execute("DELETE FROM templates WHERE id=?", (tid,))
    return {"ok": True}


@app.get("/api/templates/blank/download")
def download_blank_template():
    return xlsx_response([("Inventory", config.INVENTORY_FIELDS, [])], "inventory_template")


@app.get("/api/templates/{tid}/download")
def download_template(tid: int):
    with db.get_conn() as c:
        t = db.one(c, "SELECT * FROM templates WHERE id=?", (tid,))
    if not t:
        raise HTTPException(404)
    mapping = db.jloads(t["mapping"], {})
    cols = [(f, mapping.get(f) or lbl) for f, lbl in config.INVENTORY_FIELDS]
    return xlsx_response([("Inventory", cols, [])], f"template_{t['name']}".replace(" ", "_"))


# ------------------------------------------------------------------ extra routes + UI
app.include_router(extra_router)
app.include_router(vulns.router)
app.include_router(legacy.router)
app.include_router(asset360.router)
app.include_router(niam.router)
app.include_router(posture.router)
app.include_router(registry.router)
app.include_router(filetemplates.router)
app.include_router(sod.router)
app.include_router(commatrix.router)
app.include_router(feasibility.router)


# ------------------------------------------------------------------ inventory sources
@app.get("/api/inventory-sources")
def inventory_sources():
    """Where inventory comes from: manual uploads today; ServiceNow CMDB and Jaspersoft reports are planned connectors."""
    with db.get_conn() as c:
        m = db.one(c, """SELECT COUNT(DISTINCT lob_id) lobs, COUNT(*) versions, MAX(uploaded_at) last_upload FROM inventory_versions""")
        nodes = c.execute("SELECT COUNT(*) FROM inventory_current").fetchone()[0]
        s = db.get_settings(c)
    return {"sources": [
        {"key": "manual", "name": "Manual upload", "status": "connected" if m["versions"] else "empty",
         "detail": f"{nodes:,} nodes · {m['lobs'] or 0} LOBs · {m['versions'] or 0} uploaded versions", "last": m["last_upload"],
         "how": "Excel / CSV per LOB, per MSP or per inventory type (Upload center or the LOB page)."},
        {"key": "servicenow", "name": "ServiceNow CMDB", "status": "planned", "configured": bool(s.get("servicenow_url")),
         "url": s.get("servicenow_url") or "", "table": s.get("servicenow_table") or "cmdb_ci_server",
         "how": "Read-only Table API pull of CI records (IP, name, class, OS, support group, install status) into LOB inventories."},
        {"key": "jaspersoft", "name": "Jaspersoft reports", "status": "planned",
         "how": "Scheduled report export (CSV) from JasperReports Server, loaded like a manual upload."},
    ]}


# ------------------------------------------------------------------ possible matches (review only, counted nowhere)
MC_COLS = """m.lob_id, l.name lob, m.item_key, m.ip, m.node_name, m.aid, m.cs_hostname, m.reason, m.found_at,
    h.local_ip cs_local_ip, h.connection_ip cs_connection_ip, h.console_state, h.online_state, h.last_seen, h.os_version"""


def _mc_query(p):
    w, params = [], []
    if p.get("lob"):
        w.append("m.lob_id=?")
        params.append(int(p["lob"]))
    q = (p.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        w.append("(m.ip LIKE ? OR m.node_name LIKE ? OR m.cs_hostname LIKE ?)")
        params += [like, like, like]
    return ("WHERE " + " AND ".join(w)) if w else "", params


@app.get("/api/match-candidates")
def match_candidates(request: Request):
    p = _params(request)
    page, size = _page(p)
    where, params = _mc_query(p)
    frm = "match_candidates m JOIN lobs l ON l.id=m.lob_id LEFT JOIN hosts h ON h.aid=m.aid"
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {MC_COLS} FROM {frm} {where} ORDER BY l.name, m.node_name LIMIT ? OFFSET ?",
                       params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@app.get("/api/match-candidates/export")
def match_candidates_export(request: Request):
    p = _params(request)
    where, params = _mc_query(p)
    with db.get_conn() as c:
        rows = db.rows(c, f"""SELECT {MC_COLS} FROM match_candidates m JOIN lobs l ON l.id=m.lob_id
                             LEFT JOIN hosts h ON h.aid=m.aid {where} ORDER BY l.name, m.node_name""", params)
    cols = [("lob", "LOB"), ("ip", "Inventory IP"), ("node_name", "Inventory Name"), ("cs_hostname", "CrowdStrike Hostname"),
            ("aid", "Agent ID"), ("cs_connection_ip", "Connection IP"), ("cs_local_ip", "Local IP"), ("online_state", "Online State"),
            ("last_seen", "Last Seen"), ("reason", "Why it may match")]
    return xlsx_response([("Possible matches", cols, rows)], "possible_matches")
app.include_router(sensor_support.router)
app.include_router(detections.router)
app.include_router(satellite.router)
app.include_router(cs_posture.router)
app.include_router(splunk.router)
app.include_router(seceon.router)
app.include_router(threats.router)
app.include_router(passive.router)
app.include_router(surface.router)
app.include_router(alerts.router)
app.include_router(intel.router)
app.include_router(spotlight.router)
app.include_router(subnets.router)

FRONTEND = config.BASE_DIR / "frontend" / "out"


class NextStaticFiles(StaticFiles):
    """Static export server. Next 16 writes RSC segment files as `__next.<seg>/__PAGE__.txt`
    but the client requests `__next.<seg>.__PAGE__.txt`; map the dotted name to the folder layout."""

    async def get_response(self, path, scope):
        try:
            resp = await super().get_response(path, scope)
            if resp.status_code != 404:
                if path.replace("\\", "/").startswith("_next/static/"):
                    # content-hashed file names: a new build gets new names, so the browser can keep these for good
                    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                return resp
        except StarletteHTTPException as e:
            if e.status_code != 404:
                raise
            resp = None
        head, _, name = path.replace("\\", "/").rpartition("/")
        if name.startswith("__next.") and name.endswith(".txt"):
            parts = name[len("__next."):-len(".txt")].split(".")
            if len(parts) > 1:
                alt = "/".join(filter(None, [head, "__next." + parts[0], *parts[1:-1], parts[-1] + ".txt"]))
                return await super().get_response(alt, scope)
        if resp is None:
            raise StarletteHTTPException(status_code=404)
        return resp


if FRONTEND.exists():
    # Next.js static export (npm run build in ./frontend)
    app.mount("/", NextStaticFiles(directory=FRONTEND, html=True), name="ui")
else:
    @app.get("/")
    def no_ui():
        return JSONResponse({"detail": "UI not built. Run: cd frontend && npm install && npm run build"}, status_code=503)
