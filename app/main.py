import base64
import json
import logging
import secrets
import threading
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import config, db, falcon, inventory, queries, sync
from .exporter import xlsx_response
from .extra import router as extra_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    with db.get_conn() as c:
        sync.compute_devices(c, db.get_settings(c))  # columns may be new after an upgrade
    sync.start_scheduler()
    yield


app = FastAPI(title="EDR Asset Dashboard", lifespan=lifespan)


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
        inventory.refresh_matches(c)
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
    if sync.STATUS["running"] or not falcon.is_configured():
        return False
    threading.Thread(target=sync.run_sync, kwargs={"trigger": trigger}, daemon=True).start()
    return True


@app.post("/api/sync")
def trigger_sync():
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
    return {**sync.STATUS, "runs": runs, "log_tail": list(reversed(tail)), "configured": falcon.is_configured(),
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
        inventory.refresh_matches(c)
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
    if p.get("outdated") == "1":
        queries.prepare_outdated_temp(c)
    return queries.build_host_query(p, settings)


@app.get("/api/hosts")
def hosts(request: Request):
    p = _params(request)
    page, size = _page(p)
    with db.get_conn() as c:
        frm, where, params, order = _host_query(c, p)
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {frm} {where} {order} LIMIT ? OFFSET ?",
                       params + [size, (page - 1) * size])
    return {"total": total, "page": page, "size": size, "rows": rows}


@app.get("/api/hosts/export")
def hosts_export(request: Request):
    p = _params(request)
    with db.get_conn() as c:
        frm, where, params, order = _host_query(c, p)
        rows = db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {frm} {where} {order}", params)
    for r in rows:
        r["is_reinstall"] = "Yes" if r["is_reinstall"] else ""
    return xlsx_response([("Hosts", queries.HOST_EXPORT_COLUMNS, rows)], p.get("name") or "edr_hosts")


@app.get("/api/hosts/{aid}")
def host_detail(aid: str):
    with db.get_conn() as c:
        h = db.one(c, "SELECT * FROM hosts WHERE aid=?", (aid,))
        if not h:
            raise HTTPException(404, "Host not found")
        settings = db.get_settings(c)
        h["raw"] = db.jloads(h["raw"], {})
        h["reinstall_of"] = db.jloads(h["reinstall_of"], [])
        ips = db.rows(c, "SELECT ip, kind, source, mac, first_seen, last_seen FROM ip_history WHERE aid=? ORDER BY last_seen DESC", (aid,))
        events = db.rows(c, "SELECT ts, event, details FROM host_events WHERE aid=? ORDER BY id DESC LIMIT 200", (aid,))
        for e in events:
            e["details"] = db.jloads(e["details"], {})
        same_ip = []
        if h["local_ip"] and not sync.ip_excluded(h["local_ip"], sync.exclusion_patterns(settings)):
            same_ip = db.rows(c, """SELECT aid, hostname, local_ip, console_state, online_state, first_seen, last_seen, platform_name
                                   FROM hosts WHERE local_ip=? AND aid<>? ORDER BY last_seen DESC""", (h["local_ip"], aid))
        same_hn = db.rows(c, """SELECT aid, hostname, local_ip, console_state, online_state, first_seen, last_seen, platform_name
                               FROM hosts WHERE hostname_norm=? AND hostname_norm<>'' AND aid<>? ORDER BY last_seen DESC""",
                          (h["hostname_norm"], aid))
        # later AIDs that replaced this one
        replaced_by = [r for r in db.rows(c, "SELECT aid, hostname, local_ip, first_seen, reinstall_of FROM hosts WHERE is_reinstall=1 AND first_seen > ? AND (local_ip=? OR hostname_norm=?)",
                                          (h["first_seen"] or "", h["local_ip"], h["hostname_norm"]))
                       if aid in (r.pop("reinstall_of") or "")]
        inv = db.rows(c, """SELECT l.name lob, l.id lob_id, ic.* FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
                            WHERE ic.matched_aid=?""", (aid,))
    return {"host": h, "ip_history": ips, "events": events, "same_ip": same_ip, "same_hostname": same_hn,
            "replaced_by": replaced_by, "inventory": inv}


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
def duplicates(by: str = "ip", q: str = "", include_removed: int = 0, page: int = 1, size: int = 100):
    with db.get_conn() as c:
        return queries.duplicate_groups(c, db.get_settings(c), by, q, bool(include_removed), size, (page - 1) * size)


@app.get("/api/duplicates/members")
def duplicate_members(by: str, value: str, include_removed: int = 0):
    with db.get_conn() as c:
        return {"rows": queries.duplicate_members(c, by, value, bool(include_removed))}


@app.get("/api/duplicates/export")
def duplicates_export(by: str = "ip", q: str = "", include_removed: int = 0):
    with db.get_conn() as c:
        g = queries.duplicate_groups(c, db.get_settings(c), by, q, bool(include_removed), 100000, 0)
        members = []
        for grp in g["rows"]:
            for m in queries.duplicate_members(c, by, grp["value"], bool(include_removed)):
                members.append({"group": grp["value"], "group_size": grp["n"], **m})
    cols = [("group", "Duplicate " + by), ("group_size", "Group Size"), ("hostname", "Hostname"), ("aid", "Agent ID"),
            ("local_ip", "Local IP"), ("console_state", "Console State"), ("online_state", "Online"), ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"), ("platform_name", "Platform"), ("os_version", "OS"), ("agent_version", "Sensor"),
            ("serial_number", "Serial"), ("mac_address", "MAC")]
    return xlsx_response([("Duplicates", cols, members)], f"duplicates_by_{by}")


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
        w.append("(h.hostname LIKE ? OR h.local_ip LIKE ? OR e.aid = ?)")
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
        for t in ("inventory_changes", "inventory_current", "inventory_versions", "msps", "agent_tags"):
            c.execute(f"DELETE FROM {t} WHERE lob_id=?", (lob_id,))
        c.execute("DELETE FROM lobs WHERE id=?", (lob_id,))
        inventory.rebuild_host_map(c)
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
    return {"lob": lob, "summary": summary, "facets": facets, "current_version": current, "msps": msps, "node_types": node_types}


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
        inventory.rebuild_host_map(c)
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
        w.append("(h.hostname LIKE ? OR h.local_ip LIKE ? OR t.aid=?)")
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
        inventory.rebuild_host_map(c)
    return {"ok": True}


INV_BASE_COLS = [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("domain", "Domain"),
                 ("live", "Live/Non Live"), ("os", "OS"), ("edr_feasible", "EDR Feasible"),
                 ("edr_installed", "EDR Installed (Inventory)"), ("remarks", "Remarks")]
INV_STATUS_COLS = [("coverage_status", "EDR Status"), ("change_tag", "Change Tag"), ("first_version_no", "First Seen in Version"),
                   ("last_changed_version_no", "Last Changed in Version"), ("edr_actual", "EDR Actual Status"),
                   ("verification", "Verification"), ("match_method", "Match Method"), ("cs_hostname", "Falcon Hostname"),
                   ("cs_last_seen", "Falcon Last Seen"), ("cs_agent_version", "Sensor Version"), ("cs_os", "Falcon OS"),
                   ("matched_aid", "Matched Agent ID"), ("match_count", "Active AIDs Matched")]
INV_SORTS = {"ip": "ic.ip", "node_name": "ic.node_name COLLATE NOCASE", "node_type": "ic.node_type", "domain": "ic.domain",
             "live": "ic.live", "os": "ic.os", "edr_feasible": "ic.edr_feasible", "edr_installed": "ic.edr_installed",
             "verification": "ic.verification", "edr_actual": "ic.edr_actual", "change_tag": "ic.change_tag",
             "cs_last_seen": "ic.cs_last_seen", "lob": "l.name", "remarks": "ic.remarks", "msp": "ic.msp COLLATE NOCASE",
             "coverage_status": "ic.coverage_status"}


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
        cols = "l.name lob, ic.*"  # msp name is stored on the row
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
            params += terms + [t.lower() for t in terms]
        else:
            like = f"%{q}%"
            w.append("(ic.ip LIKE ? OR ic.node_name LIKE ? OR ic.remarks LIKE ? OR ic.extra LIKE ?"
                     + ("" if version_id else " OR ic.cs_hostname LIKE ?") + ")")
            params += [q + "%", like, like, like] + ([] if version_id else [like])
    filt = ["node_type", "domain", "live", "os", "edr_feasible", "edr_installed"]
    if not version_id:
        filt += ["verification", "edr_actual", "change_tag", "match_method", "coverage_status", "edr_state"]
        if p.get("msp"):
            if p["msp"] == "none":
                w.append("ic.msp_id IS NULL")
            else:
                w.append("ic.msp_id=?")
                params.append(int(p["msp"]))
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
        if p.get("cross_msp_dup") == "1":
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
    if p.get("applicable") == "1" or p.get("in_scope") == "1":
        w.append("COALESCE(ic.live,'')<>'Non Live' AND COALESCE(ic.edr_feasible,'')<>'No'")
    if p.get("mismatch") == "1" and not version_id:
        w.append("ic.verification IN ('Claimed - Not Found','Claimed - Removed from Console','Installed - Marked No','Installed - Marked Not Feasible')")
    sort = INV_SORTS.get(p.get("sort") or "", "ic.rowid")
    if version_id and sort.startswith(("ic.verification", "ic.edr_actual", "ic.change_tag", "ic.cs_")):
        sort = "ic.rowid"
    direction = "DESC" if (p.get("dir") or "asc").lower() == "desc" else "ASC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return cols, frm, where, params, f"ORDER BY {sort} {direction}"


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
    columns = INV_BASE_COLS + ([] if p.get("version_id") else INV_STATUS_COLS) + [("x::" + k, k) for k in extra_keys]
    return xlsx_response([("Inventory", columns, rows)], f"inventory_{name}".replace(" ", "_"))


@app.get("/api/lobs/{lob_id}/versions")
def lob_versions(lob_id: int):
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT v.*, t.name template_name FROM inventory_versions v LEFT JOIN templates t ON t.id=v.template_id
                             WHERE v.lob_id=? ORDER BY v.version_no DESC""", (lob_id,))
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
    rows = db.rows(c, f"""SELECT ch.*, v.version_no, v.uploaded_at,
            COALESCE(r.node_name, pr.node_name) node_name, COALESCE(r.ip, pr.ip) ip
            FROM inventory_changes ch JOIN inventory_versions v ON v.id=ch.version_id
            LEFT JOIN inventory_rows r ON r.version_id=ch.version_id AND r.item_key=ch.item_key
            LEFT JOIN inventory_rows pr ON ch.change_type='removed' AND pr.item_key=ch.item_key AND pr.version_id=(
                SELECT MAX(v2.id) FROM inventory_versions v2 WHERE v2.lob_id=ch.lob_id AND v2.id < ch.version_id)
            WHERE {where} ORDER BY v.version_no DESC, ch.change_type, ch.item_key {lim}""", params)
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


@app.post("/api/uploads/{token}/parse")
def reparse(token: str, data: dict = Body(default={})):
    return _parse_response(token, data.get("sheet"), data.get("header_row"), data.get("template_id"), data.get("lob_id"))


@app.post("/api/lobs/{lob_id}/upload/preview")
def upload_preview(lob_id: int, data: dict = Body(...)):
    with db.get_conn() as c:
        return inventory.preview_upload(c, lob_id, data["token"], data.get("mapping") or {}, data.get("key_field") or "ip",
                                        data.get("sheet"), data.get("header_row"), _scope_name(c, lob_id, data))


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
    if "ip" not in mapping and "node_name" not in mapping:
        raise ValueError("Map at least the IP or Node Name column before committing")
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    with db.get_conn() as c:
        lob = db.one(c, "SELECT * FROM lobs WHERE id=?", (lob_id,))
        if not lob:
            raise HTTPException(404, "LOB not found")
        scope = _scope_name(c, lob_id, data)
        _, items, warnings = inventory.scoped_items(c, lob, parsed, mapping, key_field, scope)
        if not items:
            raise ValueError("No usable rows found with this mapping")
        template_id = data.get("template_id")
        if data.get("save_template_name"):
            template_id = _save_template(c, {"name": data["save_template_name"], "key_field": key_field, "mapping": mapping,
                                             "sheet_name": parsed["sheet"], "header_row": parsed["header_row"]})
        res = inventory.commit_version(c, lob_id, items, filename=parsed["filename"], note=data.get("note", ""),
                                       uploaded_by=data.get("uploaded_by", ""), template_id=template_id,
                                       key_field=key_field, mapping=mapping, warnings=warnings, scope_msp=scope)
        if data.get("set_default_template") and template_id:
            c.execute("UPDATE lobs SET default_template_id=? WHERE id=?", (template_id, lob_id))
    return {**res, "warnings": warnings}


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

FRONTEND = config.BASE_DIR / "frontend" / "out"
if FRONTEND.exists():
    # Next.js static export (npm run build in ./frontend)
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="ui")
else:
    @app.get("/")
    def no_ui():
        return JSONResponse({"detail": "UI not built. Run: cd frontend && npm install && npm run build"}, status_code=503)
