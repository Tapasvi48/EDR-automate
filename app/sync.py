import json
import logging
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone

from . import db

log = logging.getLogger("sync")

_lock = threading.Lock()
STEPS = [
    ("auth", "Authenticate"),
    ("list", "List hosts in console"),
    ("hidden", "List hidden hosts"),
    ("details", "Fetch host details"),
    ("online", "Fetch online state"),
    ("write", "Save to database"),
    ("nic", "Fetch NIC / IP history"),
    ("analyze", "Detect duplicates & reinstalls"),
    ("inventory", "Re-verify LOB inventories"),
]
STATUS = {"running": False, "run_id": None, "stage": "idle", "started_at": None, "steps": [], "last": None}


class Progress:
    """Tracks sync steps for the UI and writes every step to the persistent sync_log."""

    def __init__(self, run_id):
        self.run_id = run_id
        STATUS["steps"] = [{"key": k, "label": l, "status": "pending", "detail": "", "done": 0, "total": 0} for k, l in STEPS]

    def _step(self, key):
        return next(x for x in STATUS["steps"] if x["key"] == key)

    def log(self, level, key, message):
        log.log({"info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}[level], "[%s] %s", key, message)
        with db.get_conn() as c:
            c.execute("INSERT INTO sync_log(run_id, ts, level, step, message) VALUES (?,?,?,?,?)",
                      (self.run_id, db.now_iso(), level, key, message))

    def start(self, key, detail=""):
        st = self._step(key)
        st.update(status="running", detail=detail, done=0, total=0)
        STATUS["stage"] = st["label"]
        self.log("info", key, f"{st['label']} started" + (f": {detail}" if detail else ""))

    def progress(self, key, done, total=None):
        st = self._step(key)
        st["done"] = done
        if total is not None:
            st["total"] = total
        STATUS["stage"] = f"{st['label']} ({done:,}/{st['total']:,})" if st["total"] else st["label"]

    def done(self, key, detail=""):
        st = self._step(key)
        st.update(status="done", detail=detail)
        self.log("info", key, f"{st['label']}: {detail}" if detail else f"{st['label']} done")

    def skip(self, key, detail):
        self._step(key).update(status="skipped", detail=detail)
        self.log("info", key, f"{self._step(key)['label']} skipped: {detail}")

    def warn(self, key, detail):
        self._step(key).update(status="warning", detail=detail)
        self.log("warn", key, detail)

    def fail(self, key, detail):
        st = self._step(key) if key else next((x for x in STATUS["steps"] if x["status"] == "running"), None)
        if st:
            st.update(status="error", detail=detail)
        self.log("error", st["key"] if st else "sync", detail)


HOST_COLS = [
    "aid", "cid", "hostname", "hostname_norm", "local_ip", "local_ip_num", "external_ip", "connection_ip",
    "default_gateway_ip", "mac_address", "platform_name", "os_version", "os_product_name", "os_build",
    "kernel_version", "product_type_desc", "chassis_type_desc", "machine_domain", "site_name", "ou",
    "agent_version", "containment_status", "rfm", "system_manufacturer", "system_product_name",
    "serial_number", "last_login_user", "tags", "groups", "first_seen", "last_seen", "modified_timestamp", "raw",
]


def _join(v):
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return v or ""


def map_host(d):
    ip = (d.get("local_ip") or "").strip()
    return {
        "aid": d.get("device_id"),
        "cid": d.get("cid"),
        "hostname": d.get("hostname") or "",
        "hostname_norm": db.norm_hostname(d.get("hostname")),
        "local_ip": ip,
        "local_ip_num": db.ip_to_num(ip),
        "external_ip": d.get("external_ip") or "",
        "connection_ip": d.get("connection_ip") or "",
        "default_gateway_ip": d.get("default_gateway_ip") or "",
        "mac_address": d.get("mac_address") or "",
        "platform_name": d.get("platform_name") or "",
        "os_version": d.get("os_version") or "",
        "os_product_name": d.get("os_product_name") or "",
        "os_build": d.get("os_build") or "",
        "kernel_version": d.get("kernel_version") or "",
        "product_type_desc": d.get("product_type_desc") or "",
        "chassis_type_desc": d.get("chassis_type_desc") or "",
        "machine_domain": d.get("machine_domain") or "",
        "site_name": d.get("site_name") or "",
        "ou": _join(d.get("ou")),
        "agent_version": d.get("agent_version") or "",
        "containment_status": d.get("status") or "",
        "rfm": d.get("reduced_functionality_mode") or "",
        "system_manufacturer": d.get("system_manufacturer") or "",
        "system_product_name": d.get("system_product_name") or "",
        "serial_number": d.get("serial_number") or "",
        "last_login_user": d.get("last_login_user") or "",
        "tags": _join(d.get("tags")),
        "groups": _join(d.get("groups")),
        "first_seen": d.get("first_seen") or "",
        "last_seen": d.get("last_seen") or "",
        "modified_timestamp": d.get("modified_timestamp") or "",
        "raw": json.dumps(d, default=str),
    }


def compute_devices(c, settings):
    """Agents in the console that share a usable IP are one device. The online (else most recently seen)
    agent is the device's primary; only primaries are counted in online / offline totals."""
    excl = exclusion_patterns(settings)
    groups = {}
    for r in c.execute("SELECT aid, local_ip, online_state, last_seen FROM hosts WHERE console_state='active'"):
        key = f"ip:{r['local_ip']}" if not ip_excluded(r["local_ip"], excl) else f"aid:{r['aid']}"
        groups.setdefault(key, []).append(r)
    updates = []
    for key, members in groups.items():
        members.sort(key=lambda m: (m["online_state"] == "online", m["last_seen"] or ""), reverse=True)
        for i, m in enumerate(members):
            updates.append((key, 1 if i == 0 else 0, m["aid"]))
    c.execute("UPDATE hosts SET device_key=NULL, is_primary=1 WHERE console_state<>'active'")
    c.executemany("UPDATE hosts SET device_key=?, is_primary=? WHERE aid=?", updates)
    return sum(1 for u in updates if u[1] == 0)


def ip_excluded(ip, patterns):
    if not ip:
        return True
    for p in patterns:
        if p.endswith("*"):
            if ip.startswith(p[:-1]):
                return True
        elif ip == p:
            return True
    return False


def exclusion_patterns(settings):
    return [p.strip() for p in (settings.get("dup_ip_exclude") or "").split(",") if p.strip()]


def run_sync(trigger="manual"):
    from .falcon import is_configured
    if not is_configured():
        return {"ok": False, "message": "CrowdStrike API credentials are not configured"}
    if not _lock.acquire(blocking=False):
        return {"ok": False, "message": "A sync is already running"}
    started = db.now_iso()
    with db.get_conn() as c:
        run_id = c.execute("INSERT INTO sync_runs(started_at, status, mode) VALUES (?, 'running', ?)",
                           (started, trigger)).lastrowid
    STATUS.update(running=True, run_id=run_id, stage="Starting", started_at=started)
    prog = Progress(run_id)
    prog.log("info", "sync", f"Sync #{run_id} started ({trigger})")
    t0 = time.time()
    try:
        result = _do_sync(started, prog)
        msg = (f"{result['total']:,} hosts · {result['new']:,} new · {result['removed']:,} removed · "
               f"{result['hidden']:,} hidden · {int(time.time() - t0)}s")
        if result.get("message"):
            msg += f" · {result['message']}"
        with db.get_conn() as c:
            c.execute("""UPDATE sync_runs SET finished_at=?, status='ok', total=?, fetched=?, new=?, removed=?,
                         restored=?, hidden=?, message=? WHERE id=?""",
                      (db.now_iso(), result["total"], result["fetched"], result["new"], result["removed"],
                       result["restored"], result["hidden"], msg, run_id))
        prog.log("info", "sync", f"Sync finished: {msg}")
        STATUS["last"] = {"ok": True, **result, "finished_at": db.now_iso()}
        return {"ok": True, **result}
    except Exception as e:  # noqa: BLE001
        log.error("Sync failed: %s\n%s", e, traceback.format_exc())
        prog.fail(None, str(e))
        with db.get_conn() as c:
            c.execute("UPDATE sync_runs SET finished_at=?, status='error', message=? WHERE id=?",
                      (db.now_iso(), str(e)[:2000], run_id))
        STATUS["last"] = {"ok": False, "message": str(e), "finished_at": db.now_iso()}
        return {"ok": False, "message": str(e)}
    finally:
        STATUS.update(running=False, stage="idle")
        _lock.release()


def _do_sync(started, prog):
    from .falcon import get_client
    settings = db.get_settings()
    now = started
    auto_days = int(settings.get("auto_remove_days") or 90)

    prog.start("auth")
    client = get_client()
    client.login()
    prog.done("auth", "API token issued")

    prog.start("list")
    active_aids = client.list_all_aids(progress=lambda d, t: prog.progress("list", d, t))
    active_set = set(active_aids)
    prog.done("list", f"{len(active_aids):,} hosts in console")

    prog.start("hidden")
    try:
        hidden_set = set(client.list_hidden_aids())
        prog.done("hidden", f"{len(hidden_set):,} hidden hosts")
    except Exception as e:  # noqa: BLE001 - optional permission
        hidden_set = set()
        prog.warn("hidden", f"Hidden hosts not available: {e}")

    with db.get_conn() as c:
        existing = {r["aid"]: r for r in c.execute(
            "SELECT aid, console_state, hostname, local_ip, agent_version, modified_timestamp, last_seen, nic_checked_at FROM hosts")}
    prev_active = [a for a, r in existing.items() if r["console_state"] == "active"]
    if len(prev_active) > 20 and len(active_set) < 0.5 * len(prev_active):
        raise RuntimeError(
            f"Falcon returned {len(active_set)} hosts but {len(prev_active)} were active last sync. "
            "Aborting to avoid mass-marking hosts as removed (check API scope / CID).")

    hidden_unknown = [a for a in hidden_set if a not in existing or existing[a]["console_state"] != "hidden"]
    fetch_ids = active_aids + [a for a in hidden_unknown if a not in active_set]
    prog.start("details")
    prog.progress("details", 0, len(fetch_ids))
    details = client.get_details(fetch_ids, progress=lambda d: prog.progress("details", d))
    prog.done("details", f"{len(details):,} host records")

    prog.start("online")
    prog.progress("online", 0, len(active_aids))
    online = client.get_online_states(active_aids, progress=lambda d: prog.progress("online", d))
    n_on = sum(1 for v in online.values() if v == "online")
    prog.done("online", f"{n_on:,} online · {len(online) - n_on:,} offline / unknown")

    prog.start("write")
    counts = {"total": len(active_set), "fetched": len(details), "new": 0, "removed": 0, "restored": 0, "hidden": 0}
    events, iph, upserts = [], [], []
    nic_targets = []

    for d in details:
        h = map_host(d)
        aid = h["aid"]
        if not aid:
            continue
        state = "active" if aid in active_set else ("hidden" if aid in hidden_set else "active")
        prev = existing.get(aid)
        if prev is None:
            counts["new"] += 1
            events.append((aid, now, "new", json.dumps({"hostname": h["hostname"], "ip": h["local_ip"], "first_seen": h["first_seen"]})))
            nic_targets.append(aid)
        else:
            if prev["console_state"] != "active" and state == "active":
                counts["restored"] += 1
                events.append((aid, now, "restored", json.dumps({"from": prev["console_state"]})))
            if prev["local_ip"] and h["local_ip"] and prev["local_ip"] != h["local_ip"]:
                events.append((aid, now, "ip_change", json.dumps({"old": prev["local_ip"], "new": h["local_ip"]})))
                nic_targets.append(aid)
            if prev["hostname"] and h["hostname"] and prev["hostname"] != h["hostname"]:
                events.append((aid, now, "hostname_change", json.dumps({"old": prev["hostname"], "new": h["hostname"]})))
            if prev["agent_version"] and h["agent_version"] and prev["agent_version"] != h["agent_version"]:
                events.append((aid, now, "agent_update", json.dumps({"old": prev["agent_version"], "new": h["agent_version"]})))
            if not prev["nic_checked_at"]:
                nic_targets.append(aid)
        if state == "hidden" and (prev is None or prev["console_state"] != "hidden"):
            counts["hidden"] += 1
            events.append((aid, now, "hidden", "{}"))
        h["console_state"] = state
        h["online_state"] = online.get(aid, "unknown" if state == "active" else None)
        upserts.append(h)
        seen = h["last_seen"] or now
        first = h["first_seen"] if prev is None else seen
        for kind in ("local", "external", "connection"):
            ip = h[f"{kind}_ip"]
            if ip:
                iph.append((aid, ip, db.ip_to_num(ip), h["mac_address"] if kind == "local" else "", kind, "sync", first, seen))

    cols = HOST_COLS + ["console_state", "online_state"]
    upd = ", ".join(f"{col}=excluded.{col}" for col in cols if col != "aid")
    sql = (f"INSERT INTO hosts ({', '.join(cols)}, online_checked_at, db_first_synced, db_last_synced) "
           f"VALUES ({', '.join('?' * len(cols))}, ?, ?, ?) ON CONFLICT(aid) DO UPDATE SET {upd}, "
           "online_checked_at=excluded.online_checked_at, db_last_synced=excluded.db_last_synced, "
           "removed_at=CASE WHEN excluded.console_state='active' THEN NULL ELSE hosts.removed_at END, "
           "removal_type=CASE WHEN excluded.console_state='active' THEN NULL ELSE hosts.removal_type END")
    with db.get_conn() as c:
        c.executemany(sql, [[h[col] for col in cols] + [now, now, now] for h in upserts])
        c.executemany(
            """INSERT INTO ip_history(aid, ip, ip_num, mac, kind, source, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(aid, ip, kind) DO UPDATE SET
                 first_seen=MIN(ip_history.first_seen, excluded.first_seen),
                 last_seen=MAX(ip_history.last_seen, excluded.last_seen),
                 mac=COALESCE(NULLIF(excluded.mac, ''), ip_history.mac)""", iph)

        # hosts that disappeared from the console
        gone = []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=auto_days - 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        handled = {h["aid"] for h in upserts}
        for aid, r in existing.items():
            if aid in active_set or aid in handled:
                continue
            if aid in hidden_set:
                if r["console_state"] != "hidden":
                    gone.append(("hidden", "hidden", aid))
                    events.append((aid, now, "hidden", "{}"))
                    counts["hidden"] += 1
            elif r["console_state"] != "removed":
                rtype = "auto_inactive" if (r["last_seen"] or "") < cutoff else "deleted"
                gone.append(("removed", rtype, aid))
                events.append((aid, now, "removed", json.dumps({"type": rtype, "last_seen": r["last_seen"],
                                                                 "from": r["console_state"]})))
                counts["removed"] += 1
        c.executemany("UPDATE hosts SET console_state=?, removal_type=?, removed_at=?, online_state=NULL WHERE aid=?",
                      [(s, t, now, a) for s, t, a in gone])
        c.execute("UPDATE hosts SET removed_at=COALESCE(removed_at, ?), removal_type='hidden' "
                  "WHERE console_state='hidden' AND COALESCE(removal_type,'')<>'hidden'", (now,))
        c.executemany("INSERT INTO host_events(aid, ts, event, details) VALUES (?,?,?,?)", events)

    prog.done("write", f"{counts['new']:,} new · {counts['removed']:,} removed · {counts['hidden']:,} hidden · {counts['restored']:,} restored")

    if settings.get("fetch_nic_history") != "1":
        prog.skip("nic", "disabled in settings")
    elif not nic_targets:
        prog.skip("nic", "no new or changed hosts")
    else:
        nic_targets = list(dict.fromkeys(nic_targets))[:20000]
        prog.start("nic", f"{len(nic_targets):,} new / changed hosts")
        prog.progress("nic", 0, len(nic_targets))
        try:
            store_nic_history(client.get_nic_history(nic_targets, progress=lambda d: prog.progress("nic", d)), nic_targets)
            prog.done("nic", f"{len(nic_targets):,} hosts")
        except Exception as e:  # noqa: BLE001
            prog.warn("nic", f"NIC history skipped: {e}")
            counts["message"] = "NIC history skipped"

    prog.start("analyze")
    with db.get_conn() as c:
        detect_reinstalls(c, settings)
        dup_agents = compute_devices(c, settings)
        capture_daily_stats(c, settings)
    prog.done("analyze", f"{dup_agents:,} duplicate agents merged into their devices")

    prog.start("inventory")
    with db.get_conn() as c:
        from .inventory import refresh_matches
        refresh_matches(c)
        n = c.execute("SELECT COUNT(*) FROM inventory_current").fetchone()[0]
    prog.done("inventory", f"{n:,} inventory nodes checked")
    return counts


def store_nic_history(hist, checked_aids):
    now = db.now_iso()
    rows_ = []
    for aid, entries in hist.items():
        per_ip = {}
        for e in entries:
            ip = (e.get("ip_address") or "").strip()
            if not ip:
                continue
            ts = e.get("timestamp") or ""
            cur = per_ip.setdefault(ip, [ts, ts, e.get("mac_address") or ""])
            cur[0] = min(cur[0], ts) if cur[0] else ts
            cur[1] = max(cur[1], ts)
        for ip, (f, l, mac) in per_ip.items():
            rows_.append((aid, ip, db.ip_to_num(ip), mac, "local", "falcon_nic", f, l))
    with db.get_conn() as c:
        c.executemany(
            """INSERT INTO ip_history(aid, ip, ip_num, mac, kind, source, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(aid, ip, kind) DO UPDATE SET
                 first_seen=MIN(ip_history.first_seen, excluded.first_seen),
                 last_seen=MAX(ip_history.last_seen, excluded.last_seen),
                 source=CASE WHEN ip_history.source='sync' THEN 'sync+falcon_nic' ELSE ip_history.source END""", rows_)
        c.executemany("UPDATE hosts SET nic_checked_at=? WHERE aid=?", [(now, a) for a in checked_aids])


def detect_reinstalls(c, settings):
    """A host is a reinstall when an OLDER agent ID (different AID) had the same IP and/or hostname.

    Confidence: ip+hostname (strong) > hostname > ip. Excluded IPs never count as evidence.
    """
    excl = exclusion_patterns(settings)
    hosts = db.rows(c, "SELECT aid, hostname_norm, local_ip, first_seen, last_seen, console_state, is_reinstall, reinstall_of FROM hosts")
    by_ip, by_hn = {}, {}
    for r in c.execute("SELECT aid, ip FROM ip_history WHERE kind='local'"):
        if not ip_excluded(r["ip"], excl):
            by_ip.setdefault(r["ip"], set()).add(r["aid"])
    info = {}
    for h in hosts:
        info[h["aid"]] = h
        if h["local_ip"] and not ip_excluded(h["local_ip"], excl):
            by_ip.setdefault(h["local_ip"], set()).add(h["aid"])
        if h["hostname_norm"]:
            by_hn.setdefault(h["hostname_norm"], set()).add(h["aid"])

    ip_of = {}
    for ip, aids in by_ip.items():
        for a in aids:
            ip_of.setdefault(a, set()).add(ip)

    updates, new_events, now = [], [], db.now_iso()
    for h in hosts:
        aid, fs = h["aid"], h["first_seen"] or ""
        cands = {}
        for ip in ip_of.get(aid, ()):
            for o in by_ip.get(ip, ()):
                if o != aid and (info[o]["first_seen"] or "") < fs:
                    cands.setdefault(o, set()).add("ip")
        if h["hostname_norm"]:
            for o in by_hn.get(h["hostname_norm"], ()):
                if o != aid and (info[o]["first_seen"] or "") < fs:
                    cands.setdefault(o, set()).add("hostname")
        if cands:
            prev = [{"aid": o, "match": "+".join(sorted(m, reverse=True)), "hostname": info[o]["hostname_norm"],
                     "ip": info[o]["local_ip"], "first_seen": info[o]["first_seen"], "last_seen": info[o]["last_seen"],
                     "state": info[o]["console_state"]} for o, m in cands.items()]
            prev.sort(key=lambda p: p["first_seen"] or "", reverse=True)
            kinds = {p["match"] for p in prev}
            reason = "ip+hostname" if "ip+hostname" in kinds else ("hostname" if "hostname" in kinds else "ip")
            payload = json.dumps(prev[:20])
            if not h["is_reinstall"]:
                new_events.append((aid, now, "reinstall", json.dumps({"reason": reason, "previous": [p["aid"] for p in prev[:5]]})))
            if not h["is_reinstall"] or h["reinstall_of"] != payload:
                updates.append((1, payload, reason, aid))
        elif h["is_reinstall"]:
            updates.append((0, None, None, aid))
    c.executemany("UPDATE hosts SET is_reinstall=?, reinstall_of=?, reinstall_reason=? WHERE aid=?", updates)
    c.executemany("INSERT INTO host_events(aid, ts, event, details) VALUES (?,?,?,?)", new_events)


def capture_daily_stats(c, settings, day=None):
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stale_cut = (datetime.now(timezone.utc) - timedelta(hours=float(settings.get("stale_online_hours") or 1))).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = db.one(c, """SELECT
        SUM(console_state='active' AND is_primary=1) total,
        SUM(console_state='active' AND is_primary=1 AND online_state='online') online,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline') offline,
        SUM(console_state='active' AND is_primary=1 AND (online_state IS NULL OR online_state='unknown')) unknown,
        SUM(console_state='active' AND is_primary=1 AND online_state='online' AND last_seen < ?) stale_online,
        SUM(console_state='hidden') hidden
        FROM hosts""", (stale_cut,))
    new = c.execute("SELECT COUNT(*) FROM hosts WHERE substr(first_seen,1,10)=?", (day,)).fetchone()[0]
    removed = c.execute("SELECT COUNT(*) FROM hosts WHERE console_state='removed' AND substr(removed_at,1,10)=?", (day,)).fetchone()[0]
    c.execute("""INSERT OR REPLACE INTO daily_stats(day, total, online, offline, unknown, stale_online, new_hosts, removed, hidden, captured_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?)""",
              (day, r["total"] or 0, r["online"] or 0, r["offline"] or 0, r["unknown"] or 0, r["stale_online"] or 0,
               new, removed, r["hidden"] or 0, db.now_iso()))


# ---------------- scheduler ----------------
def next_sync_at():
    """When the next automatic sync is due (None = disabled or not configured)."""
    from .falcon import is_configured
    minutes = int(db.get_settings().get("sync_interval_minutes") or 0)
    if minutes <= 0 or not is_configured():
        return None
    with db.get_conn() as c:
        last = c.execute("SELECT started_at FROM sync_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not last:
        return db.now_iso()
    t = datetime.strptime(last[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + timedelta(minutes=minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def start_scheduler():
    def loop():
        time.sleep(3)
        while True:
            try:
                due = next_sync_at()
                if due and due <= db.now_iso() and not STATUS["running"]:
                    run_sync(trigger="scheduled")
            except Exception:  # noqa: BLE001
                log.exception("scheduler error")
            time.sleep(30)

    threading.Thread(target=loop, daemon=True, name="sync-scheduler").start()
