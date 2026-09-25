"""SQL builders for hosts, dashboard metrics, IP search and duplicates."""
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from . import db
from .sync import exclusion_patterns


def iso_ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def excl_sql(col, settings):
    """SQL fragment that is TRUE when `col` is a usable (non-excluded) IP."""
    parts, params = [f"{col} <> ''"], []
    for p in exclusion_patterns(settings):
        if p.endswith("*"):
            parts.append(f"{col} NOT LIKE ?")
            params.append(p[:-1] + "%")
        else:
            parts.append(f"{col} <> ?")
            params.append(p)
    return " AND ".join(parts), params


def _pair_groups(settings, having):
    ex1, p1 = excl_sql("connection_ip", settings)
    ex2, p2 = excl_sql("local_ip", settings)
    return (f"""SELECT connection_ip cip, local_ip lip, COUNT(*) dup_count FROM hosts
                WHERE console_state='active' AND COALESCE(connection_ip,'')<>'' AND COALESCE(local_ip,'')<>'' AND {ex1} AND {ex2}
                GROUP BY connection_ip, local_ip HAVING COUNT(*) > 1 AND {having}"""), p1 + p2


def dup_ip_subquery(settings):
    """Duplicate agents: active agents with the same connection IP AND local IP, at most one of them online."""
    return _pair_groups(settings, "SUM(online_state='online') <= 1")


def routing_conflict_subquery(settings):
    """Routing conflict: two or more ONLINE agents with the same connection IP AND local IP."""
    return _pair_groups(settings, "SUM(online_state='online') >= 2")


INV_JOIN = """LEFT JOIN (
    SELECT ic.matched_aid aid, MAX(ic.node_name) inv_node_name,
           MAX(ic.node_type) inv_node_type, MAX(ic.domain) inv_domain, MAX(ic.live) inv_live, MAX(ic.os) inv_os,
           MAX(ic.edr_feasible) inv_edr_feasible, MAX(ic.edr_installed) inv_edr_installed, MAX(ic.remarks) inv_remarks,
           MAX(ic.verification) inv_verification
    FROM inventory_current ic
    WHERE ic.matched_aid IS NOT NULL AND ic.edr_state <> 'Not Installed'
    GROUP BY ic.matched_aid) inv ON inv.aid = h.aid
  LEFT JOIN (
    SELECT hm.aid, GROUP_CONCAT(DISTINCT l.name) inv_lobs, GROUP_CONCAT(DISTINCT m.name) inv_msps,
           MIN(CASE WHEN hm.source='inventory' THEN 0 ELSE 1 END) tag_only
    FROM host_map hm JOIN lobs l ON l.id = hm.lob_id LEFT JOIN msps m ON m.id = hm.msp_id
    GROUP BY hm.aid) hm ON hm.aid = h.aid"""

NODE_TYPE_SQL = "COALESCE(NULLIF(inv.inv_node_type, ''), h.product_type_desc)"

HOST_LIST_COLS = """h.aid, h.hostname, h.local_ip, h.connection_ip, h.external_ip, h.mac_address, h.platform_name, h.os_version, h.os_build,
    h.product_type_desc, h.chassis_type_desc, h.machine_domain, h.site_name, h.ou, h.agent_version, h.containment_status, h.rfm,
    h.system_manufacturer, h.system_product_name, h.serial_number, h.last_login_user, h.tags, h.groups,
    h.first_seen, h.last_seen, h.online_state, h.console_state, h.removed_at, h.removal_type,
    h.is_reinstall, h.reinstall_reason, COALESCE(d.dup_count, 0) dup_count, COALESCE(rc.dup_count, 0) rc_count,
    hm.inv_lobs, hm.inv_msps, hm.tag_only, COALESCE(NULLIF(inv.inv_node_type, ''), h.product_type_desc) node_type,
    inv.inv_node_name, inv.inv_node_type, inv.inv_domain, inv.inv_live, inv.inv_os,
    inv.inv_edr_feasible, inv.inv_edr_installed, inv.inv_remarks, inv.inv_verification"""

HOST_EXPORT_COLUMNS = [
    ("hostname", "Hostname"), ("aid", "Agent ID"), ("local_ip", "Local IP"), ("connection_ip", "Connection IP"), ("external_ip", "External IP"),
    ("mac_address", "MAC"), ("console_state", "Console State"), ("online_state", "Online State"),
    ("first_seen", "First Seen (UTC)"), ("last_seen", "Last Seen (UTC)"), ("platform_name", "Platform"),
    ("os_version", "OS"), ("os_build", "OS Build"), ("product_type_desc", "Type"), ("chassis_type_desc", "Chassis"),
    ("machine_domain", "Domain"), ("site_name", "Site"), ("ou", "OU"), ("agent_version", "Sensor Version"),
    ("containment_status", "Containment"), ("rfm", "RFM"), ("system_manufacturer", "Manufacturer"),
    ("system_product_name", "Model"), ("serial_number", "Serial"), ("last_login_user", "Last Login User"),
    ("tags", "Tags"), ("groups", "Host Groups"), ("dup_count", "Duplicate Agents (same connection + local IP)"), ("rc_count", "Routing Conflict (online agents on same IPs)"), ("is_reinstall", "Reinstall"),
    ("removed_at", "Removed At"), ("removal_type", "Removal Type"),
    ("inv_lobs", "LOB"), ("inv_msps", "MSP"), ("node_type", "Node Type"), ("inv_node_name", "Inv Node Name"), ("inv_node_type", "Inv Node Type"),
    ("inv_domain", "Inv Domain"), ("inv_live", "Inv Live/Non Live"), ("inv_os", "Inv OS"),
    ("inv_edr_feasible", "Inv EDR Feasible"), ("inv_edr_installed", "Inv EDR Installed"),
    ("inv_remarks", "Inv Remarks"), ("inv_verification", "Inv Verification"),
]

HOST_SORTS = {
    "hostname": "h.hostname COLLATE NOCASE", "local_ip": "h.local_ip_num", "first_seen": "h.first_seen",
    "last_seen": "h.last_seen", "platform_name": "h.platform_name", "os_version": "h.os_version",
    "agent_version": "h.agent_version", "online_state": "h.online_state", "dup_count": "dup_count",
    "machine_domain": "h.machine_domain", "site_name": "h.site_name", "product_type_desc": "h.product_type_desc",
    "removed_at": "h.removed_at", "console_state": "h.console_state", "inv_lobs": "inv_lobs",
    "inv_msps": "inv_msps", "node_type": "node_type", "inv_node_type": "inv_node_type", "inv_live": "inv_live",
}


def _like(v):
    return "%" + v.replace("%", r"\%").replace("_", r"\_") + "%"


def build_host_query(p: dict, settings):
    """p = request query params. Returns (from_sql, where_sql, params, order_sql)."""
    dsql, dparams = dup_ip_subquery(settings)
    rsql, rparams = routing_conflict_subquery(settings)
    frm = (f"hosts h LEFT JOIN ({dsql}) d ON d.cip = h.connection_ip AND d.lip = h.local_ip AND h.console_state='active' "
           f"LEFT JOIN ({rsql}) rc ON rc.cip = h.connection_ip AND rc.lip = h.local_ip AND h.console_state='active' {INV_JOIN}")
    params = list(dparams) + list(rparams)
    w = []
    state = p.get("state") or "active"
    if state == "gone":
        w.append("h.console_state IN ('removed', 'hidden')")
    elif state != "all":
        w.append("h.console_state = ?")
        params.append(state)
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:  # bulk paste of hostnames / IPs
            ph = ",".join("?" * len(terms))
            w.append(f"(h.local_ip IN ({ph}) OR h.hostname_norm IN ({ph}) OR h.aid IN ({ph}))")
            params += terms + [db.norm_hostname(t) for t in terms] + [t.lower() for t in terms]
        else:
            w.append("""(h.hostname LIKE ? ESCAPE '\\' OR h.local_ip LIKE ? ESCAPE '\\' OR h.aid = ? OR h.external_ip = ?
                        OR h.serial_number LIKE ? ESCAPE '\\' OR h.mac_address LIKE ? ESCAPE '\\' OR h.last_login_user LIKE ? ESCAPE '\\'
                        OR h.tags LIKE ? ESCAPE '\\')""")
            lk = _like(q)
            params += [lk, q + "%", q.lower(), q, lk, lk, lk, lk]
    for key, col in (("platform", "h.platform_name"), ("os", "h.os_version"), ("product_type", "h.product_type_desc"),
                     ("domain", "h.machine_domain"), ("site", "h.site_name"), ("agent_version", "h.agent_version"),
                     ("removal_type", "h.removal_type"), ("chassis", "h.chassis_type_desc")):
        v = p.get(key)
        if v:
            vals = [x for x in v.split("|") if x != ""]
            w.append(f"{col} IN ({','.join('?' * len(vals))})")
            params += vals
    if p.get("dedupe") == "1" and p.get("duplicate") != "1":
        w.append("h.is_primary = 1")
    status = p.get("status")
    if status == "stale":
        p = {**p, "online": "online", "stale_online": "1"}
    elif status in ("online", "offline", "unknown"):
        p = {**p, "online": status}
    if p.get("node_type"):
        vals = p["node_type"].split("|")
        w.append(f"{NODE_TYPE_SQL} IN ({','.join('?' * len(vals))})")
        params += vals
    online = p.get("online")
    if online == "unknown":
        w.append("(h.online_state IS NULL OR h.online_state='unknown')")
    elif online:
        w.append("h.online_state = ?")
        params.append(online)
    stale_h = float(settings.get("stale_online_hours") or 1)
    if p.get("stale_online") == "1":
        w.append("h.online_state='online' AND h.last_seen < ?")
        params.append(iso_ago(hours=stale_h))
    b = p.get("seen_bucket")  # hours since last seen
    buckets = {"1-2h": (1, 2), "2-4h": (2, 4), "4-8h": (4, 8), "8-24h": (8, 24), "lt24h": (0, 24),
               "1-7d": (24, 168), "7-30d": (168, 720), "gt30d": (720, None), "gt7d": (168, None)}
    if b in buckets:
        lo, hi = buckets[b]
        w.append("h.last_seen <= ?")
        params.append(iso_ago(hours=lo))
        if hi:
            w.append("h.last_seen > ?")
            params.append(iso_ago(hours=hi))
    if p.get("reinstall") == "1":
        w.append("h.is_reinstall = 1")
    if p.get("reinstall_reason"):
        w.append("h.reinstall_reason = ?")
        params.append(p["reinstall_reason"])
    if p.get("duplicate") == "1":
        w.append("d.dup_count > 1")
    if p.get("routing_conflict") == "1":
        w.append("rc.dup_count > 1")
    if p.get("rfm") == "1":
        w.append("LOWER(h.rfm) = 'yes'")
    if p.get("contained") == "1":
        w.append("h.containment_status <> 'normal' AND h.containment_status <> ''")
    if p.get("inventory") == "none" or p.get("unmapped") == "1":
        w.append("hm.aid IS NULL")
    elif p.get("inventory") == "any":
        w.append("hm.aid IS NOT NULL")
    if p.get("lob"):
        w.append("EXISTS (SELECT 1 FROM host_map x WHERE x.aid=h.aid AND x.lob_id=?)")
        params.append(int(p["lob"]))
    if p.get("msp"):
        if p["msp"] == "none":
            w.append("EXISTS (SELECT 1 FROM host_map x WHERE x.aid=h.aid AND x.msp_id IS NULL" + (" AND x.lob_id=?" if p.get("lob") else "") + ")")
            params += [int(p["lob"])] if p.get("lob") else []
        else:
            w.append("EXISTS (SELECT 1 FROM host_map x WHERE x.aid=h.aid AND x.msp_id=?)")
            params.append(int(p["msp"]))
    if p.get("unlisted") == "1":
        # tagged to a LOB/MSP but missing from that LOB's inventory
        cond = "t.aid=h.aid"
        if p.get("lob"):
            cond += " AND t.lob_id=?"
            params.append(int(p["lob"]))
        if p.get("msp") and p["msp"] != "none":
            cond += " AND t.msp_id=?"
            params.append(int(p["msp"]))
        w.append(f"""EXISTS (SELECT 1 FROM agent_tags t WHERE {cond} AND NOT EXISTS (
            SELECT 1 FROM inventory_current ic WHERE ic.lob_id=t.lob_id AND ic.matched_aid=h.aid AND ic.edr_state<>'Not Installed'))""")
    for key, col, op in (("first_from", "h.first_seen", ">="), ("first_to", "h.first_seen", "<"),
                         ("last_from", "h.last_seen", ">="), ("last_to", "h.last_seen", "<"),
                         ("removed_from", "h.removed_at", ">="), ("removed_to", "h.removed_at", "<")):
        v = p.get(key)
        if v:
            if op == "<" and len(v) == 10:  # inclusive end date
                v = (datetime.strptime(v, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
            w.append(f"{col} {op} ?")
            params.append(v)
    if p.get("outdated") == "1":
        w.append(f"{SENSOR_LEVEL_SQL} = 'older'")
    if p.get("sensor_level") in SENSOR_LEVELS:
        w.append(f"{SENSOR_LEVEL_SQL} = ?")
        params.append(p["sensor_level"])
    if p.get("ip_range"):
        lo, hi = cidr_range(p["ip_range"])
        if lo is not None:
            w.append("h.local_ip_num BETWEEN ? AND ?")
            params += [lo, hi]
    sort = HOST_SORTS.get(p.get("sort") or "", "h.last_seen")
    direction = "ASC" if (p.get("dir") or "desc").lower() == "asc" else "DESC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return frm, where, params, f"ORDER BY {sort} {direction}, h.aid"


def version_key(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v or "0"))


SENSOR_LEVELS = ["N", "N-1", "N-2", "older"]


def sensor_release(v):
    """Falcon sensor release = major.minor: 7.40.19206.0 and 7.40.19301.0 are both release 7.40."""
    parts = re.split(r"[.\-]", (v or "").strip())
    return ".".join(parts[:2]) if len(parts) >= 2 else (v or "")


def sensor_levels(c):
    """(platform, version, level, release) for every sensor version in the console. Levels are counted by release
    number (major.minor), per platform: the newest release is N, the release number before it N-1, then N-2;
    everything older is 'older' (outdated)."""
    out, by_plat = [], {}
    for r in c.execute("SELECT DISTINCT platform_name, agent_version FROM hosts WHERE console_state='active' AND agent_version<>''"):
        by_plat.setdefault(r["platform_name"] or "", set()).add(r["agent_version"])
    for plat, vers in by_plat.items():
        newest = max((version_key(sensor_release(v)) for v in vers), default=(0, 0))

        def level(rel):
            # N-k by release number: with 7.40 newest, 7.39 is N-1 and 7.38 is N-2 even when those releases
            # are not installed anywhere; another major version is always 'older'
            k = version_key(rel)
            if len(k) < 2 or len(newest) < 2 or k[0] != newest[0]:
                return "older"
            return SENSOR_LEVELS[min(max(newest[1] - k[1], 0), 3)]

        out += [(plat, v, level(sensor_release(v)), sensor_release(v)) for v in vers]
    return out


def outdated_versions(c):
    return [(p, v) for p, v, lvl, _ in sensor_levels(c) if lvl == "older"]


def prepare_outdated_temp(c):
    # created once per connection and refilled (DROP would block while another statement on it is still open)
    c.execute("CREATE TEMP TABLE IF NOT EXISTS _sensor_rel (platform TEXT, v TEXT, lvl TEXT, rel TEXT)")
    c.execute("DELETE FROM _sensor_rel")
    c.executemany("INSERT INTO _sensor_rel(platform, v, lvl, rel) VALUES (?,?,?,?)", sensor_levels(c))


SENSOR_LEVEL_SQL = """(SELECT s.lvl FROM _sensor_rel s WHERE s.platform = COALESCE(h.platform_name,'') AND s.v = h.agent_version)"""


def cidr_range(text):
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
        if net.version != 4:
            return None, None
        return int(net.network_address), int(net.broadcast_address)
    except ValueError:
        return None, None


# ------------------------------------------------------------------ dashboard
def dashboard(c, settings):
    stale_h = float(settings.get("stale_online_hours") or 1)
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")
    k = db.one(c, """SELECT
        SUM(console_state='active' AND is_primary=1) active,
        SUM(console_state='active' AND is_primary=1 AND online_state='online') online,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline') offline,
        SUM(console_state='active' AND is_primary=1 AND (online_state IS NULL OR online_state='unknown')) unknown,
        SUM(console_state='active' AND is_primary=1 AND online_state='online' AND last_seen < ?) stale_online,
        SUM(console_state='hidden') hidden,
        SUM(console_state='removed') removed,
        SUM(console_state='removed' AND removal_type='auto_inactive') auto_removed,
        SUM(console_state='removed' AND removed_at >= ?) removed_7d,
        SUM(console_state='removed' AND removed_at >= ? AND removal_type='auto_inactive') auto_removed_7d,
        SUM(console_state='removed' AND removed_at >= ? AND removal_type='deleted') deleted_7d,
        SUM(first_seen >= ?) new_today,
        SUM(first_seen >= ?) new_7d,
        SUM(first_seen >= ?) new_30d,
        SUM(is_reinstall=1 AND first_seen >= ?) reinstall_7d,
        SUM(is_reinstall=1 AND first_seen >= ?) reinstall_30d,
        SUM(console_state='active' AND is_primary=1 AND LOWER(rfm)='yes') rfm,
        SUM(console_state='active' AND containment_status NOT IN ('normal','')) contained,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen >= ?) offline_lt24h,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen < ? AND last_seen >= ?) offline_1_7d,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen < ? AND last_seen >= ?) offline_7_30d,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen < ?) offline_gt30d,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen >= ?) went_offline_24h,
        SUM(console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen >= ?) went_offline_7d
        FROM hosts""", (
        iso_ago(hours=stale_h), iso_ago(days=7), iso_ago(days=7), iso_ago(days=7),
        today, iso_ago(days=7), iso_ago(days=30), iso_ago(days=7), iso_ago(days=30),
        iso_ago(hours=24), iso_ago(hours=24), iso_ago(days=7), iso_ago(days=7), iso_ago(days=30), iso_ago(days=30),
        iso_ago(hours=24), iso_ago(days=7)))
    k = {key: (v or 0) for key, v in k.items()}

    stale = db.one(c, """SELECT
        SUM(last_seen < ? AND last_seen >= ?) b1_2, SUM(last_seen < ? AND last_seen >= ?) b2_4,
        SUM(last_seen < ? AND last_seen >= ?) b4_8, SUM(last_seen < ? AND last_seen >= ?) b8_24,
        SUM(last_seen < ?) b24
        FROM hosts WHERE console_state='active' AND is_primary=1 AND online_state='online'""", (
        iso_ago(hours=max(1, stale_h)), iso_ago(hours=2), iso_ago(hours=2), iso_ago(hours=4),
        iso_ago(hours=4), iso_ago(hours=8), iso_ago(hours=8), iso_ago(hours=24), iso_ago(hours=24)))
    stale = {key: (v or 0) for key, v in stale.items()}

    dsql, dp = dup_ip_subquery(settings)
    dup = db.one(c, f"SELECT COUNT(*) groups, COALESCE(SUM(dup_count),0) hosts FROM ({dsql})", dp)
    rsql, rp = routing_conflict_subquery(settings)
    rc = db.one(c, f"SELECT COUNT(*) groups, COALESCE(SUM(dup_count),0) hosts FROM ({rsql})", rp)

    def breakdown(col, limit=12, where="console_state='active'"):
        return db.rows(c, f"""SELECT COALESCE(NULLIF({col},''),'(blank)') label, COUNT(*) n,
                              SUM(online_state='online') online FROM hosts WHERE {where}
                              GROUP BY 1 ORDER BY n DESC LIMIT {limit}""")

    start30 = (now - timedelta(days=29)).strftime("%Y-%m-%d")
    installs = db.rows(c, """SELECT substr(first_seen,1,10) day, COUNT(*) n, SUM(is_reinstall) reinstalls
                             FROM hosts WHERE first_seen >= ? GROUP BY 1 ORDER BY 1""", (start30,))
    offline_days = db.rows(c, """SELECT substr(last_seen,1,10) day, COUNT(*) n FROM hosts
                                 WHERE console_state='active' AND is_primary=1 AND online_state='offline' AND last_seen >= ?
                                 GROUP BY 1 ORDER BY 1""", (start30,))
    removed_days = db.rows(c, """SELECT substr(removed_at,1,10) day, COUNT(*) n, SUM(removal_type='auto_inactive') auto,
                                 SUM(removal_type='deleted') deleted FROM hosts WHERE console_state='removed'
                                 AND removed_at >= ? GROUP BY 1 ORDER BY 1""", (start30,))
    trend = db.rows(c, "SELECT * FROM daily_stats WHERE day >= ? ORDER BY day", (start30,))

    outdated = outdated_versions(c)
    prepare_outdated_temp(c)
    outdated_n = c.execute(f"SELECT COUNT(*) FROM hosts h WHERE console_state='active' AND is_primary=1 AND {SENSOR_LEVEL_SQL}='older'").fetchone()[0]
    not_in_inv = c.execute("""SELECT COUNT(*) FROM hosts h WHERE h.console_state='active' AND h.is_primary=1
        AND NOT EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=h.aid)""").fetchone()[0]

    lobs = lob_summaries(c, settings)
    last_sync = db.one(c, "SELECT * FROM sync_runs WHERE status='ok' ORDER BY id DESC LIMIT 1")
    return {
        "kpi": {**k, "dup_ip_groups": dup["groups"], "dup_ip_hosts": dup["hosts"],
                "routing_conflict_groups": rc["groups"], "routing_conflict_hosts": rc["hosts"],

                "outdated_sensor": outdated_n, "not_in_inventory": not_in_inv},
        "stale_buckets": stale,
        "stale_hours": stale_h,
        "auto_remove_days": int(settings.get("auto_remove_days") or 45),
        "platforms": breakdown("platform_name"),
        "os": breakdown("os_version", 10),
        "product_types": breakdown("product_type_desc"),
        "sensor_versions": breakdown("agent_version", 10),
        "sites": breakdown("site_name", 10),
        "installs": installs, "offline_days": offline_days, "removed_days": removed_days, "trend": trend,
        "outdated_versions": len(outdated),
        "lobs": lobs,
        "last_sync": last_sync,
    }


COVERAGE_SELECT = """COUNT(ic.item_key) nodes,
    SUM(ic.applicable=1) applicable,
    SUM(ic.applicable=1 AND ic.edr_state IN ('Online','Offline')) installed,
    SUM(ic.applicable=1 AND ic.edr_state='Online') online,
    SUM(ic.applicable=1 AND ic.edr_state='Offline') offline,
    SUM(ic.applicable=1 AND ic.edr_state='Hidden') hidden,
    SUM(ic.applicable=1 AND ic.edr_state='Removed') removed,
    SUM(ic.applicable=1 AND ic.edr_state='Not Installed') not_installed,
    SUM(ic.coverage_status='Not Feasible') not_feasible,
    SUM(ic.coverage_status='Non Live') non_live,
    SUM(ic.applicable=0 AND ic.edr_state IN ('Online','Offline')) installed_not_applicable,
    SUM(ic.edr_installed='Yes' AND ic.applicable=1 AND ic.edr_state NOT IN ('Online','Offline')) claimed_missing,
    SUM(ic.edr_installed='No' AND ic.edr_state IN ('Online','Offline')) marked_no,
    SUM(ic.change_tag='new') new_items, SUM(ic.change_tag='modified') modified_items"""

COV_KEYS = ["nodes", "applicable", "installed", "online", "offline", "hidden", "removed", "not_installed", "not_feasible",
            "non_live", "installed_not_applicable", "claimed_missing", "marked_no", "new_items", "modified_items"]


def _finish(r):
    for k in COV_KEYS:
        r[k] = r.get(k) or 0
    r["pending"] = r["not_installed"] + r["hidden"] + r["removed"]
    r["coverage"] = round(100.0 * r["installed"] / r["applicable"], 1) if r["applicable"] else None
    return r


def _unlisted(c, by):
    """Tagged, active agents missing from their LOB inventory, grouped by lob or (lob, msp)."""
    grp = "t.lob_id" if by == "lob" else "t.lob_id, t.msp_id"
    return {tuple(r[:-1]): r[-1] for r in c.execute(f"""SELECT {grp}, COUNT(*) FROM agent_tags t JOIN hosts h ON h.aid=t.aid
        WHERE h.console_state='active' AND NOT EXISTS (SELECT 1 FROM inventory_current ic WHERE ic.lob_id=t.lob_id
        AND ic.matched_aid=t.aid AND ic.edr_state<>'Not Installed') GROUP BY {grp}""")}


def _edr_dups(c, settings, by):
    """Installed inventory nodes whose Falcon agent has duplicate agents (same connection + local IP)."""
    dsql, dp = dup_ip_subquery(settings)
    grp = "ic.lob_id" if by == "lob" else "ic.lob_id, ic.msp_id"
    return {tuple(r[:-1]): r[-1] for r in c.execute(f"""SELECT {grp}, COUNT(DISTINCT h.connection_ip || '|' || h.local_ip) FROM inventory_current ic
        JOIN hosts h ON h.aid=ic.matched_aid JOIN ({dsql}) d ON d.cip=h.connection_ip AND d.lip=h.local_ip
        WHERE ic.edr_state IN ('Online','Offline') GROUP BY {grp}""", dp)}


def _cross_msp_dups(c):
    return {r[0]: r[1] for r in c.execute("""SELECT lob_id, COUNT(*) FROM (SELECT lob_id, ip FROM inventory_current
        WHERE COALESCE(ip,'')<>'' GROUP BY lob_id, ip HAVING COUNT(DISTINCT COALESCE(msp_id, 0)) > 1) GROUP BY lob_id""")}


def lob_summaries(c, settings=None):
    settings = settings or db.get_settings(c)
    rows = db.rows(c, f"""SELECT l.id, l.name, l.description, l.owner, v.version_no current_version, v.uploaded_at,
        (SELECT COUNT(*) FROM msps m WHERE m.lob_id=l.id) msp_count, {COVERAGE_SELECT}
        FROM lobs l LEFT JOIN inventory_versions v ON v.id=l.current_version_id
        LEFT JOIN inventory_current ic ON ic.lob_id=l.id GROUP BY l.id ORDER BY l.name COLLATE NOCASE""")
    unl, dups, xdup = _unlisted(c, "lob"), _edr_dups(c, settings, "lob"), _cross_msp_dups(c)
    for r in rows:
        _finish(r)
        r["unlisted"] = unl.get((r["id"],), 0)
        r["edr_dup_ips"] = dups.get((r["id"],), 0)
        r["cross_msp_dup_ips"] = xdup.get(r["id"], 0)
    return rows


def msp_summaries(c, settings=None, lob_id=None):
    settings = settings or db.get_settings(c)
    where, params = ("WHERE l.id=?", (lob_id,)) if lob_id else ("", ())
    agg = {(r["lob_id"], r["msp_id"]): r for r in db.rows(c, f"""SELECT ic.lob_id, ic.msp_id, {COVERAGE_SELECT}
        FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id {where} GROUP BY ic.lob_id, ic.msp_id""", params)}
    msps = db.rows(c, f"""SELECT m.id msp_id, m.name msp, m.description, m.contact, l.id lob_id, l.name lob
        FROM msps m JOIN lobs l ON l.id=m.lob_id {where} ORDER BY l.name COLLATE NOCASE, m.name COLLATE NOCASE""", params)
    unl, dups = _unlisted(c, "msp"), _edr_dups(c, settings, "msp")
    out = []
    seen = set()
    for m in msps:
        key = (m["lob_id"], m["msp_id"])
        seen.add(key)
        out.append({**m, **{k: v for k, v in (agg.get(key) or {}).items() if k not in ("lob_id", "msp_id")}})
    # rows with no MSP, and tagged-but-unassigned agents
    lobs = {r["id"]: r["name"] for r in c.execute(f"SELECT id, name FROM lobs l {where}", params)}
    for (lid, mid), a in agg.items():
        if (lid, mid) not in seen and mid is None:
            out.append({"msp_id": None, "msp": "Unassigned", "lob_id": lid, "lob": lobs.get(lid, ""),
                        **{k: v for k, v in a.items() if k not in ("lob_id", "msp_id")}})
            seen.add((lid, None))
    for (lid, mid), n in unl.items():
        if mid is None and (lid, None) not in seen and lid in lobs:
            out.append({"msp_id": None, "msp": "Unassigned", "lob_id": lid, "lob": lobs[lid]})
            seen.add((lid, None))
    for r in out:
        _finish(r)
        r["unlisted"] = unl.get((r["lob_id"], r["msp_id"]), 0)
        r["edr_dup_ips"] = dups.get((r["lob_id"], r["msp_id"]), 0)
    return out


def cross_msp_duplicates(c, lob_id):
    return db.rows(c, """SELECT ic.ip, COUNT(*) n, GROUP_CONCAT(DISTINCT COALESCE(m.name,'Unassigned')) msps,
        GROUP_CONCAT(DISTINCT ic.node_name) node_names, GROUP_CONCAT(DISTINCT ic.edr_state) edr_states
        FROM inventory_current ic LEFT JOIN msps m ON m.id=ic.msp_id
        WHERE ic.lob_id=? AND COALESCE(ic.ip,'')<>'' GROUP BY ic.ip HAVING COUNT(DISTINCT COALESCE(ic.msp_id,0)) > 1
        ORDER BY n DESC, ic.ip""", (lob_id,))


def overview(c, settings):
    d = dashboard(c, settings)
    prepare_outdated_temp(c)
    lv = {r["lvl"]: r for r in db.rows(c, """SELECT s.lvl, COUNT(*) n, SUM(h.online_state='online') online,
        GROUP_CONCAT(DISTINCT s.rel) versions FROM hosts h
        JOIN _sensor_rel s ON s.platform = COALESCE(h.platform_name,'') AND s.v = h.agent_version
        WHERE h.console_state='active' AND h.is_primary=1 AND h.agent_version<>'' GROUP BY 1""")}
    sensors = [{"level": l, "n": (lv.get(l) or {}).get("n") or 0, "online": (lv.get(l) or {}).get("online") or 0,
                "versions": sorted(((lv.get(l) or {}).get("versions") or "").split(",") if lv.get(l) else [], key=version_key, reverse=True)}
               for l in SENSOR_LEVELS]
    os_rows = db.rows(c, """SELECT COALESCE(NULLIF(os_version,''),'(blank)') label, COUNT(*) n, SUM(online_state='online') online
        FROM hosts WHERE console_state='active' AND is_primary=1 GROUP BY 1 ORDER BY n DESC LIMIT 12""")
    node_types = db.rows(c, """SELECT COALESCE(NULLIF(node_type,''),'(blank)') label, COUNT(*) nodes, SUM(applicable=1) applicable,
        SUM(applicable=1 AND edr_state IN ('Online','Offline')) installed, SUM(applicable=1 AND edr_state='Offline') offline,
        SUM(applicable=1 AND edr_state NOT IN ('Online','Offline')) pending
        FROM inventory_current GROUP BY 1 ORDER BY nodes DESC LIMIT 12""")
    unmapped = c.execute("""SELECT COUNT(*) FROM hosts h WHERE h.console_state='active' AND h.is_primary=1
        AND NOT EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=h.aid)""").fetchone()[0]
    d["kpi"]["unmapped"] = unmapped
    d["kpi"]["agents"] = c.execute("SELECT COUNT(*) FROM hosts WHERE console_state='active'").fetchone()[0]
    d.update(sensors=sensors, os=os_rows, node_types=node_types, msps=msp_summaries(c, settings))
    return d


# ------------------------------------------------------------------ IP search
def ip_search(c, q):
    q = (q or "").strip()
    out = {"query": q, "mode": None, "current": [], "history": [], "inventory": []}
    if not q:
        return out
    lo, hi = (None, None)
    if "/" in q:
        lo, hi = cidr_range(q)
    host_cols = """h.aid, h.hostname, h.local_ip, h.external_ip, h.platform_name, h.os_version, h.console_state,
                   h.online_state, h.first_seen, h.last_seen, h.agent_version, h.removal_type, h.is_reinstall"""
    if lo is not None:
        out["mode"] = "cidr"
        out["current"] = db.rows(c, f"SELECT {host_cols} FROM hosts h WHERE local_ip_num BETWEEN ? AND ? ORDER BY local_ip_num LIMIT 2000", (lo, hi))
        hist_where, hp = "ih.ip_num BETWEEN ? AND ?", [lo, hi]
        inv_where, ip_ = "ic.ip <> ''", []
        inv_filter = lambda r: (db.ip_to_num(r["ip"]) or -1) >= lo and (db.ip_to_num(r["ip"]) or -1) <= hi  # noqa: E731
    elif re.fullmatch(r"[\d.]+", q):
        exact = db.ip_to_num(q) is not None
        out["mode"] = "exact" if exact else "prefix"
        op, val = ("=", q) if exact else ("LIKE", q + "%")
        out["current"] = db.rows(c, f"""SELECT {host_cols} FROM hosts h WHERE local_ip {op} ? OR external_ip = ? OR connection_ip {op} ?
                                         ORDER BY console_state, last_seen DESC LIMIT 2000""", (val, q, val))
        hist_where, hp = f"ih.ip {op} ?", [val]
        inv_where, ip_ = f"ic.ip {op} ?", [val]
        inv_filter = None
    else:
        out["mode"] = "hostname"
        hn = db.norm_hostname(q)
        out["current"] = db.rows(c, f"""SELECT {host_cols} FROM hosts h WHERE hostname_norm LIKE ? ORDER BY console_state, last_seen DESC LIMIT 2000""",
                                 (hn + "%",))
        aids = [r["aid"] for r in out["current"]]
        if aids:
            hist_where, hp = f"ih.aid IN ({','.join('?' * len(aids))})", aids
        else:
            hist_where, hp = "0", []
        inv_where, ip_ = "LOWER(ic.node_name) LIKE ?", [q.lower() + "%"]
        inv_filter = None
    out["history"] = db.rows(c, f"""SELECT ih.ip, ih.kind, ih.source, ih.mac, ih.first_seen ip_first_seen, ih.last_seen ip_last_seen,
            h.aid, h.hostname, h.local_ip current_ip, h.console_state, h.online_state, h.last_seen, h.platform_name, h.os_version
            FROM ip_history ih JOIN hosts h ON h.aid = ih.aid WHERE {hist_where}
            ORDER BY ih.last_seen DESC LIMIT 3000""", hp)
    inv = db.rows(c, f"""SELECT l.name lob, l.id lob_id, ic.item_key, ic.ip, ic.node_name, ic.node_type, ic.live,
            ic.edr_installed, ic.edr_actual, ic.verification, ic.cs_hostname, ic.matched_aid
            FROM inventory_current ic JOIN lobs l ON l.id = ic.lob_id WHERE {inv_where} LIMIT 3000""", ip_)
    out["inventory"] = [r for r in inv if inv_filter(r)] if inv_filter else inv
    # summary: distinct AIDs that ever used the IP(s)
    out["distinct_hosts"] = len({r["aid"] for r in out["history"]} | {r["aid"] for r in out["current"]})
    return out


# ------------------------------------------------------------------ duplicates / routing conflicts
def duplicate_groups(c, settings, kind="duplicate", q="", include_removed=False, limit=500, offset=0):
    """Agents grouped by (connection IP, local IP). kind='duplicate': at most one online agent in the group;
    kind='routing': two or more online agents. Removed / hidden agents are only listed when asked for."""
    states = "('active','hidden','removed')" if include_removed else "('active')"
    ex1, p1 = excl_sql("connection_ip", settings)
    ex2, p2 = excl_sql("local_ip", settings)
    params = p1 + p2
    where = f"console_state IN {states} AND COALESCE(connection_ip,'')<>'' AND COALESCE(local_ip,'')<>'' AND {ex1} AND {ex2}"
    if q:
        where += " AND (connection_ip LIKE ? OR local_ip LIKE ?)"
        params = params + [q + "%", q + "%"]
    having = ("SUM(console_state='active' AND online_state='online') >= 2" if kind == "routing"
              else "SUM(console_state='active' AND online_state='online') <= 1 AND SUM(console_state='active') >= 1")
    base = f"FROM hosts WHERE {where} GROUP BY connection_ip, local_ip HAVING COUNT(*) > 1 AND {having}"
    total = c.execute(f"SELECT COUNT(*) FROM (SELECT 1 {base})", params).fetchone()[0]
    groups = db.rows(c, f"""SELECT connection_ip || ' / ' || local_ip value, connection_ip, local_ip, COUNT(*) n,
            SUM(console_state='active') active, SUM(online_state='online') online, MIN(first_seen) oldest_first_seen,
            MAX(first_seen) newest_first_seen, MAX(last_seen) latest_last_seen, GROUP_CONCAT(DISTINCT hostname) hostnames
            {base} ORDER BY n DESC, latest_last_seen DESC LIMIT ? OFFSET ?""", params + [limit, offset])
    return {"total": total, "rows": groups, "kind": kind}


def duplicate_members(c, connection_ip, local_ip, include_removed=False):
    states = "('active','hidden','removed')" if include_removed else "('active')"
    return db.rows(c, f"""SELECT aid, hostname, connection_ip, local_ip, mac_address, platform_name, os_version, agent_version,
            console_state, online_state, first_seen, last_seen, serial_number, is_reinstall, removal_type, removed_at, last_login_user
            FROM hosts WHERE connection_ip = ? AND local_ip = ? AND console_state IN {states}
            ORDER BY online_state='online' DESC, last_seen DESC""", (connection_ip, local_ip))
