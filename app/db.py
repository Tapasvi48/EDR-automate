import ipaddress
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Every host ever seen in the Falcon console. Rows are never deleted, so hosts removed
-- from the console (manually or by Falcon's inactivity auto-removal) are retained.
CREATE TABLE IF NOT EXISTS hosts (
    aid TEXT PRIMARY KEY,
    cid TEXT,
    hostname TEXT,
    hostname_norm TEXT,
    local_ip TEXT,
    local_ip_num INTEGER,
    external_ip TEXT,
    connection_ip TEXT,
    default_gateway_ip TEXT,
    mac_address TEXT,
    platform_name TEXT,
    os_version TEXT,
    os_product_name TEXT,
    os_build TEXT,
    kernel_version TEXT,
    product_type_desc TEXT,
    chassis_type_desc TEXT,
    machine_domain TEXT,
    site_name TEXT,
    ou TEXT,
    agent_version TEXT,
    containment_status TEXT,
    rfm TEXT,
    system_manufacturer TEXT,
    system_product_name TEXT,
    serial_number TEXT,
    last_login_user TEXT,
    tags TEXT,
    groups TEXT,
    first_seen TEXT,
    last_seen TEXT,
    modified_timestamp TEXT,
    online_state TEXT,              -- online | offline | unknown (Falcon GetOnlineState)
    online_checked_at TEXT,
    console_state TEXT NOT NULL DEFAULT 'active',   -- active | hidden | removed
    removed_at TEXT,
    removal_type TEXT,              -- auto_inactive | deleted | hidden
    is_reinstall INTEGER NOT NULL DEFAULT 0,
    reinstall_of TEXT,              -- JSON list of previous AIDs sharing IP/hostname
    reinstall_reason TEXT,
    nic_checked_at TEXT,
    device_key TEXT,                -- agents sharing a (non-excluded) IP form one device
    is_primary INTEGER NOT NULL DEFAULT 1,   -- the agent that represents its device in counts
    db_first_synced TEXT,
    db_last_synced TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS ix_hosts_ip ON hosts(local_ip);
CREATE INDEX IF NOT EXISTS ix_hosts_ipnum ON hosts(local_ip_num);
CREATE INDEX IF NOT EXISTS ix_hosts_hn ON hosts(hostname_norm);
CREATE INDEX IF NOT EXISTS ix_hosts_state ON hosts(console_state, online_state);
CREATE INDEX IF NOT EXISTS ix_hosts_first ON hosts(first_seen);
CREATE INDEX IF NOT EXISTS ix_hosts_last ON hosts(last_seen);
CREATE INDEX IF NOT EXISTS ix_hosts_removed ON hosts(removed_at);
CREATE INDEX IF NOT EXISTS ix_hosts_primary ON hosts(console_state, is_primary);

-- All IPs a host has ever had (from our own syncs and from Falcon NIC history)
CREATE TABLE IF NOT EXISTS ip_history (
    aid TEXT NOT NULL,
    ip TEXT NOT NULL,
    ip_num INTEGER,
    mac TEXT,
    kind TEXT,                      -- local | external | connection
    source TEXT,                    -- sync | falcon_nic
    first_seen TEXT,
    last_seen TEXT,
    PRIMARY KEY (aid, ip, kind)
);
CREATE INDEX IF NOT EXISTS ix_iph_ip ON ip_history(ip);
CREATE INDEX IF NOT EXISTS ix_iph_num ON ip_history(ip_num);

CREATE TABLE IF NOT EXISTS host_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aid TEXT NOT NULL,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,            -- new | removed | hidden | restored | ip_change | hostname_change | agent_update | reinstall
    details TEXT
);
CREATE INDEX IF NOT EXISTS ix_ev_aid ON host_events(aid);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON host_events(ts, event);

CREATE TABLE IF NOT EXISTS sync_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT,
    finished_at TEXT,
    status TEXT,                    -- running | ok | error
    mode TEXT,                      -- full | incremental
    total INTEGER, fetched INTEGER, new INTEGER, removed INTEGER, restored INTEGER, hidden INTEGER,
    message TEXT
);

CREATE TABLE IF NOT EXISTS sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    ts TEXT,
    level TEXT,                     -- info | warn | error
    step TEXT,
    message TEXT
);
CREATE INDEX IF NOT EXISTS ix_synclog_run ON sync_log(run_id);

CREATE TABLE IF NOT EXISTS daily_stats (
    day TEXT PRIMARY KEY,
    total INTEGER, online INTEGER, offline INTEGER, unknown INTEGER, stale_online INTEGER,
    new_hosts INTEGER, removed INTEGER, hidden INTEGER, captured_at TEXT
);

-- ---------- Inventory / LOB ----------
CREATE TABLE IF NOT EXISTS lobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    owner TEXT,
    default_template_id INTEGER,
    current_version_id INTEGER,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    key_field TEXT NOT NULL DEFAULT 'ip',   -- ip | node_name | ip_node_name
    mapping TEXT NOT NULL,                  -- JSON {std_field: source column header}
    sheet_name TEXT,
    header_row INTEGER,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS inventory_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    version_no INTEGER NOT NULL,
    filename TEXT,
    note TEXT,
    uploaded_by TEXT,
    uploaded_at TEXT,
    template_id INTEGER,
    key_field TEXT,
    mapping TEXT,
    row_count INTEGER, added INTEGER, removed INTEGER, modified INTEGER, unchanged INTEGER,
    restored_from INTEGER,
    scope_msp TEXT,                 -- set when the upload replaced only one MSP's rows
    warnings TEXT,
    UNIQUE (lob_id, version_no)
);

-- Managed service providers inside a LOB
CREATE TABLE IF NOT EXISTS msps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    contact TEXT,
    created_at TEXT,
    UNIQUE (lob_id, name COLLATE NOCASE)
);

-- Agents explicitly tagged to a LOB / MSP (uploaded AID + MSP sheet). Tagged agents that are not
-- in the LOB inventory are reported as "unlisted".
CREATE TABLE IF NOT EXISTS agent_tags (
    aid TEXT NOT NULL,
    lob_id INTEGER NOT NULL,
    msp_id INTEGER,
    source TEXT,
    tagged_at TEXT,
    PRIMARY KEY (aid, lob_id)
);
CREATE INDEX IF NOT EXISTS ix_tags_lob ON agent_tags(lob_id, msp_id);

-- Resolved host -> LOB / MSP attribution (inventory match or tag), rebuilt after sync / upload
CREATE TABLE IF NOT EXISTS host_map (
    aid TEXT NOT NULL,
    lob_id INTEGER NOT NULL,
    msp_id INTEGER,
    source TEXT NOT NULL,           -- inventory | tag
    PRIMARY KEY (aid, lob_id, source)
);
CREATE INDEX IF NOT EXISTS ix_hmap_lob ON host_map(lob_id, msp_id);

-- Full snapshot of each version (immutable)
CREATE TABLE IF NOT EXISTS inventory_rows (
    version_id INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    msp TEXT,
    ip TEXT, node_name TEXT, node_type TEXT, domain TEXT, live TEXT, os TEXT,
    edr_feasible TEXT, edr_installed TEXT, remarks TEXT,
    extra TEXT,
    row_hash TEXT,
    PRIMARY KEY (version_id, item_key)
);

CREATE TABLE IF NOT EXISTS inventory_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    version_id INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    change_type TEXT NOT NULL,      -- added | removed | modified
    field TEXT,
    old_value TEXT,
    new_value TEXT
);
CREATE INDEX IF NOT EXISTS ix_chg_ver ON inventory_changes(version_id);
CREATE INDEX IF NOT EXISTS ix_chg_lob ON inventory_changes(lob_id, item_key);

-- Current (latest version) inventory with EDR verification results, rebuilt on upload and after sync
CREATE TABLE IF NOT EXISTS inventory_current (
    lob_id INTEGER NOT NULL,
    item_key TEXT NOT NULL,
    msp TEXT,
    msp_id INTEGER,
    applicable INTEGER,             -- 1 = Live and EDR feasible
    edr_state TEXT,                 -- Online | Offline | Hidden | Removed | Not Installed
    coverage_status TEXT,           -- edr_state for applicable nodes, else Not Feasible | Non Live
    ip TEXT, node_name TEXT, node_type TEXT, domain TEXT, live TEXT, os TEXT,
    edr_feasible TEXT, edr_installed TEXT, remarks TEXT,
    extra TEXT,
    first_version_no INTEGER,
    last_changed_version_no INTEGER,
    change_tag TEXT,                -- new | modified | unchanged (relative to previous version)
    matched_aid TEXT,
    match_method TEXT,              -- ip+hostname | hostname | ip | ip_history
    match_count INTEGER,
    cs_hostname TEXT, cs_console_state TEXT, cs_online_state TEXT, cs_last_seen TEXT, cs_agent_version TEXT,
    cs_os TEXT,
    edr_actual TEXT,                -- Online | Offline | Inactive | Removed | Not Found
    verification TEXT,              -- Verified | Claimed - Not Found | Installed - Marked No | ...
    PRIMARY KEY (lob_id, item_key)
);
CREATE INDEX IF NOT EXISTS ix_inv_aid ON inventory_current(matched_aid);
CREATE INDEX IF NOT EXISTS ix_inv_ip ON inventory_current(ip);
CREATE INDEX IF NOT EXISTS ix_inv_msp ON inventory_current(lob_id, msp_id);
"""

# columns added after the first release: (table, column, type)
MIGRATIONS = [
    ("inventory_rows", "msp", "TEXT"),
    ("inventory_current", "msp", "TEXT"),
    ("inventory_current", "msp_id", "INTEGER"),
    ("inventory_current", "applicable", "INTEGER"),
    ("inventory_current", "edr_state", "TEXT"),
    ("inventory_current", "coverage_status", "TEXT"),
    ("inventory_versions", "scope_msp", "TEXT"),
    ("hosts", "device_key", "TEXT"),
    ("hosts", "is_primary", "INTEGER NOT NULL DEFAULT 1"),
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ip_to_num(ip):
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip.strip())
        return int(a) if a.version == 4 else None
    except ValueError:
        return None


def norm_hostname(name):
    if not name:
        return ""
    n = str(name).strip().lower()
    # FQDN -> short name, but keep plain IP-looking values intact
    if "." in n and ip_to_num(n) is None:
        n = n.split(".", 1)[0]
    return n


def connect():
    fresh = not config.DB_PATH.exists()
    conn = sqlite3.connect(config.DB_PATH, timeout=30, check_same_thread=False)
    if fresh:
        try:
            config.DB_PATH.chmod(0o600)  # holds the API secret
        except OSError:
            pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-64000")
    return conn


@contextmanager
def get_conn():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as c:
        for table, col, typ in MIGRATIONS:
            exists = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if exists and col not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        c.executescript(SCHEMA)
        for k, v in config.DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
        c.execute("""INSERT OR IGNORE INTO templates(name, description, key_field, mapping, created_at, updated_at)
                     VALUES (?,?,?,?,?,?)""",
                  (config.STANDARD_TEMPLATE, "Default inventory layout: IP, Node Name, MSP, Node Type, Domain, Live/Non Live, "
                   "OS, EDR Feasible, EDR Installed, Remarks", "ip", json.dumps(dict(config.INVENTORY_FIELDS)), now_iso(), now_iso()))


def standard_template_id(conn):
    r = conn.execute("SELECT id FROM templates WHERE name=?", (config.STANDARD_TEMPLATE,)).fetchone()
    return r[0] if r else None


def get_settings(conn=None):
    if conn is None:
        with get_conn() as c:
            return get_settings(c)
    s = dict(config.DEFAULT_SETTINGS)
    s.update({r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")})
    return s


def public_settings(conn=None):
    """Settings safe to send to the browser (secrets masked)."""
    s = get_settings(conn)
    for k in config.SECRET_SETTINGS:
        s[k] = ""
    return s


def set_settings(values: dict):
    with get_conn() as c:
        for k, v in values.items():
            if k in config.DEFAULT_SETTINGS:
                c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (k, str(v)))


def rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params)]


def one(conn, sql, params=()):
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def jloads(v, default=None):
    if not v:
        return default
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return default
