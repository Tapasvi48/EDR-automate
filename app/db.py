import ipaddress
import json
import re
from functools import lru_cache
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
    source TEXT DEFAULT 'falcon',   -- falcon | import (old EDR inventory upload)
    import_id INTEGER,
    db_first_synced TEXT,
    db_last_synced TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS ix_hosts_ip ON hosts(local_ip);
CREATE INDEX IF NOT EXISTS ix_hosts_connip ON hosts(connection_ip);
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
    type_id INTEGER,                -- NULL = main LOB inventory, else lob_types.id
    scope_msp TEXT,                 -- set when the upload replaced only one MSP's rows
    warnings TEXT
);
-- version numbers run per inventory stream: the main inventory and each type have their own v1, v2, ...
CREATE UNIQUE INDEX IF NOT EXISTS ux_versions_stream ON inventory_versions(lob_id, COALESCE(type_id, 0), version_no);

-- Inventory types of a LOB (e.g. Servers, Network, Databases). Each type has its own inventory file and its own
-- version history; the LOB's current inventory is the main inventory plus the current version of every type.
CREATE TABLE IF NOT EXISTS lob_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    current_version_id INTEGER,
    created_at TEXT,
    UNIQUE (lob_id, name COLLATE NOCASE)
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
    file_dups INTEGER DEFAULT 0,    -- extra rows in the uploaded file with the same key (merged into this one)
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
    file_dups INTEGER DEFAULT 0,    -- extra rows in the uploaded file with the same key
    dup_ip INTEGER DEFAULT 0,       -- rows in this LOB sharing the IP (>1 = duplicate)
    dup_name INTEGER DEFAULT 0,     -- rows in this LOB sharing the node name (>1 = duplicate)
    type_id INTEGER,                -- inventory type the row belongs to (NULL = main inventory)
    PRIMARY KEY (lob_id, item_key)
);
CREATE INDEX IF NOT EXISTS ix_inv_aid ON inventory_current(matched_aid);
CREATE INDEX IF NOT EXISTS ix_inv_ip ON inventory_current(ip);
CREATE INDEX IF NOT EXISTS ix_inv_msp ON inventory_current(lob_id, msp_id);

-- ---------- Vulnerabilities (Nessus-style exports, per LOB) ----------
CREATE TABLE IF NOT EXISTS vuln_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    filename TEXT, note TEXT, uploaded_by TEXT, uploaded_at TEXT,
    scan_date TEXT,                 -- latest "Last Observed" in the file (else upload time)
    rows INTEGER, hosts INTEGER,
    new_findings INTEGER, fixed_findings INTEGER, reopened INTEGER, still_open INTEGER,
    mapping TEXT, warnings TEXT
);

-- One row per (LOB, IP, plugin, port, protocol). Status tracks open -> fixed across scans.
CREATE TABLE IF NOT EXISTS vuln_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lob_id INTEGER NOT NULL,
    finding_key TEXT NOT NULL,
    ip TEXT, ip_num INTEGER,
    plugin_id TEXT, name TEXT, severity TEXT, sev_rank INTEGER,
    protocol TEXT, port TEXT,
    synopsis TEXT, description TEXT, solution TEXT, plugin_text TEXT, see_also TEXT, cve TEXT,
    exploit_ease TEXT, first_discovered TEXT, last_observed TEXT, vuln_pub_date TEXT, patch_pub_date TEXT,
    remarks TEXT, extra TEXT,
    status TEXT NOT NULL DEFAULT 'open',   -- open | fixed
    first_scan_id INTEGER, last_scan_id INTEGER, fixed_scan_id INTEGER, fixed_at TEXT, reopened INTEGER DEFAULT 0,
    UNIQUE (lob_id, finding_key)
);
CREATE INDEX IF NOT EXISTS ix_vf_ip ON vuln_findings(ip);
CREATE INDEX IF NOT EXISTS ix_vf_lob ON vuln_findings(lob_id, status, sev_rank);
CREATE INDEX IF NOT EXISTS ix_vf_plugin ON vuln_findings(plugin_id);

-- Last scan that covered each IP of a LOB
CREATE TABLE IF NOT EXISTS vuln_scan_hosts (
    lob_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    scan_id INTEGER,
    scanned_at TEXT,
    PRIMARY KEY (lob_id, ip)
);

-- Every IP a LOB's scans covered, joined to inventory + EDR (rebuilt after scans, uploads and syncs)
CREATE TABLE IF NOT EXISTS vuln_assets (
    lob_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    ip_num INTEGER,
    last_scan_id INTEGER, last_scanned_at TEXT,
    crit INTEGER DEFAULT 0, high INTEGER DEFAULT 0, med INTEGER DEFAULT 0, low INTEGER DEFAULT 0, info INTEGER DEFAULT 0,
    fixed INTEGER DEFAULT 0,
    in_inventory INTEGER DEFAULT 0, item_key TEXT, node_name TEXT, msp TEXT, msp_id INTEGER, node_type TEXT, live TEXT,
    aid TEXT, hostname TEXT, edr_status TEXT,    -- Online | Offline | Hidden | Removed | Not Installed
    PRIMARY KEY (lob_id, ip)
);
CREATE INDEX IF NOT EXISTS ix_va_ip ON vuln_assets(ip);

-- Old EDR inventory imports (history of what was imported; the hosts themselves go into `hosts`)
CREATE TABLE IF NOT EXISTS edr_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT, note TEXT, uploaded_by TEXT, uploaded_at TEXT,
    rows INTEGER, added INTEGER, already_known INTEGER, live_now INTEGER, mapping TEXT
);

-- NIAM dump uploads (Host -> NE ID); each upload is a full snapshot
CREATE TABLE IF NOT EXISTS niam_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT, note TEXT, uploaded_by TEXT, uploaded_at TEXT,
    rows INTEGER, added INTEGER, removed INTEGER, changed INTEGER, mapping TEXT, warnings TEXT
);

-- One row per (NE ID, host). Nodes missing from a later dump stay with present=0. Match columns are rebuilt by niam.refresh().
CREATE TABLE IF NOT EXISTS niam_nodes (
    ne_id TEXT NOT NULL DEFAULT '',
    host_key TEXT NOT NULL,          -- canonical IP, or lower-case host when it is not an IP
    host TEXT, ip TEXT, ip_num INTEGER, hostname_norm TEXT, extra TEXT,
    upload_id INTEGER, first_upload_id INTEGER, first_seen_at TEXT, last_seen_at TEXT,
    present INTEGER NOT NULL DEFAULT 1, removed_at TEXT,
    in_inventory INTEGER DEFAULT 0, lobs TEXT, msps TEXT, node_name TEXT, node_type TEXT, inv_status TEXT,
    aid TEXT, hostname TEXT, edr_status TEXT, edr_last_seen TEXT,
    crit INTEGER DEFAULT 0, high INTEGER DEFAULT 0, med INTEGER DEFAULT 0, low INTEGER DEFAULT 0, last_scan TEXT,
    PRIMARY KEY (ne_id, host_key)
);
CREATE INDEX IF NOT EXISTS ix_niam_ip ON niam_nodes(ip);

-- One row per asset of a LOB (inventory node or scanned IP): risk score and scan age. Rebuilt by posture.refresh().
CREATE TABLE IF NOT EXISTS asset_risk (
    lob_id INTEGER NOT NULL,
    asset_key TEXT NOT NULL,          -- canonical IP, or name:<node> for inventory rows without an IP
    ip TEXT, ip_num INTEGER, item_key TEXT, node_name TEXT, node_type TEXT, msp TEXT, msp_id INTEGER, live TEXT,
    applicable INTEGER, in_inventory INTEGER, coverage_status TEXT,
    aid TEXT, hostname TEXT, edr_status TEXT, edr_last_seen TEXT,
    crit INTEGER, high INTEGER, med INTEGER, low INTEGER, exploitable INTEGER,
    last_scan TEXT, scan_age_days INTEGER, scan_bucket TEXT,    -- 0-30 | 31-60 | 61-90 | 90+ | never
    score INTEGER, level TEXT, factors TEXT,                     -- factors: JSON [[label, points], ...]
    PRIMARY KEY (lob_id, asset_key)
);
CREATE INDEX IF NOT EXISTS ix_risk_score ON asset_risk(score);
CREATE INDEX IF NOT EXISTS ix_risk_ip ON asset_risk(ip);

-- Every IP from every source (inventory, CrowdStrike, VA scans, NIAM), joined. Rebuilt by registry.refresh().
CREATE TABLE IF NOT EXISTS asset_registry (
    asset_key TEXT PRIMARY KEY, ip TEXT, ip_num INTEGER, name TEXT,
    lobs TEXT, lob_ids TEXT, msps TEXT, msp_ids TEXT, node_type TEXT, live TEXT, edr_applicable INTEGER,
    in_inventory INTEGER, in_edr INTEGER, in_scan INTEGER, in_niam INTEGER,
    edr_status TEXT, edr_detail TEXT, aid TEXT, cs_hostname TEXT, edr_last_seen TEXT,
    last_scan TEXT, crit INTEGER, high INTEGER, med INTEGER, low INTEGER, ne_ids TEXT,
    exposed INTEGER, exposure TEXT, exposure_src TEXT, public_ips TEXT, nat_of TEXT, is_public INTEGER, sources TEXT,
    os TEXT, os_source TEXT, feasibility TEXT, feasibility_reason TEXT, whitelisted INTEGER DEFAULT 0, cgnat INTEGER DEFAULT 0
);

-- Falcon sensor builds per platform with their N / N-1 / N-2 tag (Sensor update policies API), replaced on each fetch
CREATE TABLE IF NOT EXISTS sensor_builds (
    platform TEXT, sensor_version TEXT, build TEXT, tag TEXT, stage TEXT, fetched_at TEXT
);
-- Linux distributions / versions CrowdStrike supports, summarised from the supported-kernel list
CREATE TABLE IF NOT EXISTS linux_support (
    distro TEXT, version TEXT, kernels INTEGER, newest_sensor TEXT, oldest_sensor TEXT, n2_supported INTEGER, fetched_at TEXT,
    PRIMARY KEY (distro, version)
);

-- Feasibility sheet decisions: Node Type + OS pairs you set to Yes / No (only where it differs from the automatic decision)
CREATE TABLE IF NOT EXISTS feasibility_sheet (
    node_type TEXT NOT NULL, os_key TEXT NOT NULL, node_type_label TEXT, os_label TEXT, feasible TEXT NOT NULL, remarks TEXT, set_at TEXT,
    PRIMARY KEY (node_type, os_key)
);

-- Feasibility sheet decisions per LOB (lob_id 0 = every LOB): Node Type + OS pairs set to Yes / No where they differ
-- from the automatic decision
CREATE TABLE IF NOT EXISTS feasibility_pairs (
    lob_id INTEGER NOT NULL DEFAULT 0, node_type TEXT NOT NULL, os_key TEXT NOT NULL, node_type_label TEXT, os_label TEXT,
    feasible TEXT NOT NULL, remarks TEXT, set_at TEXT,
    PRIMARY KEY (lob_id, node_type, os_key)
);

-- Possible inventory <-> CrowdStrike matches for review (NIC IP + near hostname). Not counted anywhere.
CREATE TABLE IF NOT EXISTS match_candidates (
    lob_id INTEGER, item_key TEXT, ip TEXT, node_name TEXT, aid TEXT, cs_hostname TEXT, reason TEXT, found_at TEXT
);

-- CrowdStrike detections (Alerts API), the last N days; shown per asset on Asset 360
CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY, aid TEXT, hostname TEXT, severity TEXT, name TEXT, tactic TEXT, technique TEXT, status TEXT,
    created_at TEXT, description TEXT, filename TEXT, cmdline TEXT, disposition TEXT, product TEXT, fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_det_aid ON detections(aid, created_at);

-- Red Hat Satellite hosts (packages, errata, OpenSCAP / MBSS compliance) and their applicable errata; replaced on each sync
CREATE TABLE IF NOT EXISTS satellite_hosts (
    host_id INTEGER PRIMARY KEY, name TEXT, name_norm TEXT, ip TEXT, os TEXT, last_checkin TEXT, subscription TEXT,
    packages INTEGER, upgradable INTEGER, errata_security INTEGER, errata_bugfix INTEGER, errata_enhancement INTEGER,
    installable_security INTEGER, installable_total INTEGER, compliance_policy TEXT, compliance_passed INTEGER,
    compliance_failed INTEGER, compliance_other INTEGER, compliance_at TEXT, fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_sat_ip ON satellite_hosts(ip);
CREATE INDEX IF NOT EXISTS ix_sat_name ON satellite_hosts(name_norm);
CREATE TABLE IF NOT EXISTS satellite_errata (
    host_id INTEGER, errata_id TEXT, title TEXT, type TEXT, severity TEXT, issued TEXT, cves TEXT, installable INTEGER
);
CREATE INDEX IF NOT EXISTS ix_sate_host ON satellite_errata(host_id);
-- failed MBSS / OpenSCAP rules of each host's latest compliance report
CREATE TABLE IF NOT EXISTS satellite_mbss (
    host_id INTEGER, rule_id TEXT, title TEXT, severity TEXT, result TEXT, control TEXT, fix TEXT
);
CREATE INDEX IF NOT EXISTS ix_satm_host ON satellite_mbss(host_id);

-- CrowdStrike Spotlight: open vulnerabilities the agent itself reports
CREATE TABLE IF NOT EXISTS spotlight_vulns (
    id TEXT PRIMARY KEY, aid TEXT, hostname TEXT, ip TEXT, cve TEXT, severity TEXT, score REAL, exprt TEXT, exploit_status TEXT,
    product TEXT, remediation TEXT, status TEXT, created_at TEXT, updated_at TEXT, fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_spot_aid ON spotlight_vulns(aid);
-- CrowdStrike prevention policies (names for the policy id on each device record)
CREATE TABLE IF NOT EXISTS prevention_policies (
    id TEXT PRIMARY KEY, name TEXT, platform TEXT, enabled INTEGER, description TEXT, modified_at TEXT
);

-- Seceon NDR alerts (webhook push or uploaded export)
CREATE TABLE IF NOT EXISTS ndr_alerts (
    id TEXT PRIMARY KEY, created_at TEXT, severity TEXT, name TEXT, category TEXT, src_ip TEXT, dst_ip TEXT, host TEXT,
    description TEXT, status TEXT, source TEXT, raw TEXT, received_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_ndr_src ON ndr_alerts(src_ip);
CREATE INDEX IF NOT EXISTS ix_ndr_dst ON ndr_alerts(dst_ip);

-- Manual EDR feasibility decisions for inventory nodes (win over the feasibility rules)
CREATE TABLE IF NOT EXISTS feasibility_overrides (
    lob_id INTEGER NOT NULL, item_key TEXT NOT NULL, feasible TEXT NOT NULL, note TEXT, set_at TEXT,
    PRIMARY KEY (lob_id, item_key)
);
CREATE INDEX IF NOT EXISTS ix_reg_ip ON asset_registry(ip_num);
CREATE INDEX IF NOT EXISTS ix_reg_aid ON asset_registry(aid);
CREATE INDEX IF NOT EXISTS ix_reg_ipt ON asset_registry(ip);

-- Vulnerability exceptions (SOD). The uploaded sheet is the full register; each upload replaces it.
CREATE TABLE IF NOT EXISTS vuln_exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exception_id TEXT, scope TEXT, target TEXT, lob TEXT, plugin_id TEXT, cve TEXT, name TEXT, port TEXT,
    justification TEXT, control TEXT, approved_by TEXT, approval_date TEXT, valid_till TEXT, ticket TEXT, remarks TEXT,
    upload_id INTEGER, matched INTEGER DEFAULT 0, created_at TEXT
);
CREATE TABLE IF NOT EXISTS sod_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, note TEXT, uploaded_by TEXT, uploaded_at TEXT,
    rows INTEGER, added INTEGER, removed INTEGER, mapping TEXT, warnings TEXT
);

-- Communication matrix (firewall / NAT flows). The uploaded sheet is the full matrix; each upload replaces it.
CREATE TABLE IF NOT EXISTS comm_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT, direction TEXT, src_zone TEXT, src TEXT, src_nat TEXT, isp TEXT, firewall TEXT, fw_rule TEXT, dst_zone TEXT,
    dst_nat TEXT, dst TEXT, protocol TEXT, ports TEXT, service TEXT, action TEXT, cr TEXT, valid_till TEXT, remarks TEXT,
    inbound_internet INTEGER DEFAULT 0, upload_id INTEGER
);
CREATE TABLE IF NOT EXISTS comm_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, note TEXT, uploaded_by TEXT, uploaded_at TEXT,
    rows INTEGER, replaced INTEGER, mapping TEXT, warnings TEXT
);

-- Manual "internet-facing" decisions on matrix rows, kept across re-uploads of the same workbook / sheet / row
CREATE TABLE IF NOT EXISTS comm_overrides (
    workbook TEXT NOT NULL DEFAULT '', sheet TEXT NOT NULL DEFAULT '', rule_id TEXT NOT NULL, inbound INTEGER NOT NULL, note TEXT, set_at TEXT,
    PRIMARY KEY (workbook, sheet, rule_id)
);

-- Daily per-MSP snapshot for scorecard trends (msp_id 0 = unassigned)
CREATE TABLE IF NOT EXISTS msp_daily (
    day TEXT NOT NULL, lob_id INTEGER NOT NULL, msp_id INTEGER NOT NULL,
    nodes INTEGER, applicable INTEGER, installed INTEGER, online INTEGER, offline INTEGER, pending INTEGER, coverage REAL,
    crit INTEGER, high INTEGER, crit_high_no_edr INTEGER, live_nodes INTEGER, scanned_recent INTEGER, never_scanned INTEGER,
    risk_critical INTEGER, risk_high INTEGER,
    PRIMARY KEY (day, lob_id, msp_id)
);
"""

# NIAM dump: Host (IP) -> NE ID. Full snapshot per upload; nodes missing from a later dump keep present=0.
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
    ("inventory_rows", "file_dups", "INTEGER DEFAULT 0"),
    ("inventory_versions", "type_id", "INTEGER"),
    ("inventory_current", "type_id", "INTEGER"),
    ("inventory_current", "file_dups", "INTEGER DEFAULT 0"),
    ("inventory_current", "dup_ip", "INTEGER DEFAULT 0"),
    ("inventory_current", "dup_name", "INTEGER DEFAULT 0"),
    ("hosts", "source", "TEXT DEFAULT 'falcon'"),     # falcon | import (old EDR inventory)
    ("hosts", "import_id", "INTEGER"),
    ("vuln_findings", "exception_ref", "TEXT"),        # SOD exception that accepted this finding
    ("hosts", "gone_primary", "INTEGER DEFAULT 0"),   # representative agent of a device in EDR history
    ("hosts", "gone_group", "INTEGER"),               # agents of that device (duplicates merged)
    ("hosts", "gone_source", "TEXT"),                 # console (removed, seen by sync) | import (old EDR upload only)
    ("inventory_current", "feasible", "TEXT"),        # EDR feasibility decided by the rules / manual override: Yes | No
    ("inventory_current", "feasible_reason", "TEXT"),
    ("inventory_current", "os_resolved", "TEXT"),     # OS from Falcon, else the inventory OS column, else the VA scan
    ("inventory_current", "os_source", "TEXT"),       # edr | inventory | scan
    ("inventory_current", "os_support", "TEXT"),      # Supported | Legacy | Not supported (OS support catalog), NULL = unknown
    ("vuln_findings", "os", "TEXT"),                  # Operating System column of the scan export, if any
    ("asset_registry", "os", "TEXT"),
    ("asset_registry", "os_source", "TEXT"),
    ("asset_registry", "feasibility", "TEXT"),        # Yes | No | Unidentified
    ("asset_registry", "feasibility_reason", "TEXT"),
    ("asset_registry", "whitelisted", "INTEGER DEFAULT 0"),  # IP / public IP on the exposure whitelist
    ("asset_registry", "cgnat", "INTEGER DEFAULT 0"),        # IP / public IP in 100.64.0.0/10
    ("detections", "assigned_to", "TEXT"),            # analyst the alert is assigned to (Alerts API assigned_to_name)
    ("detections", "updated_at", "TEXT"),             # last status change; closed alerts: time to close
    # communication matrix workbooks: several sheets of different types, each row keeps its workbook / sheet
    ("comm_rules", "name", "TEXT"), ("comm_rules", "application", "TEXT"), ("comm_rules", "app_owner", "TEXT"),
    ("comm_rules", "lob", "TEXT"), ("comm_rules", "domain", "TEXT"), ("comm_rules", "msp", "TEXT"), ("comm_rules", "location", "TEXT"),
    ("comm_rules", "workbook", "TEXT"), ("comm_rules", "sheet", "TEXT"), ("comm_rules", "sheet_type", "TEXT"),
    ("comm_uploads", "sheets", "TEXT"),               # JSON: [{sheet, type, rows}]
    ("comm_rules", "inbound_auto", "INTEGER"),        # internet-facing as computed from the row; inbound_internet may be a manual override
]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
    "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%d-%m-%Y",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%b %d, %Y %H:%M:%S", "%b %d, %Y %I:%M:%S %p",
    "%b %d, %Y", "%d %b %Y %H:%M:%S", "%d %b %Y", "%d-%b-%Y", "%B %d, %Y",
]


_ISO_DAY = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?(?:\.\d+)?Z?$")


def parse_ts(v):
    """Best-effort parse of export timestamps (Nessus, CrowdStrike, Excel) -> ISO UTC string, or '' if unknown.
    Memoised: scan exports repeat the same few dates on tens of thousands of rows."""
    return _parse_ts(str(v or "").strip())


@lru_cache(maxsize=100_000)
def _parse_ts(s):
    m = _ISO_DAY.match(s)  # fast path for the common 2026-09-20 / 2026-09-20 10:15[:30] forms
    if m and 1 <= int(m.group(2)) <= 12 and 1 <= int(m.group(3)) <= 31 and int(m.group(4) or 0) < 24:
        y, mo, d, hh, mi, ss = m.groups()
        return f"{y}-{mo}-{d}T{hh or '00'}:{mi or '00'}:{ss or '00'}Z"
    if not s or s in ("-", "N/A", "n/a"):
        return ""
    s = s.replace(" UTC", "").replace(" GMT", "").replace("+00:00", "Z")
    for f in _TS_FORMATS:
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


_V4_PORT = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?")
_BR_V6 = re.compile(r"\[([0-9A-Fa-f:.%\w]+)\](?::\d{1,5})?")


def _parse_ip(tok):
    """One token -> canonical IP string or None. Handles IPv4 (leading zeros, :port, /prefix),
    IPv6 (any case / compression, [addr]:port, %zone, /prefix) and IPv4-mapped IPv6."""
    t = str(tok or "").strip().strip("\"'()<>")
    if not t:
        return None
    m = _BR_V6.fullmatch(t)
    if m:
        t = m.group(1)
    t = t.split("%", 1)[0].split("/", 1)[0]
    m = _V4_PORT.fullmatch(t)
    if m:
        parts = [int(x) for x in m.group(1).split(".")]
        return ".".join(map(str, parts)) if all(p <= 255 for p in parts) else None
    if ":" not in t:
        return None
    try:
        a = ipaddress.ip_address(t)
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        return str(a.ipv4_mapped)
    return a.compressed.lower()


def canon_ip(v):
    """Canonical form used for every IP stored or compared, so 010.001.001.005 == 10.1.1.5 and
    2001:DB8:0:0::1 == 2001:db8::1. Cells holding several IPs ("10.1.1.1, 10.1.1.2" / "10.1.1.1 eth0")
    give the first one; values that are not IPs come back trimmed and unchanged."""
    return _canon_ip(str(v or "").strip())


@lru_cache(maxsize=200_000)
def _canon_ip(s):
    if not s:
        return ""
    ip = _parse_ip(s)
    if ip:
        return ip
    for tok in re.split(r"[\s,;|]+", s):
        ip = _parse_ip(tok)
        if ip:
            return ip
    return s


def is_ip(v):
    return _parse_ip(v) is not None


def all_ips(v):
    """Every IP in a cell, canonical, in order."""
    out = []
    for tok in re.split(r"[\s,;|]+", str(v or "")):
        ip = _parse_ip(tok)
        if ip and ip not in out:
            out.append(ip)
    return out


def ip_to_num(ip):
    """Integer for IPv4 (used for fast range queries). IPv6 has no number column; ranges use ip_in()."""
    ip = _parse_ip(ip)
    if not ip or ":" in ip:
        return None
    return int(ipaddress.IPv4Address(ip))


def parse_net(text):
    """'10.1.0.0/16', '2001:db8::/32', a single IP, or an IPv4 prefix like '10.1.' / '10.1' -> ip_network or None."""
    t = str(text or "").strip()
    if not t:
        return None
    if "/" in t:
        try:
            return ipaddress.ip_network(t.split("/")[0].strip("[]") + "/" + t.split("/")[1], strict=False)
        except ValueError:
            return None
    m = re.fullmatch(r"(\d{1,3})(?:\.(\d{1,3}))?(?:\.(\d{1,3}))?\.?", t)
    if m:
        octs = [int(x) for x in m.groups() if x is not None]
        if all(o <= 255 for o in octs):
            return ipaddress.ip_network(".".join(map(str, octs + [0] * (4 - len(octs)))) + f"/{8 * len(octs)}")
    return None


def is_range_query(text):
    """CIDR ('10.1.0.0/16', '2001:db8::/48') or IPv4 prefix ('10.1.'). A plain IP is not a range."""
    t = str(text or "").strip()
    if not t:
        return False
    if "/" in t:
        return parse_net(t) is not None
    return not is_ip(t) and parse_net(t) is not None


_NET_CACHE = {}


def ip_in(ip, net):
    """SQLite function ip_in(ip, 'cidr'): works for IPv4 and IPv6."""
    if not ip or not net:
        return 0
    n = _NET_CACHE.get(net)
    if n is None:
        n = _NET_CACHE[net] = parse_net(net) or False
        if len(_NET_CACHE) > 500:
            _NET_CACHE.clear()
    if not n:
        return 0
    try:
        return 1 if ipaddress.ip_address(ip) in n else 0
    except ValueError:
        return 0


def norm_hostname(name):
    if not name:
        return ""
    n = str(name).strip().lower()
    # FQDN -> short name, but keep plain IP-looking values intact
    if "." in n and not is_ip(n):
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
    conn.create_function("ip_in", 2, ip_in, deterministic=True)
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
        # older databases numbered versions per LOB (UNIQUE lob_id, version_no); rebuild the table so each
        # inventory type can have its own version numbers
        old = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='inventory_versions'").fetchone()
        rebuild = bool(old and "UNIQUE (lob_id, version_no)" in old[0])
        if rebuild:
            c.execute("ALTER TABLE inventory_versions RENAME TO _inventory_versions_old")
        c.executescript(SCHEMA)
        for table, col, typ in MIGRATIONS:  # fresh databases: tables were just created without the later columns
            if col not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        if rebuild:
            cols = [r[1] for r in c.execute("PRAGMA table_info(_inventory_versions_old)")]
            new_cols = {r[1] for r in c.execute("PRAGMA table_info(inventory_versions)")}
            keep = ", ".join(x for x in cols if x in new_cols)
            c.execute(f"INSERT INTO inventory_versions({keep}) SELECT {keep} FROM _inventory_versions_old")
            c.execute("DROP TABLE _inventory_versions_old")
        if c.execute("SELECT 1 FROM feasibility_sheet LIMIT 1").fetchone():  # first sheet format: decisions for every LOB
            c.execute("""INSERT OR IGNORE INTO feasibility_pairs(lob_id, node_type, os_key, node_type_label, os_label, feasible, remarks, set_at)
                         SELECT 0, node_type, os_key, node_type_label, os_label, feasible, remarks, set_at FROM feasibility_sheet""")
            c.execute("DELETE FROM feasibility_sheet")
        for k, v in config.DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
        if not c.execute("SELECT 1 FROM settings WHERE key='ip_canon_v1'").fetchone():
            if canonicalize_ips(c):
                c.execute("DELETE FROM settings WHERE key='match_rev'")  # recompute matches on startup
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('ip_canon_v1', '1')")
        c.execute("""INSERT OR IGNORE INTO templates(name, description, key_field, mapping, created_at, updated_at)
                     VALUES (?,?,?,?,?,?)""",
                  (config.STANDARD_TEMPLATE, "Default inventory layout: IP, Node Name, MSP, Node Type, Domain, Live/Non Live, "
                   "OS, EDR Feasible, EDR Installed, Remarks", "ip", json.dumps(dict(config.INVENTORY_FIELDS)), now_iso(), now_iso()))


# (table, ip column, ip number column or None)
IP_COLUMNS = [("hosts", "local_ip", "local_ip_num"), ("hosts", "external_ip", None), ("hosts", "connection_ip", None),
              ("ip_history", "ip", "ip_num"), ("inventory_current", "ip", None), ("inventory_rows", "ip", None),
              ("vuln_findings", "ip", "ip_num"), ("vuln_scan_hosts", "ip", None), ("niam_nodes", "ip", "ip_num")]


def canonicalize_ips(c):
    """One-time rewrite of stored IPs into canon_ip() form (IPv4 leading zeros, IPv6 case/compression,
    IPv4-mapped IPv6). Returns the number of values changed."""
    changed = 0
    for table, col, num in IP_COLUMNS:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
            continue
        fix = []
        for r in c.execute(f"SELECT rowid, {col} FROM {table} WHERE {col} IS NOT NULL AND {col}<>''"):
            v = canon_ip(r[1])
            if v != r[1]:
                fix.append((v, ip_to_num(v), r[0]) if num else (v, r[0]))
        if fix:
            sql = f"UPDATE OR IGNORE {table} SET {col}=?{f', {num}=?' if num else ''} WHERE rowid=?"
            c.executemany(sql, fix)
            changed += len(fix)
    return changed


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
