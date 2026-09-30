import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _env(name, default=""):
    return os.getenv(name, default).strip()


FALCON_CLIENT_ID = _env("FALCON_CLIENT_ID")
FALCON_CLIENT_SECRET = _env("FALCON_CLIENT_SECRET")
FALCON_BASE_URL = _env("FALCON_BASE_URL", "us-1")
FALCON_MEMBER_CID = _env("FALCON_MEMBER_CID")


# DEMO=1: sample data in its own database file (data/demo.db) - the real database is never touched; syncing is off
DEMO = _env("DEMO").lower() in ("1", "true", "yes")
DB_PATH = Path(_env("DB_PATH", "data/edr_assets.db"))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH
if DEMO:
    # always a separate file next to the real one (DB_PATH from .env / Docker must never receive sample data)
    DB_PATH = Path(_env("DEMO_DB_PATH") or DB_PATH.with_name("demo.db"))
    if not DB_PATH.is_absolute():
        DB_PATH = BASE_DIR / DB_PATH
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DB_PATH.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

APP_USERNAME = _env("APP_USERNAME")
APP_PASSWORD = _env("APP_PASSWORD")

# Defaults for settings editable from the UI (stored in the settings table).
DEFAULT_SETTINGS = {
    # MSP scorecard targets
    "target_coverage": "95", "target_offline_pct": "5", "target_scan_days": "30", "target_scan_coverage": "90",
    "target_max_critical": "0", "target_max_risk_critical": "0",
    # Host is online per Falcon but last_seen is older than this -> "stale online"
    "stale_online_hours": "1",
    # Falcon auto-removes hosts inactive for this many days (console setting)
    "auto_remove_days": "90",
    # IPs / prefixes (ending in *) that must never be treated as duplicates or reinstall evidence
    "dup_ip_exclude": "127.0.0.1, 0.0.0.0, 169.254.*, 192.168.0.1, 192.168.1.1, 10.0.2.15",
    # Fetch Falcon NIC (network address) history for changed hosts on each sync
    "fetch_nic_history": "1",
    # Hosts whose last_seen is older than this many days are flagged "inactive" in inventory verification
    "inventory_stale_days": "7",
    # Automatic sync interval in minutes (0 = manual only)
    "sync_interval_minutes": "60",
    # CrowdStrike API connection (entered in Settings; .env values are used when these are empty)
    "falcon_client_id": "",
    "falcon_client_secret": "",
    "falcon_base_url": "",
    "falcon_member_cid": "",
    # Days of CrowdStrike detections fetched on each sync (Alerts API)
    "detections_days": "30",
    # Red Hat Satellite (packages, errata / remediation, OpenSCAP MBSS compliance) - entered in Integrations
    "satellite_url": "",
    "satellite_user": "",
    "satellite_token": "",
    "satellite_verify_ssl": "1",
    # Splunk log-source presence (REST / management port) - entered in Integrations
    "splunk_url": "",
    "splunk_token": "",
    "splunk_index": "*",
    "splunk_days": "7",
    "splunk_verify_ssl": "1",
    # Seceon NDR webhook token (generated on the Integrations page)
    "seceon_webhook_token": "",
    # ServiceNow CMDB inventory source (planned) - entered in Inventory sources
    "servicenow_url": "",
    "servicenow_table": "cmdb_ci_server",
}
SECRET_SETTINGS = {"falcon_client_secret", "satellite_token", "splunk_token", "seceon_webhook_token"}

# Standard inventory template fields: key -> label
INVENTORY_FIELDS = [
    ("ip", "IP"),
    ("node_name", "Node Name"),
    ("msp", "MSP"),
    ("node_type", "Node Type"),
    ("domain", "Domain"),
    ("live", "Live/Non Live"),
    ("os", "OS"),
    ("edr_feasible", "EDR Feasible"),
    ("edr_installed", "EDR Installed"),
    ("remarks", "Remarks"),
    ("niam_integrated", "NIAM Integrated"),   # Yes / No; blank -> taken from the NIAM dump (IP match)
    ("ne_id", "NE ID"),                       # blank -> NE ID(s) of the IP in the NIAM dump
]
INVENTORY_FIELD_KEYS = [k for k, _ in INVENTORY_FIELDS]

# Built-in template: spreadsheet headers are exactly the standard field names above
STANDARD_TEMPLATE = "Standard"
