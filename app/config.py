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


DB_PATH = Path(_env("DB_PATH", "data/edr_assets.db"))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DB_PATH.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

APP_USERNAME = _env("APP_USERNAME")
APP_PASSWORD = _env("APP_PASSWORD")

# Defaults for settings editable from the UI (stored in the settings table).
DEFAULT_SETTINGS = {
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
}
SECRET_SETTINGS = {"falcon_client_secret"}

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
]
INVENTORY_FIELD_KEYS = [k for k, _ in INVENTORY_FIELDS]

# Built-in template: spreadsheet headers are exactly the standard field names above
STANDARD_TEMPLATE = "Standard"
