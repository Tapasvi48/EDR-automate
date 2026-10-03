"""Old EDR inventory imports: agents that once reported to Falcon but are no longer in the console.

Imported agents are stored in `hosts` as console_state='removed', removal_type='imported', source='import', so every
view (IP search, inventory matching, vulnerability matching, EDR history) treats them like any other removed agent.
If an imported agent later shows up in the live console, the next sync restores it (source -> falcon)."""
import hashlib
import json
import re

from fastapi import APIRouter, Body

from . import db, inventory, sync

router = APIRouter()

FIELDS = [
    ("aid", "Agent ID (AID)", False), ("hostname", "Hostname", False), ("local_ip", "Local IP", False),
    ("external_ip", "External IP", False), ("mac_address", "MAC Address", False), ("platform_name", "Platform", False),
    ("os_version", "OS Version", False), ("agent_version", "Sensor Version", False), ("product_type_desc", "Host Type", False),
    ("machine_domain", "Domain", False), ("site_name", "Site", False), ("ou", "OU", False),
    ("system_manufacturer", "Manufacturer", False), ("system_product_name", "Model", False),
    ("serial_number", "Serial Number", False), ("last_login_user", "Last Login User", False), ("tags", "Tags", False),
    ("first_seen", "First Seen", False), ("last_seen", "Last Seen", False),
]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "aid": ["aid", "agentid", "hostid", "deviceid", "sensorid", "falconid"],
    "hostname": ["hostname", "host", "computername", "devicename", "name", "hostnames"],
    "local_ip": ["localip", "ip", "ipaddress", "localipaddress", "internalip"],
    "external_ip": ["externalip", "publicip"],
    "mac_address": ["macaddress", "mac"],
    "platform_name": ["platform", "platformname", "osfamily"],
    "os_version": ["osversion", "os", "operatingsystem", "osname"],
    "agent_version": ["sensorversion", "agentversion", "version", "sensor"],
    "product_type_desc": ["type", "hosttype", "producttype", "producttypedesc"],
    "machine_domain": ["domain", "machinedomain", "addomain"],
    "site_name": ["site", "sitename"],
    "ou": ["ou", "organizationalunit"],
    "system_manufacturer": ["manufacturer", "systemmanufacturer", "vendor"],
    "system_product_name": ["model", "systemproductname", "product"],
    "serial_number": ["serialnumber", "serial"],
    "last_login_user": ["lastloginuser", "lastuser", "user", "lastloggedinuser"],
    "tags": ["tags", "sensortags", "groupingtags"],
    "first_seen": ["firstseen", "firstseenutc", "installed", "installdate"],
    "last_seen": ["lastseen", "lastseenutc", "lastcheckin", "lastcontact"],
}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    from .filetemplates import custom_aliases
    custom = custom_aliases("old_edr")
    for f in KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == alias), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def build(parsed, mapping):
    if not any(mapping.get(k) for k in ("aid", "hostname", "local_ip")):
        raise ValueError("Map at least one of: Agent ID, Hostname or Local IP")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    mapped = set(v for v in mapping.values() if v)
    out, seen = [], set()
    for r in parsed["rows"]:
        h = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        h["local_ip"] = inventory.norm_ip(h["local_ip"]) if h["local_ip"] else ""
        h["aid"] = re.sub(r"[^0-9a-f]", "", h["aid"].lower()) if h["aid"] else ""
        if not (h["aid"] or h["hostname"] or h["local_ip"]):
            continue
        if not h["aid"]:
            # no agent ID in the export: stable synthetic ID from hostname + IP
            h["aid"] = "import-" + hashlib.sha1(f"{db.norm_hostname(h['hostname'])}|{h['local_ip']}".encode()).hexdigest()[:24]
        if h["aid"] in seen:
            continue
        seen.add(h["aid"])
        h["first_seen"] = db.parse_ts(h["first_seen"])
        h["last_seen"] = db.parse_ts(h["last_seen"])
        h["_raw"] = {hd: r[idx[hd]] for hd in parsed["headers"] if r[idx[hd]] and hd not in mapped} | \
                    {mapping[k]: h[k] for k in KEYS if mapping.get(k)}
        out.append(h)
    return out


def classify(c, rows):
    known = {r["aid"]: r["console_state"] for r in c.execute("SELECT aid, console_state FROM hosts")}
    active_hn = {r[0] for r in c.execute("SELECT hostname_norm FROM hosts WHERE console_state='active' AND hostname_norm<>''")}
    active_ip = {r[0] for r in c.execute("SELECT connection_ip FROM hosts WHERE console_state='active' AND connection_ip<>''")}
    res = {"new": [], "live_now": [], "known": [], "reinstalled": 0}
    for h in rows:
        st = known.get(h["aid"])
        if st == "active":
            res["live_now"].append(h)
        elif st:
            res["known"].append(h)
        else:
            res["new"].append(h)
            if db.norm_hostname(h["hostname"]) in active_hn or (h["local_ip"] and h["local_ip"] in active_ip):
                res["reinstalled"] += 1
    return res


def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    rows = build(parsed, mapping)
    if not rows:
        raise ValueError("No agents found with this mapping")
    return parsed, mapping, rows


@router.post("/api/edr-import/parse")
def edr_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/edr-import/preview")
def edr_preview(data: dict = Body(...)):
    _, _, rows = _load(data)
    with db.get_conn() as c:
        r = classify(c, rows)
    return {"rows": len(rows), "new": len(r["new"]), "live_now": len(r["live_now"]), "known": len(r["known"]),
            "reinstalled": r["reinstalled"],
            "sample": [{k: h[k] for k in ("aid", "hostname", "local_ip", "os_version", "last_seen")} for h in r["new"][:50]]}


@router.post("/api/edr-import/commit")
def edr_commit(data: dict = Body(...)):
    parsed, mapping, rows = _load(data)
    now = db.now_iso()
    with db.get_conn() as c:
        r = classify(c, rows)
        iid = c.execute("""INSERT INTO edr_imports(filename, note, uploaded_by, uploaded_at, rows, added, already_known, live_now, mapping)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (parsed["filename"], data.get("note", ""), data.get("uploaded_by", ""), now, len(rows), len(r["new"]),
                         len(r["known"]), len(r["live_now"]), json.dumps(mapping))).lastrowid
        cols = [k for k in KEYS if k != "aid"]
        c.executemany(
            f"""INSERT INTO hosts(aid, {', '.join(cols)}, hostname_norm, local_ip_num, console_state, removal_type, removed_at,
                source, import_id, is_primary, raw, db_first_synced, db_last_synced)
                VALUES (?,{','.join('?' * len(cols))},?,?,'removed','imported',?,'import',?,1,?,?,?)""",
            [(h["aid"], *[h[k] for k in cols], db.norm_hostname(h["hostname"]), db.ip_to_num(h["local_ip"]),
              h["last_seen"] or now, iid, json.dumps(h["_raw"], default=str), now, now) for h in r["new"]])
        db.move_raw(c)
        # an old EDR export has one IP per device: it is the device's connection IP (how CrowdStrike assets are identified)
        c.execute("""UPDATE hosts SET connection_ip=local_ip, connection_ip_num=local_ip_num
                     WHERE import_id=? AND COALESCE(connection_ip,'')='' AND COALESCE(local_ip,'')<>''""", (iid,))
        c.executemany("""INSERT OR IGNORE INTO ip_history(aid, ip, ip_num, mac, kind, source, first_seen, last_seen)
                         VALUES (?,?,?,?,'local','import',?,?)""",
                      [(h["aid"], h["local_ip"], db.ip_to_num(h["local_ip"]), h["mac_address"], h["first_seen"] or h["last_seen"] or now,
                        h["last_seen"] or now) for h in r["new"] if h["local_ip"]])
        c.executemany("INSERT INTO host_events(aid, ts, event, details) VALUES (?,?,?,?)",
                      [(h["aid"], now, "imported", json.dumps({"file": parsed["filename"], "last_seen": h["last_seen"]})) for h in r["new"]])
        settings = db.get_settings(c)
        sync.detect_reinstalls(c, settings)
        inventory.refresh_soon(c)
    return {"import_id": iid, "rows": len(rows), "added": len(r["new"]), "live_now": len(r["live_now"]), "known": len(r["known"]),
            "reinstalled": r["reinstalled"]}


@router.get("/api/edr-import/history")
def edr_import_history():
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT * FROM edr_imports ORDER BY id DESC")}


@router.get("/api/edr-history/summary")
def edr_history_summary():
    """Devices (not agent IDs) that left the console: removed as seen by our syncs, or known only from an old EDR upload."""
    from .queries import removed_devices
    with db.get_conn() as c:
        return removed_devices(c)
