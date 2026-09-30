"""Seceon NDR (aiXDR / OTM) detections, shown per asset on Asset 360 next to CrowdStrike and Splunk detections.

Seceon does not publish its REST API openly, so alerts come in two ways that need nothing from Seceon's docs:
  * webhook: Seceon's alert notifications (it supports syslog / email / webhook) POST JSON to
        POST /api/seceon/webhook   header X-Webhook-Token: <token>   (or ?token=...)
    One alert object or a list. Common key names are recognised (see WEBHOOK_KEYS); everything else is kept as raw JSON.
  * upload: an alert export (Excel / CSV) through the Upload center, mapped like any other upload.
A REST pull can be added once Seceon's API documentation for your version is available (Integrations page)."""
import hashlib
import json
import re
import secrets

from fastapi import APIRouter, Body, HTTPException, Query, Request

from . import config, db, inventory

router = APIRouter()

FIELDS = [("alert_id", "Alert ID", False), ("created_at", "Time", True), ("severity", "Severity", False), ("name", "Alert Name", True),
          ("category", "Category / Tactic", False), ("src_ip", "Source IP", False), ("dst_ip", "Destination IP", False),
          ("host", "Host", False), ("description", "Description", False), ("status", "Status", False)]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "alert_id": ["alertid", "id", "incidentid", "alertno", "ticketid", "eventid"],
    "created_at": ["time", "timestamp", "createdat", "created", "detectedtime", "detectiontime", "eventtime", "date", "firstseen"],
    "severity": ["severity", "priority", "risk", "risklevel", "threatlevel"],
    "name": ["alertname", "name", "alert", "threat", "threatname", "title", "rule", "detection", "signature"],
    "category": ["category", "tactic", "type", "threattype", "alerttype", "killchain"],
    "src_ip": ["sourceip", "srcip", "src", "source", "attackerip", "clientip"],
    "dst_ip": ["destinationip", "dstip", "dst", "destination", "victimip", "targetip", "serverip"],
    "host": ["host", "hostname", "asset", "assetname", "device", "entity"],
    "description": ["description", "details", "message", "summary", "info"],
    "status": ["status", "state", "disposition"],
}
WEBHOOK_KEYS = {k: v for k, v in ALIASES.items()}
SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low", "info": "Informational",
       "informational": "Informational"}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def norm_sev(v):
    s = str(v or "").strip().lower()
    if s in SEV:
        return SEV[s]
    try:  # numeric scores: 0-10 or 0-100
        n = float(s)
        n = n / 10 if n > 10 else n
        return "Critical" if n >= 9 else "High" if n >= 7 else "Medium" if n >= 4 else "Low" if n > 0 else "Informational"
    except ValueError:
        return s.title() or "Medium"


def _row(d, now, source):
    rid = d.get("alert_id") or hashlib.sha1(json.dumps([d.get("created_at"), d.get("name"), d.get("src_ip"), d.get("dst_ip"), d.get("host")],
                                                       default=str).encode()).hexdigest()[:20]
    return (f"seceon:{rid}", db.parse_ts(d.get("created_at")) or now, norm_sev(d.get("severity")), str(d.get("name") or "")[:500],
            str(d.get("category") or "")[:200], db.canon_ip(d.get("src_ip") or ""), db.canon_ip(d.get("dst_ip") or ""),
            str(d.get("host") or "")[:200], str(d.get("description") or "")[:2000], str(d.get("status") or "")[:50], source,
            json.dumps(d.get("_raw") or {}, default=str)[:8000], now)


COLS = "id, created_at, severity, name, category, src_ip, dst_ip, host, description, status, source, raw, received_at"


def _store(c, rows):
    c.executemany(f"INSERT OR REPLACE INTO ndr_alerts({COLS}) VALUES ({','.join('?' * 13)})", rows)


# ------------------------------------------------------------------ upload (Excel / CSV export)
def suggest_mapping(headers):
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    from .filetemplates import custom_aliases
    custom = custom_aliases("ndr")
    for f in KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == alias), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def build(parsed, mapping):
    for k, _, req in FIELDS:
        if req and not mapping.get(k):
            raise ValueError(f"Map the {dict((a, b) for a, b, _ in FIELDS)[k]} column")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    out, warnings, skipped = [], [], 0
    for r in parsed["rows"]:
        d = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        if not d["name"] or not (d["src_ip"] or d["dst_ip"] or d["host"]):
            skipped += 1
            continue
        d["_raw"] = {h: r[i] for h, i in idx.items() if r[i]}
        out.append(d)
    if skipped:
        warnings.append(f"{skipped:,} rows skipped: no alert name, or no IP / host")
    return out, warnings


def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    rows, warnings = build(parsed, mapping)
    if not rows:
        raise ValueError("No alerts found with this mapping")
    return parsed, mapping, rows, warnings


@router.post("/api/ndr/parse")
def ndr_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/ndr/preview")
def ndr_preview(data: dict = Body(...)):
    try:
        _, _, rows, warnings = _load(data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    sev = {}
    for r in rows:
        s = norm_sev(r["severity"])
        sev[s] = sev.get(s, 0) + 1
    return {"stats": [["Alerts in file", len(rows), ""], *[[k, v, "crit" if k in ("Critical", "High") else ""] for k, v in sev.items()]],
            "warnings": warnings, "note": "Alerts are added to what is already stored (same Alert ID = updated).",
            "sample_cols": [["created_at", "Time"], ["severity", "Severity"], ["name", "Alert"], ["src_ip", "Source"], ["dst_ip", "Destination"], ["host", "Host"]],
            "sample": rows[:50]}


@router.post("/api/ndr/commit")
def ndr_commit(data: dict = Body(...)):
    try:
        parsed, _, rows, _ = _load(data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    now = db.now_iso()
    with db.get_conn() as c:
        _store(c, [_row(r, now, "upload:" + parsed["filename"]) for r in rows])
    return {"message": f"{len(rows):,} Seceon alerts loaded", "rows": len(rows)}


# ------------------------------------------------------------------ webhook (Seceon pushes alerts)
def _pick(obj, keys):
    flat = {}

    def walk(o, depth=0):
        if isinstance(o, dict) and depth < 3:
            for k, v in o.items():
                if isinstance(v, (dict, list)):
                    walk(v, depth + 1)
                else:
                    flat.setdefault(_norm(k), v)
    walk(obj)
    return next((flat[a] for a in keys if a in flat and flat[a] not in (None, "")), "")


@router.post("/api/seceon/webhook")
async def seceon_webhook(request: Request, token: str = Query("")):
    want = db.get_settings().get("seceon_webhook_token") or ""
    got = request.headers.get("x-webhook-token") or token
    if not want or not secrets.compare_digest(want, got or ""):
        raise HTTPException(401, "Invalid or missing webhook token")
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Body must be JSON (one alert object or a list)")
    items = body if isinstance(body, list) else (body.get("alerts") or body.get("data") or [body]) if isinstance(body, dict) else []
    now, rows = db.now_iso(), []
    for a in items[:5000]:
        if not isinstance(a, dict):
            continue
        d = {k: _pick(a, keys) for k, keys in WEBHOOK_KEYS.items()}
        d["_raw"] = a
        if d["name"] or d["src_ip"] or d["dst_ip"]:
            rows.append(_row(d, now, "webhook"))
    with db.get_conn() as c:
        _store(c, rows)
    return {"ok": True, "received": len(rows)}


@router.get("/api/seceon/config")
def seceon_config():
    with db.get_conn() as c:
        n = db.one(c, "SELECT COUNT(*) n, MAX(received_at) last, SUM(source='webhook') via_webhook FROM ndr_alerts")
    return {"token_set": bool(db.get_settings().get("seceon_webhook_token")), "alerts": n["n"] or 0, "last": n["last"],
            "via_webhook": n["via_webhook"] or 0, "path": "/api/seceon/webhook", "demo": config.DEMO}


@router.post("/api/seceon/token")
def seceon_new_token():
    """Generate (or rotate) the webhook token. Shown once, to paste into Seceon's webhook notification settings."""
    tok = secrets.token_urlsafe(32)
    db.set_settings({"seceon_webhook_token": tok})
    return {"token": tok}


# ------------------------------------------------------------------ per asset
@router.get("/api/asset/ndr")
def asset_ndr(ips: str = "", hosts: str = "", date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to")):
    from datetime import datetime, timedelta, timezone
    ip_l = [db.canon_ip(i) for i in ips.split(",") if i]
    hn_l = [db.norm_hostname(h) for h in hosts.split(",") if h]
    now = datetime.now(timezone.utc)
    d_from = date_from or (now - timedelta(days=7)).strftime("%Y-%m-%d")
    d_to = date_to or now.strftime("%Y-%m-%d")
    w, params = [], []
    if ip_l:
        ph = ",".join("?" * len(ip_l))
        w.append(f"(src_ip IN ({ph}) OR dst_ip IN ({ph}))")
        params += ip_l + ip_l
    if hn_l:
        w.append(f"LOWER(host) IN ({','.join('?' * len(hn_l))})")
        params += hn_l
    if not w:
        return {"rows": [], "counts": {}}
    with db.get_conn() as c:
        rows = db.rows(c, f"""SELECT id, created_at, severity, name, category, src_ip, dst_ip, host, description, status, source
                              FROM ndr_alerts WHERE ({' OR '.join(w)}) AND substr(created_at,1,10) BETWEEN ? AND ?
                              ORDER BY created_at DESC LIMIT 1000""", params + [d_from, d_to])
        any_data = c.execute("SELECT 1 FROM ndr_alerts LIMIT 1").fetchone() is not None
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        r["direction"] = "attacker" if r["src_ip"] in ip_l else "target" if r["dst_ip"] in ip_l else ""
    return {"rows": rows, "counts": counts, "from": d_from, "to": d_to, "configured": any_data or config.DEMO}
