"""Internet intelligence for one public IP, in one place (Asset 360 → Internet scan, or any public IP searched in Asset 360):
  Shodan InternetDB  open ports, CVEs, software, hostnames (free, no key)            -> passive_results
  RIPEstat           advertised prefix, origin ASN, holder (free, no key)            -> ip_intel
  GreyNoise          seen scanning the internet / known benign service (free, no key) -> ip_intel
  VirusTotal         how many security vendors flag the IP, reputation, owner, country -> vt_results
                     (needs a free VirusTotal API key, entered under Integrations; free tier: 4 lookups / minute, 500 / day)
Only the IP address is sent to these services. Answers are cached; "refresh" asks again."""
import json

from fastapi import APIRouter, Body, HTTPException

from . import config, db

router = APIRouter()
VT_KEY = "virustotal_api_key"


def _vt_key():
    return (db.get_settings().get(VT_KEY) or "").strip()


def vt_lookup(ip):
    """(data dict, error) from VirusTotal v3 ip_addresses."""
    if config.DEMO:
        h = sum(int(x) for x in ip.split(".")) % 9
        return {"malicious": 2 if h == 4 else 0, "suspicious": 1 if h in (4, 6) else 0, "harmless": 60 + h, "undetected": 30 - h,
                "reputation": -5 if h == 4 else 0, "as_owner": "EXAMPLE-ENTERPRISE (sample)", "country": "IN", "network": f"{ip.rsplit('.', 1)[0]}.0/24",
                "last_analysis_date": None, "tags": []}, None
    key = _vt_key()
    if not key:
        return None, "no key"
    from .surface import _s
    r = _s().get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": key}, timeout=20)
    if r.status_code == 401:
        return None, "VirusTotal rejected the API key"
    if r.status_code == 429:
        return None, "VirusTotal quota reached (free key: 4 lookups a minute, 500 a day) — try again shortly"
    if r.status_code == 404:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "reputation": 0, "not_found": True}, None
    if not r.ok:
        return None, f"VirusTotal HTTP {r.status_code}"
    a = ((r.json() or {}).get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0),
            "undetected": st.get("undetected", 0), "reputation": a.get("reputation", 0), "as_owner": a.get("as_owner") or "",
            "country": a.get("country") or "", "network": a.get("network") or "", "last_analysis_date": a.get("last_analysis_date"),
            "tags": a.get("tags") or []}, None


def _passive(c, ip):
    r = db.one(c, "SELECT * FROM passive_results WHERE ip=?", (ip,))
    if r:
        for k in ("ports", "vulns", "cpes", "hostnames", "tags"):
            r[k] = db.jloads(r.get(k), []) or []
    return r


def ip_intel(ip, refresh=False):
    from .passive import scan_now
    from .registry import exposed_by_itself
    from .surface import enrich
    ip = db.canon_ip(ip)
    if not exposed_by_itself(ip):
        raise HTTPException(400, "Internet intelligence works on public IPv4 addresses")
    vt_err = None
    with db.get_conn() as c:
        if refresh or not _passive(c, ip):
            reg = db.one(c, "SELECT nat_of, name FROM asset_registry WHERE ip=?", (ip,)) or {}
            inner = (reg.get("nat_of") or "").split(", ")[0] or None
            scan_now(c, [(ip, inner, reg.get("name"))], source="asset 360")
        have = db.one(c, "SELECT ripe_at, gn_at FROM ip_intel WHERE ip=?", (ip,))
    if refresh or not have or not have["ripe_at"]:
        enrich([ip])
    with db.get_conn() as c:
        vt = db.one(c, "SELECT * FROM vt_results WHERE ip=?", (ip,))
    if refresh or not vt:
        data, vt_err = vt_lookup(ip)
        if data is not None:
            with db.get_conn() as c:
                c.execute("INSERT OR REPLACE INTO vt_results(ip, data, fetched_at) VALUES (?,?,?)", (ip, json.dumps(data), db.now_iso()))
    with db.get_conn() as c:
        pv = _passive(c, ip)
        it = db.one(c, "SELECT * FROM ip_intel WHERE ip=?", (ip,)) or {}
        vt = db.one(c, "SELECT * FROM vt_results WHERE ip=?", (ip,))
        asset = db.one(c, """SELECT ip, name, lobs, exposed, edr_status FROM asset_registry WHERE ip=? OR (', ' || public_ips || ', ') LIKE ?
                             ORDER BY name IS NULL, ip=? DESC LIMIT 1""", (ip, f"%, {ip}, %", ip))
    return {"ip": ip, "asset": asset, "internetdb": pv, "ripe": {k: it.get(k) for k in ("prefix", "asn", "holder", "ripe_at")},
            "greynoise": {k: it.get(k) for k in ("gn_noise", "gn_riot", "gn_class", "gn_name", "gn_message", "gn_last_seen", "gn_at")},
            "virustotal": ({**db.jloads(vt["data"], {}), "fetched_at": vt["fetched_at"]} if vt else None),
            "virustotal_error": vt_err if vt_err != "no key" else None, "virustotal_key": bool(_vt_key()) or config.DEMO, "demo": config.DEMO}


@router.get("/api/intel/ip")
def intel_ip(ip: str):
    """Everything the free internet sources say about one public IP (cached; looked up the first time)."""
    return ip_intel(ip)


@router.post("/api/intel/ip/refresh")
def intel_ip_refresh(data: dict = Body(...)):
    return ip_intel(str(data.get("ip") or ""), refresh=True)


@router.get("/api/intel/config")
def intel_config():
    with db.get_conn() as c:
        n = db.one(c, "SELECT COUNT(*) n, MAX(fetched_at) last FROM vt_results")
    return {"virustotal_key_set": bool(_vt_key()), "virustotal_lookups": n["n"] or 0, "virustotal_last": n["last"], "demo": config.DEMO}


@router.put("/api/intel/config")
def intel_config_save(data: dict = Body(...)):
    """VirusTotal API key (free account → API key). Stored like other secrets; never sent back to the browser."""
    if "virustotal_key" in data:
        key = str(data.get("virustotal_key") or "").strip()
        if key and (len(key) < 32 or not key.isalnum()):
            raise HTTPException(400, "That does not look like a VirusTotal API key (64 letters and digits)")
        db.set_settings({VT_KEY: key})
    return intel_config()


@router.post("/api/intel/test")
def intel_test():
    data, err = vt_lookup("8.8.8.8")
    if err == "no key":
        return {"ok": False, "detail": "Add a VirusTotal API key first"}
    return {"ok": data is not None, "detail": err or "VirusTotal answered (8.8.8.8)"}
