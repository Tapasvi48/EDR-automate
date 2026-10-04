"""IOC check: is an IP, domain, URL or file hash known bad, and have we seen it?

For each value (up to 50, pasted or from Asset 360):
  CrowdStrike threat intel    Intel indicators API (QueryIntelIndicatorEntities): malicious confidence, labels, actors, malware families
  Custom IOCs                 IOC Management API (indicator_combined_v1): is it already blocked / detected in the tenant
                              Both go straight to the CrowdStrike API with the sync's credentials (FalconPy) — Falcon MCP is not
                              needed; it is only used when the console has no API credentials but a remote MCP server is configured.
  Seen in our data            detections (file, command line, raw record), asset registry (is it one of ours?), NDR alerts,
                              enterprise / non-enterprise mark
  Public IPs                  WHOIS (RDAP), Shodan InternetDB ports, GreyNoise, VirusTotal (with a key)
One verdict per value: Malicious · Suspicious · Ours · Seen internally · Not known. Every check is saved (ioc_checks) as
team memory and shown on the next check of the same value."""
import json
import re
import time

from fastapi import APIRouter, Body, HTTPException

from . import config, db

router = APIRouter()
RX = {"sha256": re.compile(r"^[a-f0-9]{64}$"), "sha1": re.compile(r"^[a-f0-9]{40}$"), "md5": re.compile(r"^[a-f0-9]{32}$"),
      "ipv4": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"), "url": re.compile(r"^https?://", re.I),
      "domain": re.compile(r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")}


def kind_of(v):
    v = v.strip().lower()
    for k in ("sha256", "sha1", "md5", "ipv4", "url", "domain"):
        if RX[k].match(v):
            return k
    return None


def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS ioc_checks (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, value TEXT, kind TEXT, verdict TEXT,
                 detail TEXT)""")


MCP_TOOL = {"QueryIntelIndicatorEntities": "falcon_search_indicators", "indicator_combined_v1": "falcon_search_iocs"}


def _live(operation, params, how):
    """One CrowdStrike lookup: the direct API (or sample data), else Falcon MCP. Returns (results, error)."""
    from . import cs_api
    try:
        if how in ("direct", "sample"):
            body = cs_api.call(operation, "CrowdStrike intel" if "Intel" in operation else "Custom IOCs", parameters=params)
            return body.get("resources") or [], None
        if how == "mcp":
            from . import falconmcp
            r = falconmcp.call(MCP_TOOL[operation], params, user="ioc-check")
            if not r["ok"]:
                return None, (r["error"] or "")[:200]
            d = r["data"] if isinstance(r["data"], dict) else {"results": r["data"] or []}
            return d.get("results") or [], None
        return None, "no CrowdStrike connection (add API credentials in Sync & settings)"
    except HTTPException as e:
        return None, str(e.detail)[:200]
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]


def check_one(value, use_live=True, how=None):
    v = value.strip().strip("[]").replace("[.]", ".").replace("hxxp", "http")
    k = kind_of(v)
    if not k:
        return {"value": value, "kind": None, "verdict": "Not an IOC", "error": "not an IP, domain, URL or MD5 / SHA1 / SHA256"}
    lv = v.lower()
    host = re.sub(r"^https?://", "", lv).split("/")[0] if k == "url" else lv
    out = {"value": v, "kind": k, "intel": [], "custom": [], "seen": {}, "internet": {}, "errors": []}
    if use_live:
        from . import cs_api
        how = how or cs_api.mode()
        out["source"] = cs_api.describe(how)
        intel, err = _live("QueryIntelIndicatorEntities", {"filter": f"indicator:'{host if k in ('url',) else lv}'", "limit": 10, "include_relations": True}, how)
        if err:
            out["errors"].append(f"CrowdStrike intel: {err}")
        out["intel"] = [{"indicator": i.get("indicator"), "type": i.get("type"), "confidence": i.get("malicious_confidence"),
                         "labels": [x.get("name") if isinstance(x, dict) else x for x in (i.get("labels") or [])][:8],
                         "actors": i.get("actors") or [], "malware": i.get("malware_families") or [], "published": i.get("published_date")}
                        for i in (intel or []) if str(i.get("indicator") or "").lower() in (lv, host)]
        custom, err = _live("indicator_combined_v1", {"filter": f"value:'{host if k == 'url' else lv}'", "limit": 10}, how)
        if err:
            out["errors"].append(f"Custom IOCs: {err}")
        out["custom"] = [{"value": i.get("value"), "type": i.get("type"), "action": i.get("action"), "severity": i.get("severity"),
                          "description": i.get("description")} for i in (custom or []) if str(i.get("value") or "").lower() in (lv, host)]
    like = f"%{host}%"
    with db.get_conn() as c:
        _ensure(c)
        det = db.rows(c, """SELECT id, name, severity, hostname, created_at FROM detections WHERE LOWER(COALESCE(filename,'')) LIKE ? OR LOWER(COALESCE(cmdline,'')) LIKE ?
                            OR LOWER(COALESCE(raw,'')) LIKE ? ORDER BY created_at DESC LIMIT 10""", (like, like, like))
        out["seen"]["detections"] = det
        if k == "ipv4":
            out["seen"]["asset"] = db.one(c, "SELECT ip, name, lobs, edr_status, exposed, in_inventory, in_edr FROM asset_registry WHERE ip=?", (lv,))
            out["seen"]["agents"] = c.execute("SELECT COUNT(*) FROM hosts WHERE connection_ip=? OR external_ip=?", (lv, lv)).fetchone()[0]
            out["seen"]["ndr"] = c.execute("SELECT COUNT(*) FROM ndr_alerts WHERE src_ip=? OR dst_ip=?", (lv, lv)).fetchone()[0]
            m = c.execute("SELECT class FROM ip_class WHERE ip=?", (lv,)).fetchone()
            out["seen"]["mark"] = m[0] if m else None
            from .registry import exposed_by_itself
            if exposed_by_itself(lv):
                from .whois import whois_map
                w = whois_map(c, [lv]).get(lv) or {}
                pv = db.one(c, "SELECT ports, vulns, tags FROM passive_results WHERE ip=?", (lv,))
                it = db.one(c, "SELECT gn_noise, gn_riot, gn_class, gn_name FROM ip_intel WHERE ip=?", (lv,))
                vt = db.one(c, "SELECT data FROM vt_results WHERE ip=?", (lv,))
                out["internet"] = {"whois": {k2: w.get(k2) for k2 in ("whois_name", "whois_descr", "whois_org", "whois_country") if w.get(k2)},
                                   "ports": db.jloads(pv["ports"], []) if pv else None, "cves": db.jloads(pv["vulns"], []) if pv else None,
                                   "greynoise": it, "virustotal": db.jloads(vt["data"], {}) if vt else None}
        prev = db.rows(c, "SELECT at, verdict FROM ioc_checks WHERE LOWER(value)=? ORDER BY id DESC LIMIT 3", (lv,))
    out["previous"] = prev
    out["verdict"], out["why"] = verdict(out)
    with db.get_conn() as c:
        c.execute("INSERT INTO ioc_checks(at, value, kind, verdict, detail) VALUES (?,?,?,?,?)",
                  (db.now_iso(), v, k, out["verdict"], json.dumps({"why": out["why"], "intel": len(out["intel"]), "custom": len(out["custom"])})))
    out["hunt"] = {"sha256": "hunt_hash", "sha1": "hunt_hash", "md5": "hunt_hash", "ipv4": "hunt_network_ip", "domain": "hunt_dns", "url": "hunt_dns"}[k]
    out["hunt_slot"] = {"hunt_hash": {"hash": lv}, "hunt_network_ip": {"ip": lv}, "hunt_dns": {"domain": host}}[out["hunt"]]
    return out


def verdict(o):
    why = []
    conf = [str(i.get("confidence") or "").lower() for i in o["intel"]]
    if "high" in conf or "medium" in conf:
        why.append(f"CrowdStrike intel: {', '.join(sorted(set(conf)))} malicious confidence")
        for i in o["intel"]:
            if i["actors"]:
                why.append("linked to " + ", ".join(map(str, i["actors"][:3])))
        return "Malicious", why
    vt = (o.get("internet") or {}).get("virustotal") or {}
    if o["custom"]:
        why.append("already a custom IOC in the tenant (" + ", ".join(str(c.get("action") or "") for c in o["custom"]) + ")")
        return "Malicious", why
    if (vt.get("malicious") or 0) >= 3:
        why.append(f"VirusTotal: {vt['malicious']} vendors flag it")
        return "Malicious", why
    seen = o["seen"]
    if seen.get("mark") == "enterprise" or (seen.get("asset") and (seen["asset"]["in_inventory"] or seen["asset"]["in_edr"])):
        a = seen.get("asset") or {}
        why.append("one of our assets" + (f" ({', '.join(x for x in (a.get('name'), a.get('lobs')) if x)})" if a.get("name") or a.get("lobs") else "")
                   + (" · marked enterprise" if seen.get("mark") == "enterprise" else ""))
        return "Ours", why
    gn = (o.get("internet") or {}).get("greynoise") or {}
    if conf or (vt.get("malicious") or 0) > 0 or (vt.get("suspicious") or 0) > 0 or gn.get("gn_noise"):
        if conf:
            why.append("in CrowdStrike intel with low confidence")
        if vt.get("malicious") or vt.get("suspicious"):
            why.append(f"VirusTotal: {vt.get('malicious', 0)} malicious, {vt.get('suspicious', 0)} suspicious")
        if gn.get("gn_noise"):
            why.append("GreyNoise sees it scanning the internet")
        return "Suspicious", why
    if seen.get("detections") or seen.get("ndr"):
        why.append(f"appears in {len(seen.get('detections') or [])} detections / {seen.get('ndr') or 0} NDR alerts")
        return "Seen internally", why
    why.append("not in CrowdStrike intel, custom IOCs or our data")
    return "Not known", why


@router.post("/api/ioc/check")
def ioc_check(data: dict = Body(...)):
    vals = [v for v in re.split(r"[\s,;]+", str(data.get("values") or "")) if v.strip()] if isinstance(data.get("values"), str) else list(data.get("values") or [])
    vals = list(dict.fromkeys(vals))[:50]
    if not vals:
        raise HTTPException(400, "Paste at least one IP, domain, URL or hash")
    t0 = time.time()
    from . import cs_api
    how = cs_api.mode()
    rows = [check_one(v, use_live=data.get("live", True), how=how) for v in vals]
    return {"rows": rows, "seconds": round(time.time() - t0, 2), "demo": config.DEMO, "source": cs_api.describe(how), "mode": how}


@router.get("/api/ioc/recent")
def ioc_recent(limit: int = 30):
    with db.get_conn() as c:
        _ensure(c)
        rows = db.rows(c, "SELECT id, at, value, kind, verdict, detail FROM ioc_checks ORDER BY id DESC LIMIT ?", (min(200, limit),))
    for r in rows:
        r["detail"] = db.jloads(r["detail"], {})
    return {"rows": rows}
