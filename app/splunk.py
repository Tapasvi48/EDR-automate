"""Splunk: is this host sending logs to the SIEM? (log-source presence on Asset 360)

What the integration needs (Integrations page shows the same list):
  * the Splunk REST (management) port reachable from this server, normally https://<search-head>:8089
  * an authentication token (Settings > Tokens) for a user whose role can run searches (capability `search`) on the
    indexes that hold host logs; read-only is enough - nothing is written to Splunk
  * the index filter to search (default `*`, or e.g. `index=wineventlog OR index=linux_secure OR index=firewall`)
For a host (its hostnames and IPs) the console runs one fast metadata search over the last N days:
  | tstats latest(_time) AS last_seen count WHERE (<index filter>) (host="name" OR host="10.1.2.3") BY host index sourcetype
and shows, per index / sourcetype, when the host last logged. Nothing is stored; each Asset 360 view asks Splunk live
(sample data mode simulates it)."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, HTTPException, Query

from . import config, db

router = APIRouter()
KEYS = {"url": "splunk_url", "token": "splunk_token", "index": "splunk_index", "days": "splunk_days", "verify": "splunk_verify_ssl"}


def settings():
    s = db.get_settings()
    return {"url": (s.get("splunk_url") or "").rstrip("/"), "token": s.get("splunk_token") or "", "index": s.get("splunk_index") or "*",
            "days": int(s.get("splunk_days") or 7), "verify": s.get("splunk_verify_ssl", "1") != "0"}


def _search(cfg, spl):
    import requests
    if not cfg["url"] or not cfg["token"]:
        raise ValueError("Splunk is not configured")
    r = requests.post(cfg["url"] + "/services/search/v2/jobs/export", verify=cfg["verify"], timeout=60,
                      headers={"Authorization": f"Bearer {cfg['token']}"},
                      data={"search": spl, "output_mode": "json", "earliest_time": f"-{cfg['days']}d", "latest_time": "now"})
    if r.status_code in (401, 403):
        raise ValueError(f"Splunk: access denied (HTTP {r.status_code}) - check the token and that its role may search these indexes")
    r.raise_for_status()
    out = []
    for line in r.text.splitlines():  # export streams one JSON object per line
        try:
            res = json.loads(line).get("result")
        except ValueError:
            continue
        if res:
            out.append(res)
    return out


def _quote(v):
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


@router.get("/api/asset/splunk")
def asset_splunk(hosts: str = "", ips: str = ""):
    names = [h for h in hosts.split(",") if h]
    addrs = [i for i in ips.split(",") if i]
    terms = sorted({*names, *[db.norm_hostname(h) for h in names], *addrs})
    cfg = settings()
    if not terms:
        return {"configured": bool(cfg["url"]) or config.DEMO, "rows": []}
    stored = _stored_hosts(terms, addrs)
    if stored is not None:  # synced by the Splunk automation: instant, no live search
        return stored
    if config.DEMO:  # simulated: most hosts log to Windows / Linux indexes, some are silent
        seed = int(hashlib.md5(",".join(terms).encode()).hexdigest(), 16)
        if seed % 5 == 0:
            return {"configured": True, "rows": [], "days": 7, "simulated": True}
        now = datetime.now(timezone.utc)
        idx = [("wineventlog", "WinEventLog:Security"), ("linux_secure", "linux_secure"), ("os", "syslog"), ("crowdstrike", "CrowdStrike:Event:Streams:JSON")]
        rows = [{"host": names[0] if names else addrs[0], "index": i, "sourcetype": st, "count": (seed >> (k * 5)) % 5000 + 50,
                 "last_seen": (now - timedelta(minutes=(seed >> (k * 3)) % (60 * 30))).strftime("%Y-%m-%dT%H:%M:%SZ")}
                for k, (i, st) in enumerate(idx) if (seed >> k) % 3]
        return {"configured": True, "rows": rows, "days": 7, "simulated": True}
    if not cfg["url"]:
        return {"configured": False, "rows": []}
    idx = cfg["index"] if cfg["index"].strip() not in ("", "*") else "index=*"
    if not idx.startswith("index") and "index=" not in idx:
        idx = f"index={idx}"
    spl = (f"| tstats latest(_time) AS last_seen count WHERE ({idx}) ({' OR '.join('host=' + _quote(t) for t in terms)}) "
           "BY host index sourcetype")
    try:
        res = _search(cfg, spl)
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "error": str(e), "rows": []}
    rows = [{"host": r.get("host"), "index": r.get("index"), "sourcetype": r.get("sourcetype"), "count": int(float(r.get("count") or 0)),
             "last_seen": datetime.fromtimestamp(float(r.get("last_seen") or 0), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} for r in res]
    return {"configured": True, "rows": sorted(rows, key=lambda r: r["last_seen"], reverse=True), "days": cfg["days"]}


def _stored_hosts(terms, addrs):
    """The synced Splunk host table (Splunk section): rows per index for the asset's hosts, or None when nothing is synced."""
    try:
        with db.get_conn() as c:
            if not c.execute("SELECT 1 FROM splunk_hosts LIMIT 1").fetchone():
                return None
            ph = ",".join("?" * len(terms))
            norm = [db.norm_hostname(t) for t in terms]
            rows = db.rows(c, f"""SELECT host, last_seen, events_7d, events_24h, indexes, sourcetypes FROM splunk_hosts
                                  WHERE host IN ({ph}) OR host_norm IN ({ph}) OR asset_ip IN ({",".join("?" * max(1, len(addrs)))})""",
                           terms + norm + (addrs or [""]))
    except Exception:  # noqa: BLE001
        return None
    out = []
    for r in rows:
        for i, idx in enumerate([x for x in (r["indexes"] or "").split(", ") if x] or ["(all)"]):
            out.append({"host": r["host"], "index": idx, "sourcetype": r["sourcetypes"] if i == 0 else "", "count": r["events_7d"] or r["events_24h"] or 0,
                        "last_seen": r["last_seen"]})
    return {"configured": True, "rows": sorted(out, key=lambda x: x["last_seen"] or "", reverse=True), "days": 7, "stored": True}


NOTABLE_INDEX = "notable"  # Splunk Enterprise Security notable events
DEMO_RULES = [("Brute force access behaviour detected", "high", "Credential Access"),
              ("Excessive failed logins", "medium", "Credential Access"), ("Unusual outbound traffic volume", "high", "Exfiltration"),
              ("Windows security log cleared", "critical", "Defense Evasion"), ("New local admin account created", "high", "Persistence"),
              ("Suspicious DNS query to rare domain", "medium", "Command and Control")]


@router.get("/api/asset/splunk/detections")
def asset_splunk_detections(hosts: str = "", ips: str = "", date_from: str = Query("", alias="from"), date_to: str = Query("", alias="to")):
    """Splunk Enterprise Security notable events where the host is the source, destination or host of the event."""
    names = [h for h in hosts.split(",") if h]
    addrs = [i for i in ips.split(",") if i]
    terms = sorted({*names, *[db.norm_hostname(h) for h in names], *addrs})
    now = datetime.now(timezone.utc)
    d_from = date_from or (now - timedelta(days=7)).strftime("%Y-%m-%d")
    d_to = date_to or now.strftime("%Y-%m-%d")
    cfg = settings()
    if not terms:
        return {"configured": bool(cfg["url"]) or config.DEMO, "rows": []}
    try:  # synced notables (Splunk section) first
        with db.get_conn() as c:
            if c.execute("SELECT 1 FROM splunk_notables LIMIT 1").fetchone():
                ph = ",".join("?" * len(terms))
                rows = db.rows(c, f"""SELECT created_at, rule name, urgency, domain category, src, dest, host, status FROM splunk_notables
                                      WHERE (host IN ({ph}) OR dest IN ({ph}) OR src IN ({ph}) OR asset_ip IN ({ph}))
                                      AND created_at >= ? AND created_at <= ? ORDER BY created_at DESC LIMIT 500""",
                               terms * 4 + [d_from, d_to + "T23:59:59Z"])
                for r in rows:
                    r["severity"] = (r.pop("urgency") or "").title()
                return {"configured": True, "rows": rows, "stored": True}
    except Exception:  # noqa: BLE001
        pass
    if config.DEMO:
        seed = int(hashlib.md5(("n" + ",".join(terms)).encode()).hexdigest(), 16)
        start = datetime.strptime(d_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        span = max(1, int((datetime.strptime(d_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) - start).total_seconds() // 60) + 1440)
        rows = []
        for k in range((seed % 4) if seed % 3 else 0):
            rule, urg, cat = DEMO_RULES[(seed >> (k * 4)) % len(DEMO_RULES)]
            t = start + timedelta(minutes=(seed >> (k * 7)) % span)
            if t > now:
                continue
            rows.append({"created_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "name": rule, "severity": urg.title(), "category": cat,
                         "src": addrs[0] if addrs and k % 2 else "", "dest": addrs[0] if addrs and not k % 2 else "",
                         "host": names[0] if names else "", "status": ["New", "In Progress", "Closed"][k % 3]})
        return {"configured": True, "rows": sorted(rows, key=lambda r: r["created_at"], reverse=True), "simulated": True}
    if not cfg["url"]:
        return {"configured": False, "rows": []}
    q = " OR ".join(f"{f}={_quote(t)}" for t in terms for f in ("dest", "src", "host", "dvc"))
    spl = (f'search index={NOTABLE_INDEX} ({q}) | eval t=strftime(_time, "%Y-%m-%dT%H:%M:%SZ") '
           "| table t rule_name urgency security_domain src dest host status_label | head 500")
    try:
        import requests  # noqa: F401
        c = dict(cfg)
        res = _search_window(c, spl, d_from, d_to)
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "error": str(e), "rows": []}
    rows = [{"created_at": r.get("t"), "name": r.get("rule_name"), "severity": str(r.get("urgency") or "").title(),
             "category": r.get("security_domain"), "src": r.get("src"), "dest": r.get("dest"), "host": r.get("host"),
             "status": r.get("status_label")} for r in res]
    return {"configured": True, "rows": rows}


def _search_window(cfg, spl, d_from, d_to):
    import requests
    r = requests.post(cfg["url"] + "/services/search/v2/jobs/export", verify=cfg["verify"], timeout=60,
                      headers={"Authorization": f"Bearer {cfg['token']}"},
                      data={"search": spl, "output_mode": "json", "earliest_time": f"{d_from}T00:00:00", "latest_time": f"{d_to}T23:59:59"})
    if r.status_code in (401, 403):
        raise ValueError(f"Splunk: access denied (HTTP {r.status_code})")
    r.raise_for_status()
    out = []
    for line in r.text.splitlines():
        try:
            res = json.loads(line).get("result")
        except ValueError:
            continue
        if res:
            out.append(res)
    return out


@router.get("/api/splunk/config")
def splunk_config():
    cfg = settings()
    return {"url": cfg["url"], "token_set": bool(cfg["token"]), "index": cfg["index"], "days": cfg["days"], "verify_ssl": cfg["verify"], "demo": config.DEMO}


@router.put("/api/splunk/config")
def splunk_config_save(data: dict = Body(...)):
    url = str(data.get("url") or "").strip().rstrip("/")
    if url and not url.startswith(("https://", "http://")):
        raise HTTPException(400, "The Splunk URL must start with https:// (management port, usually :8089)")
    vals = {"splunk_url": url, "splunk_index": str(data.get("index") or "*").strip() or "*",
            "splunk_days": str(max(1, min(90, int(data.get("days") or 7)))), "splunk_verify_ssl": "0" if data.get("verify_ssl") is False else "1"}
    if data.get("token"):
        vals["splunk_token"] = str(data["token"]).strip()
    db.set_settings(vals)
    return splunk_config()


@router.post("/api/splunk/test")
def splunk_test():
    try:
        res = _search(settings(), "| rest /services/server/info splunk_server=local | fields serverName version")
        info = res[0] if res else {}
        return {"ok": True, "detail": f"Connected to {info.get('serverName', 'Splunk')} {info.get('version', '')}".strip()}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": str(e)}
