"""Splunk automation: log sources, EPS, detections (ES notables), indexes, forwarders and license — synced, stored and joined
with the asset registry, so the console can answer "which assets send no logs?" for lakhs of assets without asking Splunk live.

Sync steps (each reads only what it needs; a step is skipped while its data is fresh — Full refresh forces all):
  connect      server info (version) — always
  hosts        last event + 24 h event count per host                    every sync   (| tstats … earliest=-24h BY host)
  inventory    per host and per index / sourcetype: events, last event   once a day   (| tstats … earliest=-7d BY host index sourcetype)
  eps          events per hour per index, from the last stored hour      every sync   (incremental; 14 days kept)
  notables     ES notable events since the last fetch (and the last      every sync   (`notable` macro: status / owner included)
               7 days once a day, for status / owner changes)
  indexes      size, event count, retention, newest event per index      once a day   (| rest /services/data/indexes)
  forwarders   universal forwarders connected to the indexers            once a day   (index=_internal group=tcpin_connections)
  license      GB per index per day (yesterday and back to 30 days)      once a day   (index=_internal license_usage.log)
  coverage     Splunk hosts matched to assets (IP or host name), and     after hosts / inventory
               the coverage numbers (logging / silent / never per LOB)
Splunk needs: the management port (8089) reachable, a token whose role may search the log indexes (capability `search`);
for notables the `notable` index / ES; for forwarders and license read access to `_internal` (optional — skipped when denied).
Sample-data mode simulates every step from the sample assets."""
import hashlib
import json
import math
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, HTTPException, Request

from . import config, db
from .splunk import settings as sp_settings

router = APIRouter()
ISO = "%Y-%m-%dT%H:%M:%SZ"
STEPS = [("connect", "Connect to Splunk", 0), ("hosts", "Hosts: last event (24 h)", 0), ("inventory", "Log sources per host (7 days)", 1440),
         ("eps", "Events per second (hourly)", 0), ("notables", "Detections (ES notables)", 0), ("indexes", "Indexes: size & retention", 1440),
         ("forwarders", "Forwarders", 1440), ("license", "License usage", 1440), ("coverage", "Match hosts to assets", 0)]
STATUS = {"running": False, "started_at": None, "finished_at": None, "steps": [], "full": False, "error": None, "message": None}
_LOCK = threading.Lock()
SETTINGS = {"splunk_sync_minutes": "60", "splunk_silent_hours": "24", "splunk_notable_index": "notable", "splunk_last": "{}"}


def now():
    return datetime.now(timezone.utc)


def iso(d):
    return d.strftime(ISO)


def ensure(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS splunk_hosts (host TEXT PRIMARY KEY, host_norm TEXT, first_seen TEXT, last_seen TEXT, events_24h INTEGER DEFAULT 0,
        events_7d INTEGER DEFAULT 0, indexes TEXT, sourcetypes TEXT, asset_ip TEXT, asset_name TEXT, lob TEXT, edr_status TEXT, updated_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_sph_asset ON splunk_hosts(asset_ip);
    CREATE INDEX IF NOT EXISTS ix_sph_norm ON splunk_hosts(host_norm);
    CREATE TABLE IF NOT EXISTS splunk_sources (idx TEXT, sourcetype TEXT, events_7d INTEGER, hosts INTEGER, first_seen TEXT, last_seen TEXT,
        eps REAL, updated_at TEXT, PRIMARY KEY (idx, sourcetype));
    CREATE TABLE IF NOT EXISTS splunk_eps (idx TEXT, hour TEXT, events INTEGER, PRIMARY KEY (idx, hour));
    CREATE TABLE IF NOT EXISTS splunk_license (day TEXT, idx TEXT, gb REAL, PRIMARY KEY (day, idx));
    CREATE TABLE IF NOT EXISTS splunk_indexes (name TEXT PRIMARY KEY, size_mb REAL, events INTEGER, max_time TEXT, min_time TEXT,
        retention_days REAL, disabled INTEGER, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS splunk_forwarders (hostname TEXT, ip TEXT, version TEXT, os TEXT, fwd_type TEXT, last_seen TEXT, asset_ip TEXT,
        PRIMARY KEY (hostname, ip));
    CREATE TABLE IF NOT EXISTS splunk_notables (event_id TEXT PRIMARY KEY, created_at TEXT, rule TEXT, urgency TEXT, domain TEXT, src TEXT,
        dest TEXT, user TEXT, host TEXT, status TEXT, owner TEXT, asset_ip TEXT, fetched_at TEXT);
    CREATE INDEX IF NOT EXISTS ix_spn_time ON splunk_notables(created_at);
    CREATE INDEX IF NOT EXISTS ix_spn_asset ON splunk_notables(asset_ip);
    CREATE TABLE IF NOT EXISTS splunk_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT, finished_at TEXT, status TEXT, full INTEGER,
        steps TEXT, message TEXT);
    """)


def cfg():
    s = db.get_settings()
    out = sp_settings()
    out.update(minutes=int(s.get("splunk_sync_minutes") or 60), silent_hours=int(s.get("splunk_silent_hours") or 24),
               notable_index=s.get("splunk_notable_index") or "notable", last=db.jloads(s.get("splunk_last"), {}) or {})
    return out


def configured():
    c = cfg()
    return bool(c["url"] and c["token"])


# ------------------------------------------------------------------ Splunk search (streaming export)
def spl(c, query, earliest, latest="now"):
    """Run a search through the export endpoint and stream the results (one JSON object per line), so lakhs of rows never sit
    in memory as one response."""
    import requests
    if not c["url"] or not c["token"]:
        raise ValueError("Splunk is not configured (Integrations → Splunk)")
    r = requests.post(c["url"] + "/services/search/v2/jobs/export", verify=c["verify"], timeout=(15, 600), stream=True,
                      headers={"Authorization": f"Bearer {c['token']}"},
                      data={"search": query if query.lstrip().startswith(("|", "search")) else "search " + query, "output_mode": "json",
                            "earliest_time": earliest, "latest_time": latest})
    if r.status_code in (401, 403):
        raise PermissionError(f"Splunk: access denied (HTTP {r.status_code}) — the token's role may not search this")
    r.raise_for_status()
    for line in r.iter_lines(decode_unicode=True):
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("result"):
            yield obj["result"]
        elif obj.get("messages") and any(m.get("type") == "ERROR" for m in obj["messages"]):
            raise ValueError("Splunk: " + "; ".join(m.get("text", "") for m in obj["messages"])[:300])


def _ts(v):
    try:
        return iso(datetime.fromtimestamp(float(v), timezone.utc))
    except (TypeError, ValueError):
        return None


def _mv(v):
    return ", ".join(v) if isinstance(v, list) else (v or "")


def _idx(c):
    i = (c["index"] or "*").strip()
    if i in ("", "*"):
        return "index=*"
    return i if "index" in i else f"index={i}"


# ------------------------------------------------------------------ sample data (demo)
DEMO_SOURCES = [("wineventlog", "WinEventLog:Security", 0.55), ("wineventlog", "WinEventLog:System", 0.2), ("linux_secure", "linux_secure", 0.45),
                ("os", "syslog", 0.3), ("firewall", "pan:traffic", 0.05), ("crowdstrike", "CrowdStrike:Event:Streams:JSON", 0.35),
                ("proxy", "bluecoat:proxysg", 0.03), ("network", "cisco:ios", 0.12)]
DEMO_EPS = {"wineventlog": 1450, "linux_secure": 620, "os": 380, "firewall": 4200, "crowdstrike": 900, "proxy": 2600, "network": 310}


def _rng(*k):
    return random.Random(int(hashlib.md5("|".join(map(str, k)).encode()).hexdigest()[:12], 16))


def _demo_assets():
    with db.get_conn() as c:
        return db.rows(c, """SELECT r.ip, r.name, r.edr_status FROM asset_registry r WHERE r.ip LIKE '%.%' AND (r.in_inventory=1 OR r.in_edr=1)
                             ORDER BY r.ip_num LIMIT 50000""")


def demo_hosts(window_h):
    out, t = [], now()
    for a in _demo_assets():
        r = _rng(a["ip"])
        p = 0.92 if a["edr_status"] in ("Online", "Offline") else 0.45  # most protected hosts also log; unprotected ones often don't
        if r.random() > p:
            continue
        host = (a["name"] or "").split(",")[0].strip() or a["ip"]
        silent = r.random() < 0.08  # stopped logging some days ago
        last = t - timedelta(hours=r.uniform(30, 24 * 6) if silent else r.uniform(0, 2))
        srcs = [s for s in DEMO_SOURCES if r.random() < s[2]] or [DEMO_SOURCES[3]]
        ev = 0 if silent else int(r.uniform(2_000, 90_000) * window_h / 24)
        out.append({"host": host if r.random() < 0.8 else a["ip"], "last": last, "first": t - timedelta(days=r.uniform(20, 400)), "count": ev,
                    "sources": srcs})
    for k in range(60):  # hosts logging to Splunk that no inventory / CrowdStrike knows (shadow log sources)
        r = _rng("shadow", k)
        out.append({"host": f"unk-{['web', 'db', 'app', 'fw'][k % 4]}-{k:03d}", "last": t - timedelta(minutes=r.uniform(1, 600)),
                    "first": t - timedelta(days=r.uniform(1, 90)), "count": int(r.uniform(500, 40_000) * window_h / 24), "sources": [DEMO_SOURCES[k % 8]]})
    return out


# ------------------------------------------------------------------ steps
def step_connect(c, full, prog):
    if config.DEMO and not configured():
        return "Sample data: simulated Splunk Enterprise 9.3 with Enterprise Security"
    res = list(spl(c, "| rest /services/server/info splunk_server=local | fields serverName version", "-1m"))
    info = res[0] if res else {}
    return f"Connected to {info.get('serverName', 'Splunk')} {info.get('version', '')}".strip()


def step_hosts(c, full, prog):
    """Last event and 24 h events per host — one tstats over the last 24 h, merged into what we have (hosts that went quiet
    keep their last event time, so 'silent for N days' stays right)."""
    t = iso(now())
    if config.DEMO and not configured():
        rows = [(h["host"], db.norm_hostname(h["host"]), iso(h["first"]), iso(h["last"]), h["count"]) for h in demo_hosts(24)
                if h["last"] > now() - timedelta(hours=24)]
    else:
        q = f"| tstats latest(_time) AS last earliest(_time) AS first count WHERE {_idx(c)} BY host"
        rows = []
        for i, r in enumerate(spl(c, q, "-24h")):
            rows.append((r.get("host"), db.norm_hostname(r.get("host")), _ts(r.get("first")), _ts(r.get("last")), int(float(r.get("count") or 0))))
            if i % 20000 == 0:
                prog(f"{i:,} hosts read")
    with db.get_conn() as d:
        ensure(d)
        d.execute("UPDATE splunk_hosts SET events_24h=0")
        d.executemany("""INSERT INTO splunk_hosts(host, host_norm, first_seen, last_seen, events_24h, updated_at) VALUES (?,?,?,?,?,?)
                         ON CONFLICT(host) DO UPDATE SET last_seen=MAX(COALESCE(splunk_hosts.last_seen,''), excluded.last_seen),
                         first_seen=MIN(COALESCE(splunk_hosts.first_seen, excluded.first_seen), excluded.first_seen),
                         events_24h=excluded.events_24h, updated_at=excluded.updated_at""", [(*r, t) for r in rows if r[0]])
    return f"{len(rows):,} hosts sent events in the last 24 h"


def step_inventory(c, full, prog):
    """Per host and per index / sourcetype over 7 days (once a day): which log types each host sends, and the source list."""
    t = iso(now())
    per_host, per_src = {}, {}
    if config.DEMO and not configured():
        for h in demo_hosts(24 * 7):
            per_host[h["host"]] = (iso(h["first"]), iso(h["last"]), h["count"], sorted({s[0] for s in h["sources"]}), [s[1] for s in h["sources"]])
            for idx, st, _ in h["sources"]:
                s = per_src.setdefault((idx, st), [0, set(), iso(h["first"]), iso(h["last"])])
                s[0] += h["count"] // len(h["sources"])
                s[1].add(h["host"])
                s[2], s[3] = min(s[2], iso(h["first"])), max(s[3], iso(h["last"]))
    else:
        q = f"| tstats latest(_time) AS last earliest(_time) AS first count WHERE {_idx(c)} BY host index sourcetype"
        for i, r in enumerate(spl(c, q, "-7d")):
            host, idx, st, n = r.get("host"), r.get("index"), r.get("sourcetype"), int(float(r.get("count") or 0))
            first, last = _ts(r.get("first")), _ts(r.get("last"))
            h = per_host.setdefault(host, [first, last, 0, set(), set()])
            h[0], h[1], h[2] = min(h[0] or first, first or h[0]), max(h[1] or "", last or ""), h[2] + n
            h[3].add(idx)
            h[4].add(st)
            s = per_src.setdefault((idx, st), [0, set(), first, last])
            s[0] += n
            s[1].add(host)
            s[2], s[3] = min(s[2] or first, first or s[2]), max(s[3] or "", last or "")
            if i % 50000 == 0:
                prog(f"{i:,} host / source rows read")
        per_host = {k: (v[0], v[1], v[2], sorted(v[3]), sorted(v[4])) for k, v in per_host.items()}
    with db.get_conn() as d:
        ensure(d)
        d.execute("UPDATE splunk_hosts SET events_7d=0")
        d.executemany("""INSERT INTO splunk_hosts(host, host_norm, first_seen, last_seen, events_7d, indexes, sourcetypes, updated_at) VALUES (?,?,?,?,?,?,?,?)
                         ON CONFLICT(host) DO UPDATE SET last_seen=MAX(COALESCE(splunk_hosts.last_seen,''), excluded.last_seen),
                         first_seen=MIN(COALESCE(splunk_hosts.first_seen, excluded.first_seen), excluded.first_seen), events_7d=excluded.events_7d,
                         indexes=excluded.indexes, sourcetypes=excluded.sourcetypes, updated_at=excluded.updated_at""",
                      [(h, db.norm_hostname(h), v[0], v[1], v[2], ", ".join(v[3]), ", ".join(v[4][:20]), t) for h, v in per_host.items() if h])
        d.execute("DELETE FROM splunk_sources")
        d.executemany("INSERT INTO splunk_sources(idx, sourcetype, events_7d, hosts, first_seen, last_seen, eps, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                      [(k[0], k[1], v[0], len(v[1]), v[2], v[3], round(v[0] / (7 * 86400), 2), t) for k, v in per_src.items()])
    return f"{len(per_host):,} hosts · {len(per_src):,} log sources (index / sourcetype) in 7 days"


def step_eps(c, full, prog):
    """Hourly events per index, from the newest stored hour on (14 days kept)."""
    with db.get_conn() as d:
        ensure(d)
        last = d.execute("SELECT MAX(hour) FROM splunk_eps").fetchone()[0]
    start = now().replace(minute=0, second=0, microsecond=0) - timedelta(days=7)
    if last and not full:
        start = max(start, datetime.strptime(last, ISO).replace(tzinfo=timezone.utc) - timedelta(hours=1))
    end = now().replace(minute=0, second=0, microsecond=0)
    rows = []
    if config.DEMO and not configured():
        h = start
        while h < end:
            for idx, base in DEMO_EPS.items():
                diurnal = 0.55 + 0.45 * math.sin((h.hour - 6) / 24 * 2 * math.pi) + (0.15 if h.weekday() < 5 else -0.2)
                spike = 2.4 if _rng(idx, iso(h)).random() < 0.01 else 1
                rows.append((idx, iso(h), int(base * 3600 * max(0.15, diurnal) * spike * _rng(idx, h.day).uniform(0.9, 1.1))))
            h += timedelta(hours=1)
    else:
        q = f"| tstats count WHERE {_idx(c)} BY _time span=1h index"
        for r in spl(c, q, iso(start), iso(end)):
            rows.append((r.get("index"), _ts(r.get("_time")) or r.get("_time"), int(float(r.get("count") or 0))))
    with db.get_conn() as d:
        d.executemany("INSERT OR REPLACE INTO splunk_eps(idx, hour, events) VALUES (?,?,?)", rows)
        d.execute("DELETE FROM splunk_eps WHERE hour < ?", (iso(now() - timedelta(days=14)),))
    hours = len({r[1] for r in rows})
    return f"{hours:,} new hour(s) of EPS" if hours else "EPS already up to date"


DEMO_RULES = [("Brute Force Access Behavior Detected", "high", "access"), ("Excessive Failed Logins", "medium", "access"),
              ("Unusual Volume of Outbound Traffic", "high", "network"), ("Windows Security Log Cleared", "critical", "endpoint"),
              ("New Local Admin Account", "high", "endpoint"), ("Suspicious DNS Query to Rare Domain", "medium", "network"),
              ("Host With Multiple Infections", "critical", "endpoint"), ("Geographically Improbable Access", "medium", "identity"),
              ("Threat Activity Detected (Threat Intel match)", "high", "threat"), ("Abnormally High Number of Endpoint Changes", "low", "endpoint")]


def step_notables(c, full, prog):
    """ES notables since the last fetch; once a day the last 7 days again, so status / owner changes made in ES are picked up."""
    last = c["last"].get("notables_at")
    redo = full or not c["last"].get("notables_full") or c["last"]["notables_full"] < iso(now() - timedelta(days=1))
    earliest = iso(now() - timedelta(days=7)) if (redo or not last) else iso(datetime.strptime(last, ISO).replace(tzinfo=timezone.utc) - timedelta(minutes=15))
    rows, t = [], iso(now())
    if config.DEMO and not configured():
        hosts = [h["host"] for h in demo_hosts(24)][:400]
        start = datetime.strptime(earliest, ISO).replace(tzinfo=timezone.utc)
        n = int((now() - start).total_seconds() / 3600 * 1.6)
        for k in range(n):
            r = _rng("notable", earliest[:13], k)
            when = start + timedelta(seconds=r.uniform(0, (now() - start).total_seconds()))
            rule, urg, dom = DEMO_RULES[r.randrange(len(DEMO_RULES))]
            host = hosts[r.randrange(len(hosts))] if hosts else "host"
            age_h = (now() - when).total_seconds() / 3600
            status = "Closed" if age_h > 72 and r.random() < 0.7 else "In Progress" if r.random() < 0.3 else "New"
            rows.append((hashlib.md5(f"{iso(when)}{k}{rule}".encode()).hexdigest(), iso(when), rule, urg, dom, f"10.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(256)}",
                         host, r.choice(["svc_backup", "j.smith", "administrator", "", ""]), host, status,
                         r.choice(["Priya Sharma", "Arjun Mehta", "unassigned"]) if status != "New" else "unassigned"))
    else:
        q = ("`notable` | eval t=strftime(_time, \"%Y-%m-%dT%H:%M:%SZ\") | fields event_id t rule_name urgency security_domain src dest user host "
             "status_label owner")
        try:
            it = spl(c, q, earliest)
            first = next(it, None)
            res = ([first] if first else []) + list(it)
        except ValueError as e:  # no `notable` macro (no ES): plain index
            if "notable" not in str(e).lower():
                raise
            res = list(spl(c, f"search index={c['notable_index']} | eval t=strftime(_time, \"%Y-%m-%dT%H:%M:%SZ\")", earliest))
        for r in res:
            eid = r.get("event_id") or hashlib.md5(json.dumps(r, sort_keys=True).encode()).hexdigest()
            rows.append((eid, r.get("t"), r.get("rule_name") or r.get("search_name"), str(r.get("urgency") or "").lower(), r.get("security_domain"),
                         _mv(r.get("src")), _mv(r.get("dest")), _mv(r.get("user")), _mv(r.get("host")), r.get("status_label") or r.get("status"),
                         r.get("owner")))
    with db.get_conn() as d:
        ensure(d)
        d.executemany("""INSERT INTO splunk_notables(event_id, created_at, rule, urgency, domain, src, dest, user, host, status, owner, fetched_at)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET status=excluded.status, owner=excluded.owner,
                         fetched_at=excluded.fetched_at""", [(*r, t) for r in rows])
        d.execute("DELETE FROM splunk_notables WHERE created_at < ?", (iso(now() - timedelta(days=180)),))
    upd = {"notables_at": t}
    if redo:
        upd["notables_full"] = t
    _remember(upd)
    return f"{len(rows):,} notables {'in the last 7 days (status refresh)' if redo else 'new or changed since the last sync'}"


def step_indexes(c, full, prog):
    t = iso(now())
    if config.DEMO and not configured():
        res = [{"title": i, "currentDBSizeMB": DEMO_EPS[i] * 86400 * 0.6 / 1e5 * 30, "totalEventCount": DEMO_EPS[i] * 86400 * 30,
                "maxTime": iso(now() - timedelta(seconds=_rng(i).uniform(1, 120))), "minTime": iso(now() - timedelta(days=90)),
                "frozenTimePeriodInSecs": 86400 * (365 if i in ("wineventlog", "firewall") else 90), "disabled": "0"} for i in DEMO_EPS]
        res.append({"title": "legacy_app", "currentDBSizeMB": 1200, "totalEventCount": 9_100_000, "maxTime": iso(now() - timedelta(days=9)),
                    "minTime": iso(now() - timedelta(days=300)), "frozenTimePeriodInSecs": 86400 * 180, "disabled": "0"})
    else:
        res = list(spl(c, "| rest /services/data/indexes count=0 | fields title currentDBSizeMB totalEventCount maxTime minTime "
                          "frozenTimePeriodInSecs disabled", "-1m"))
    rows = [(r.get("title"), float(r.get("currentDBSizeMB") or 0), int(float(r.get("totalEventCount") or 0)), r.get("maxTime"), r.get("minTime"),
             round(float(r.get("frozenTimePeriodInSecs") or 0) / 86400, 1), 1 if str(r.get("disabled")) in ("1", "true") else 0, t)
            for r in res if r.get("title") and not str(r.get("title")).startswith("_")]
    with db.get_conn() as d:
        ensure(d)
        d.execute("DELETE FROM splunk_indexes")
        d.executemany("INSERT INTO splunk_indexes VALUES (?,?,?,?,?,?,?,?)", rows)
    return f"{len(rows):,} indexes · {sum(r[1] for r in rows) / 1024:,.0f} GB"


def step_forwarders(c, full, prog):
    if config.DEMO and not configured():
        res = []
        for h in demo_hosts(24)[:3000]:
            r = _rng("fwd", h["host"])
            if r.random() < 0.7:
                res.append({"hostname": h["host"], "sourceIp": "", "version": r.choice(["9.3.1", "9.2.2", "9.1.4", "8.2.12"]),
                            "os": r.choice(["Windows", "Linux"]), "fwdType": "uf", "last": h["last"].timestamp()})
    else:
        res = list(spl(c, "index=_internal sourcetype=splunkd group=tcpin_connections | stats latest(_time) AS last latest(version) AS version "
                          "latest(os) AS os latest(fwdType) AS fwdType BY hostname sourceIp", "-24h"))
    rows = [(r.get("hostname"), r.get("sourceIp") or "", r.get("version"), r.get("os"), r.get("fwdType"), _ts(r.get("last"))) for r in res if r.get("hostname")]
    with db.get_conn() as d:
        ensure(d)
        d.execute("DELETE FROM splunk_forwarders")
        d.executemany("INSERT OR REPLACE INTO splunk_forwarders(hostname, ip, version, os, fwd_type, last_seen) VALUES (?,?,?,?,?,?)", rows)
    return f"{len(rows):,} forwarders connected in the last 24 h"


def step_license(c, full, prog):
    days = 30 if full or not c["last"].get("license_at") else 3
    rows = []
    if config.DEMO and not configured():
        for k in range(1, days + 1):
            day = (now() - timedelta(days=k)).strftime("%Y-%m-%d")
            for idx, eps in DEMO_EPS.items():
                rows.append((day, idx, round(eps * 86400 * 450 / 1e9 * _rng(idx, day).uniform(0.85, 1.15), 2)))
    else:
        q = ("index=_internal source=*license_usage.log* type=Usage | bin _time span=1d | stats sum(b) AS b BY _time idx "
             "| eval day=strftime(_time, \"%Y-%m-%d\")")
        for r in spl(c, q, f"-{days}d@d", "@d"):
            rows.append((r.get("day"), r.get("idx"), round(float(r.get("b") or 0) / 1024 ** 3, 3)))
    with db.get_conn() as d:
        ensure(d)
        d.executemany("INSERT OR REPLACE INTO splunk_license(day, idx, gb) VALUES (?,?,?)", rows)
        d.execute("DELETE FROM splunk_license WHERE day < ?", ((now() - timedelta(days=120)).strftime("%Y-%m-%d"),))
    _remember({"license_at": iso(now())})
    return f"{len({r[0] for r in rows})} day(s) of license usage"


def step_coverage(c, full, prog):
    """Match every Splunk host (host name, FQDN or IP) to an asset of the registry, for coverage."""
    with db.get_conn() as d:
        ensure(d)
        by_ip, by_name = {}, {}
        for r in d.execute("SELECT ip, name, lobs, edr_status FROM asset_registry WHERE COALESCE(ip,'')<>''"):
            by_ip[r["ip"]] = r
            for n in (r["name"] or "").split(","):
                if n.strip():
                    by_name.setdefault(db.norm_hostname(n.strip()), r)
        for r in d.execute("SELECT hostname_norm, connection_ip FROM hosts WHERE console_state<>'hidden' AND COALESCE(connection_ip,'')<>''"):
            if r["hostname_norm"] and r["connection_ip"] in by_ip:
                by_name.setdefault(r["hostname_norm"], by_ip[r["connection_ip"]])
        upd, matched = [], 0
        for h in db.rows(d, "SELECT host, host_norm, asset_ip FROM splunk_hosts"):
            a = by_ip.get(h["host"]) if db.is_ip(h["host"] or "") else by_name.get(h["host_norm"] or db.norm_hostname(h["host"]))
            if a:
                matched += 1
            upd.append((a["ip"] if a else None, (a["name"] or "").split(",")[0] if a else None, a["lobs"] if a else None,
                        a["edr_status"] if a else None, h["host"]))
        d.executemany("UPDATE splunk_hosts SET asset_ip=?, asset_name=?, lob=?, edr_status=? WHERE host=?", upd)
        d.execute("""UPDATE splunk_notables SET asset_ip=(SELECT asset_ip FROM splunk_hosts h WHERE h.host=splunk_notables.host
                     OR h.host=splunk_notables.dest LIMIT 1) WHERE asset_ip IS NULL""")
        d.execute("""UPDATE splunk_forwarders SET asset_ip=(SELECT asset_ip FROM splunk_hosts h WHERE h.host=splunk_forwarders.hostname LIMIT 1)""")
    return f"{matched:,} of {len(upd):,} Splunk hosts matched to an asset"


FNS = {"connect": step_connect, "hosts": step_hosts, "inventory": step_inventory, "eps": step_eps, "notables": step_notables,
       "indexes": step_indexes, "forwarders": step_forwarders, "license": step_license, "coverage": step_coverage}
OPTIONAL = {"notables", "forwarders", "license"}  # need ES / _internal access: a denial skips the step, not the sync


def _remember(upd):
    with _LOCK:
        cur = db.jloads(db.get_settings().get("splunk_last"), {}) or {}
        cur.update(upd)
        db.set_settings({"splunk_last": json.dumps(cur)})


def _due(key, interval, last, full):
    if full or not interval:
        return True
    at = last.get(f"{key}_ok")
    return not at or at < iso(now() - timedelta(minutes=interval - 5))


def run_sync(full=False, trigger="manual"):
    with _LOCK:
        if STATUS["running"]:
            return False
        STATUS.update(running=True, started_at=iso(now()), finished_at=None, full=full, error=None, message=None,
                      steps=[{"key": k, "label": l, "status": "pending", "detail": ""} for k, l, _ in STEPS])
    threading.Thread(target=_worker, args=(full, trigger), daemon=True, name="splunk-sync").start()
    return True


def _set(key, **kw):
    for s in STATUS["steps"]:
        if s["key"] == key:
            s.update(kw)


def _worker(full, trigger):
    c = cfg()
    ok, errs = True, []
    with db.get_conn() as d:
        ensure(d)
        rid = d.execute("INSERT INTO splunk_runs(started_at, status, full) VALUES (?,?,?)", (STATUS["started_at"], "running", 1 if full else 0)).lastrowid
    changed_hosts = False
    for key, label, interval in STEPS:
        if key == "coverage" and not (changed_hosts or full or not c["last"].get("coverage_ok")):
            _set(key, status="skipped", detail="no host changes")
            continue
        if not _due(key, interval, c["last"], full):
            _set(key, status="skipped", detail=f"fresh (last {c['last'].get(key + '_ok', '')[:16].replace('T', ' ')}); every {interval // 60} h")
            continue
        t0 = time.time()
        _set(key, status="running", started=iso(now()))
        try:
            detail = FNS[key](c, full, lambda m, k=key: _set(k, detail=m))
            _set(key, status="done", detail=detail, seconds=round(time.time() - t0, 1))
            _remember({f"{key}_ok": iso(now())})
            c["last"][f"{key}_ok"] = iso(now())
            if key in ("hosts", "inventory"):
                changed_hosts = True
        except PermissionError as e:
            _set(key, status="skipped" if key in OPTIONAL else "error", detail=str(e)[:300], seconds=round(time.time() - t0, 1))
            if key not in OPTIONAL:
                ok = False
                errs.append(str(e))
        except Exception as e:  # noqa: BLE001
            _set(key, status="error", detail=str(e)[:300], seconds=round(time.time() - t0, 1))
            errs.append(f"{label}: {str(e)[:200]}")
            if key == "connect":
                ok = False
                for s in STATUS["steps"][1:]:
                    s.update(status="skipped", detail="not connected")
                break
            ok = ok and key in OPTIONAL
    msg = "; ".join(errs) if errs else "Splunk sync complete"
    with db.get_conn() as d:
        d.execute("UPDATE splunk_runs SET finished_at=?, status=?, steps=?, message=? WHERE id=?",
                  (iso(now()), "ok" if ok else "error", json.dumps(STATUS["steps"]), msg, rid))
    STATUS.update(running=False, finished_at=iso(now()), error=None if ok else msg, message=msg)
    _remember({"sync_at": iso(now()), "sync_ok": ok})


def start_scheduler():
    """Every minute: run a sync when one is due (Splunk configured, interval passed)."""
    def loop():
        while True:
            time.sleep(60)
            try:
                c = cfg()
                if configured() and c["minutes"] > 0 and not STATUS["running"]:
                    last = c["last"].get("sync_at")
                    if not last or last < iso(now() - timedelta(minutes=c["minutes"])):
                        run_sync(trigger="scheduled")
            except Exception:  # noqa: BLE001
                pass
    threading.Thread(target=loop, daemon=True, name="splunk-scheduler").start()


# ------------------------------------------------------------------ read API
def _silent_cut(c):
    return iso(now() - timedelta(hours=c["silent_hours"]))


@router.get("/api/splunk/summary")
def splunk_summary():
    c = cfg()
    cut = _silent_cut(c)
    with db.get_conn() as d:
        ensure(d)
        cov = db.one(d, """SELECT COUNT(*) assets,
            SUM(s.ls >= ?) logging, SUM(s.ls < ?) silent, SUM(s.ls IS NULL) never,
            SUM(r.edr_status IN ('Online','Offline') AND (s.ls IS NULL OR s.ls < ?)) edr_no_logs,
            SUM(r.edr_status NOT IN ('Online','Offline') AND s.ls >= ?) logs_no_edr,
            SUM(r.exposed=1 AND (s.ls IS NULL OR s.ls < ?)) exposed_no_logs
            FROM asset_registry r LEFT JOIN (SELECT asset_ip, MAX(last_seen) ls FROM splunk_hosts WHERE asset_ip IS NOT NULL GROUP BY asset_ip) s
            ON s.asset_ip=r.ip WHERE r.in_inventory=1 OR r.in_edr=1""", (cut, cut, cut, cut, cut))
        hosts = db.one(d, """SELECT COUNT(*) total, SUM(last_seen >= ?) reporting, SUM(last_seen < ?) silent, SUM(asset_ip IS NULL) unmatched,
            SUM(events_24h) events_24h FROM splunk_hosts""", (cut, cut))
        last_hour = d.execute("SELECT MAX(hour) FROM splunk_eps").fetchone()[0]
        eps_now = (d.execute("SELECT SUM(events) FROM splunk_eps WHERE hour=?", (last_hour,)).fetchone()[0] or 0) / 3600 if last_hour else 0
        eps = db.one(d, """SELECT AVG(t) avg_24h FROM (SELECT hour, SUM(events)/3600.0 t FROM splunk_eps WHERE hour >= ? GROUP BY hour)""",
                     (iso(now() - timedelta(hours=24)),))
        peak = db.one(d, """SELECT hour, MAX(t) peak FROM (SELECT hour, SUM(events)/3600.0 t FROM splunk_eps WHERE hour >= ? GROUP BY hour)""",
                      (iso(now() - timedelta(days=7)),))
        lic = db.one(d, """SELECT AVG(g) avg_gb, MAX(g) max_gb FROM (SELECT day, SUM(gb) g FROM splunk_license WHERE day >= ? GROUP BY day)""",
                     ((now() - timedelta(days=30)).strftime("%Y-%m-%d"),))
        lic_y = d.execute("SELECT SUM(gb) FROM splunk_license WHERE day=?", ((now() - timedelta(days=1)).strftime("%Y-%m-%d"),)).fetchone()[0]
        nt = db.one(d, """SELECT COUNT(*) total, SUM(created_at >= ?) last_24h, SUM(LOWER(COALESCE(status,'new')) NOT IN ('closed','resolved')) open,
            SUM(urgency IN ('critical','high') AND LOWER(COALESCE(status,'new')) NOT IN ('closed','resolved')) open_crit_high FROM splunk_notables
            WHERE created_at >= ?""", (iso(now() - timedelta(hours=24)), iso(now() - timedelta(days=30))))
        idx = db.one(d, "SELECT COUNT(*) n, SUM(size_mb)/1024.0 gb, SUM(max_time < ?) stale FROM splunk_indexes", (iso(now() - timedelta(days=1)),))
        fwd = db.one(d, "SELECT COUNT(*) n, SUM(last_seen < ?) silent FROM splunk_forwarders", (iso(now() - timedelta(hours=4)),))
        by_lob = db.rows(d, """SELECT COALESCE(l.name, 'Not in inventory') lob, COUNT(*) assets, SUM(s.ls >= ?) logging,
            SUM(r.edr_status IN ('Online','Offline') AND (s.ls IS NULL OR s.ls < ?)) edr_no_logs, SUM(s.ls IS NULL) never
            FROM asset_registry r LEFT JOIN lobs l ON r.lob_ids LIKE '%,' || l.id || ',%'
            LEFT JOIN (SELECT asset_ip, MAX(last_seen) ls FROM splunk_hosts WHERE asset_ip IS NOT NULL GROUP BY asset_ip) s ON s.asset_ip=r.ip
            WHERE r.in_inventory=1 OR r.in_edr=1 GROUP BY 1 ORDER BY assets DESC""", (cut, cut))
        lastrun = db.one(d, "SELECT * FROM splunk_runs WHERE status<>'running' ORDER BY id DESC LIMIT 1")
    return {"configured": configured(), "demo": config.DEMO, "coverage": {k: v or 0 for k, v in cov.items()},
            "hosts": {k: v or 0 for k, v in hosts.items()}, "eps": {"now": round(eps_now, 1), "avg_24h": round(eps["avg_24h"] or 0, 1),
                                                                   "peak_7d": round(peak["peak"] or 0, 1), "peak_at": peak["hour"]},
            "license": {"yesterday_gb": round(lic_y or 0, 2), "avg_gb": round(lic["avg_gb"] or 0, 2), "max_gb": round(lic["max_gb"] or 0, 2)},
            "notables": {k: v or 0 for k, v in nt.items()}, "indexes": {"n": idx["n"] or 0, "gb": round(idx["gb"] or 0, 1), "stale": idx["stale"] or 0},
            "forwarders": {"n": fwd["n"] or 0, "silent": fwd["silent"] or 0}, "by_lob": by_lob, "silent_hours": c["silent_hours"],
            "last_run": lastrun, "last": c["last"]}


def _paged(d, sql, params, p, order):
    page, size = db.page_args(p)
    total = d.execute(f"SELECT COUNT(*) FROM ({sql})", params).fetchone()[0]
    rows = db.rows(d, f"{sql} ORDER BY {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@router.get("/api/splunk/hosts")
def splunk_hosts(request: Request):
    p, c = dict(request.query_params), cfg()
    cut, w, prm = _silent_cut(c), ["1=1"], []
    st = db.multi(p, "status")
    conds = {"reporting": "last_seen >= ?", "silent": "last_seen < ?"}
    if st:
        w.append("(" + " OR ".join(conds[s] for s in st if s in conds) + ")" if any(s in conds for s in st) else "1=1")
        prm += [cut for s in st if s in conds]
    if p.get("matched") in ("0", "1"):
        w.append("asset_ip IS " + ("NOT NULL" if p["matched"] == "1" else "NULL"))
    if p.get("idx"):
        w.append("(', ' || indexes || ',') LIKE ?")
        prm.append(f"%, {p['idx']},%")
    if p.get("q"):
        w.append("(host LIKE ? OR asset_ip LIKE ? OR asset_name LIKE ? OR lob LIKE ?)")
        prm += [f"%{p['q']}%"] * 4
    sort = {"host": "host", "last_seen": "last_seen", "events_24h": "events_24h", "events_7d": "events_7d", "lob": "lob"}.get(p.get("sort") or "", "last_seen")
    with db.get_conn() as d:
        ensure(d)
        out = _paged(d, f"""SELECT host, last_seen, first_seen, events_24h, events_7d, indexes, sourcetypes, asset_ip, asset_name, lob, edr_status,
                             CASE WHEN last_seen >= ? THEN 'Reporting' ELSE 'Silent' END status FROM splunk_hosts WHERE {' AND '.join(w)}""",
                     [cut] + prm, p, f"{sort} {'ASC' if p.get('dir') == 'asc' else 'DESC'}")
    return out


@router.get("/api/splunk/coverage")
def splunk_coverage(request: Request):
    """Every asset (inventory or CrowdStrike) with its logging state: Logging / Silent / No logs."""
    p, c = dict(request.query_params), cfg()
    cut = _silent_cut(c)
    w, prm = ["(r.in_inventory=1 OR r.in_edr=1)"], []
    st = db.multi(p, "log")
    m = {"logging": "s.ls >= ?", "silent": "s.ls < ?", "none": "s.ls IS NULL"}
    if st:
        w.append("(" + " OR ".join(m[x] for x in st if x in m) + ")")
        prm += [cut for x in st if x in m and x != "none"]
    if p.get("gap") == "edr_no_logs":
        w.append("r.edr_status IN ('Online','Offline') AND (s.ls IS NULL OR s.ls < ?)")
        prm.append(cut)
    elif p.get("gap") == "logs_no_edr":
        w.append("r.edr_status NOT IN ('Online','Offline') AND s.ls >= ?")
        prm.append(cut)
    elif p.get("gap") == "exposed_no_logs":
        w.append("r.exposed=1 AND (s.ls IS NULL OR s.ls < ?)")
        prm.append(cut)
    if db.multi(p, "lob"):
        sql, v = db.or_like("r.lob_ids", [int(x) for x in db.multi(p, "lob")], "%,{},%")
        w.append(sql)
        prm += v
    if p.get("q"):
        w.append("(r.ip LIKE ? OR r.name LIKE ?)")
        prm += [f"{p['q']}%", f"%{p['q']}%"]
    sort = {"ip": "r.ip_num", "name": "r.name", "last_log": "s.ls", "lobs": "r.lobs", "edr_status": "r.edr_status"}.get(p.get("sort") or "", "s.ls")
    with db.get_conn() as d:
        ensure(d)
        return _paged(d, f"""SELECT r.ip, r.name, r.lobs, r.msps, r.edr_status, r.exposed, r.os, s.ls last_log, s.hosts splunk_hosts, s.idx indexes,
                             CASE WHEN s.ls >= ? THEN 'Logging' WHEN s.ls IS NOT NULL THEN 'Silent' ELSE 'No logs' END log_status
                             FROM asset_registry r LEFT JOIN (SELECT asset_ip, MAX(last_seen) ls, GROUP_CONCAT(host, ', ') hosts,
                             MAX(indexes) idx FROM splunk_hosts WHERE asset_ip IS NOT NULL GROUP BY asset_ip) s ON s.asset_ip=r.ip
                             WHERE {' AND '.join(w)}""", [cut] + prm, p, f"{sort} {'ASC' if p.get('dir') == 'asc' else 'DESC'} NULLS LAST, r.ip_num")


@router.get("/api/splunk/sources")
def splunk_sources():
    c = cfg()
    with db.get_conn() as d:
        ensure(d)
        rows = db.rows(d, "SELECT * FROM splunk_sources ORDER BY events_7d DESC")
        eps = {r[0]: r[1] / 3600 for r in d.execute("""SELECT idx, AVG(events) FROM splunk_eps WHERE hour >= ? GROUP BY idx""",
                                                     (iso(now() - timedelta(hours=24)),))}
    stale_cut = iso(now() - timedelta(hours=c["silent_hours"]))
    for r in rows:
        r["status"] = "Stale" if (r["last_seen"] or "") < stale_cut else "Active"
        r["index_eps_24h"] = round(eps.get(r["idx"], 0), 1)
    return {"rows": rows}


@router.get("/api/splunk/eps")
def splunk_eps(days: int = 7):
    with db.get_conn() as d:
        ensure(d)
        rows = db.rows(d, "SELECT idx, hour, events FROM splunk_eps WHERE hour >= ? ORDER BY hour", (iso(now() - timedelta(days=max(1, min(14, days)))),))
    series, idxs = {}, []
    for r in rows:
        if r["idx"] not in idxs:
            idxs.append(r["idx"])
        series.setdefault(r["hour"], {"hour": r["hour"]})[r["idx"]] = round(r["events"] / 3600, 1)
    tot = {i: sum(v.get(i, 0) for v in series.values()) for i in idxs}
    return {"indexes": sorted(idxs, key=lambda i: -tot[i]), "rows": list(series.values())}


@router.get("/api/splunk/notables")
def splunk_notables(request: Request):
    p = dict(request.query_params)
    w, prm = ["1=1"], []
    if db.multi(p, "urgency"):
        s, v = db.in_clause("n.urgency", db.multi(p, "urgency"))
        w.append(s)
        prm += v
    if db.multi(p, "status"):
        s, v = db.in_clause("COALESCE(n.status,'New')", db.multi(p, "status"))
        w.append(s)
        prm += v
    if p.get("open") == "1":
        w.append("LOWER(COALESCE(n.status,'new')) NOT IN ('closed','resolved')")
    if p.get("days"):
        w.append("n.created_at >= ?")
        prm.append(iso(now() - timedelta(days=int(p["days"]))))
    if p.get("q"):
        w.append("(n.rule LIKE ? OR n.host LIKE ? OR n.dest LIKE ? OR n.src LIKE ? OR n.user LIKE ?)")
        prm += [f"%{p['q']}%"] * 5
    sort = {"created_at": "n.created_at", "rule": "n.rule", "urgency": "n.urgency", "status": "n.status"}.get(p.get("sort") or "", "n.created_at")
    with db.get_conn() as d:
        ensure(d)
        out = _paged(d, f"""SELECT n.*, h.lob, h.edr_status FROM splunk_notables n LEFT JOIN splunk_hosts h ON h.host=n.host
                            WHERE {' AND '.join(w)}""", prm, p, f"{sort} {'ASC' if p.get('dir') == 'asc' else 'DESC'}")
        out["facets"] = {"by_rule": db.rows(d, f"""SELECT rule, COUNT(*) n FROM splunk_notables n WHERE {' AND '.join(w)} GROUP BY 1
                                                  ORDER BY n DESC LIMIT 8""", prm)}
    return out


@router.get("/api/splunk/indexes")
def splunk_indexes():
    with db.get_conn() as d:
        ensure(d)
        rows = db.rows(d, "SELECT * FROM splunk_indexes ORDER BY size_mb DESC")
        lic = {r[0]: r[1] for r in d.execute("SELECT idx, AVG(gb) FROM splunk_license WHERE day >= ? GROUP BY idx",
                                              ((now() - timedelta(days=30)).strftime("%Y-%m-%d"),))}
    for r in rows:
        r["license_gb_day"] = round(lic.get(r["name"], 0), 2)
        r["stale"] = (r["max_time"] or "") < iso(now() - timedelta(days=1))
    return {"rows": rows}


@router.get("/api/splunk/forwarders")
def splunk_forwarders():
    with db.get_conn() as d:
        ensure(d)
        rows = db.rows(d, "SELECT * FROM splunk_forwarders ORDER BY last_seen")
        versions = db.rows(d, "SELECT version, COUNT(*) n FROM splunk_forwarders GROUP BY 1 ORDER BY n DESC")
    return {"rows": rows, "versions": versions}


@router.get("/api/splunk/license")
def splunk_license(days: int = 30):
    with db.get_conn() as d:
        ensure(d)
        rows = db.rows(d, "SELECT day, idx, gb FROM splunk_license WHERE day >= ? ORDER BY day",
                       ((now() - timedelta(days=max(1, min(120, days)))).strftime("%Y-%m-%d"),))
    by_day, idxs = {}, []
    for r in rows:
        if r["idx"] not in idxs:
            idxs.append(r["idx"])
        by_day.setdefault(r["day"], {"day": r["day"]})[r["idx"]] = r["gb"]
    return {"indexes": idxs, "rows": list(by_day.values())}


@router.get("/api/splunk/sync/status")
def splunk_sync_status():
    c = cfg()
    with db.get_conn() as d:
        ensure(d)
        runs = db.rows(d, "SELECT id, started_at, finished_at, status, full, message FROM splunk_runs ORDER BY id DESC LIMIT 15")
    return {**STATUS, "configured": configured(), "demo": config.DEMO, "minutes": c["minutes"], "silent_hours": c["silent_hours"],
            "last": c["last"], "runs": runs, "schedule": [{"key": k, "label": l, "every_minutes": i} for k, l, i in STEPS]}


@router.post("/api/splunk/sync")
def splunk_sync_start(data: dict = Body(default={})):
    if not configured() and not config.DEMO:
        raise HTTPException(400, "Connect Splunk first (URL and token)")
    if not run_sync(full=bool((data or {}).get("full"))):
        return {"ok": False, "message": "A Splunk sync is already running"}
    return {"ok": True, "message": "Splunk sync started"}


@router.put("/api/splunk/sync/settings")
def splunk_sync_settings(data: dict = Body(...)):
    vals = {}
    if "minutes" in data:
        vals["splunk_sync_minutes"] = str(max(0, min(1440, int(data["minutes"]))))
    if "silent_hours" in data:
        vals["splunk_silent_hours"] = str(max(1, min(720, int(data["silent_hours"]))))
    if data.get("notable_index"):
        vals["splunk_notable_index"] = str(data["notable_index"]).strip()
    db.set_settings(vals)
    return splunk_sync_status()
