"""Ask Falcon: plain-English threat hunting over the official Falcon MCP server, built to work well with a small local model
(8B, e.g. qwen3:8b on Ollama).

Why it works with an 8B model:
  * The model never writes FQL / CQL. It picks one of a small library of tested hunt templates and fills its typed slots
    (host, IP, hash, CVE, domain, process, user, port, days…). Its answer is forced into a JSON schema whose template field is an
    enum, so it cannot invent tools or field names.
  * Entities are pulled out of the question with regular expressions first (IPs, hashes, CVEs, domains, "last 3 days"); they
    fill and check the model's slots.
  * Every slot is validated and escaped before a query is built; time ranges and limits are capped; only read-only tools.
  * Two short calls, no agent loop: plan (temperature 0, thinking off, ~1.5k tokens of context) and an optional summary of a
    compact result table (only the columns that matter, at most 25 rows).
  * Without a model (or when it fails) a keyword router answers, so the feature always works; the page says which one did.
  * Every question, plan, latency and thumbs up / down is stored (ai_asks): the evaluation set and, later, fine-tuning data.
    A built-in evaluation (EVAL) scores the configured model's routing accuracy and latency."""
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from fastapi import APIRouter, Body, HTTPException

from . import db

router = APIRouter()

TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
           "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Machine Learning", "Malware"]
GROUPS = {"severity": "severity_name", "tactic": "tactic", "technique": "technique", "host": "device.hostname", "status": "status",
          "analyst": "assigned_to_name", "product": "product"}
SEVS = ["Critical", "High", "Medium", "Low", "Informational"]


def _iso(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rx(v):
    """A value used inside a CQL regex /…/: escaped, slashes too."""
    return re.escape(v).replace("/", "\\/")


def _fql(v):
    return str(v).replace("'", "").replace("\\", "")


INCLUDE_INFO = [False]  # set per question: True when the analyst asks for informational detections / prefers them


def _sev_list(p):
    s = [x.strip().title() for x in re.split(r"[,|/ ]+", p.get("severity") or "") if x.strip()]
    return [x for x in s if x in SEVS]


# ------------------------------------------------------------------ the hunt library
# id: (title, description for the model, slots {name: (type, required)}, tool, build(params, days) -> args, columns, examples)
def _det_filter(p, d):
    f = [f"created_timestamp:>'now-{d}d'"]
    if _sev_list(p):
        f.append("severity_name:[" + ",".join(f"'{s}'" for s in _sev_list(p)) + "]")
    elif not INCLUDE_INFO[0]:  # informational detections are noise in counts and lists unless asked for
        f.append("severity_name:!'Informational'")
    if p.get("host"):
        f.append(f"device.hostname:'{_fql(p['host'])}'")
    if p.get("tactic"):
        f.append(f"tactic:'{_fql(p['tactic'])}'")
    return "+".join(f)


TEMPLATES = {
    "detections_recent": ("Recent detections", "list recent CrowdStrike detections / alerts, optionally by severity and/or one host",
                          {"severity": ("severity", False), "host": ("host", False)}, "falcon_search_detections",
                          lambda p, d: {"filter": _det_filter(p, d), "limit": 100, "sort": "created_timestamp.desc"},
                          ["created_timestamp", "severity_name", "display_name", "tactic", "technique", "device.hostname", "filename", "status", "assigned_to_name"],
                          ["show critical detections from the last 3 days", "any alerts on PAY-SER-085?"]),
    "detections_tactic": ("Detections for a MITRE tactic", "detections for one MITRE ATT&CK tactic, e.g. credential access, lateral movement",
                          {"tactic": ("tactic", True), "host": ("host", False)}, "falcon_search_detections",
                          lambda p, d: {"filter": _det_filter(p, d), "limit": 100, "sort": "created_timestamp.desc"},
                          ["created_timestamp", "severity_name", "display_name", "technique", "device.hostname", "filename", "status"],
                          ["lateral movement detections this week", "credential dumping alerts"]),
    "detection_counts": ("Detection counts", "count / rank detections grouped by severity, tactic, technique, host, status, analyst or product",
                         {"group_by": ("group", True), "severity": ("severity", False)}, "falcon_aggregate_detections",
                         lambda p, d: {"field": GROUPS.get(p.get("group_by") or "severity", "severity_name"), "type": "terms", "size": 25,
                                       "filter": _det_filter({"severity": p.get("severity")}, d)},
                         ["label", "count"], ["which hosts have the most detections", "how many alerts per tactic this month"]),
    "host_lookup": ("Find a host", "find one host by hostname or IP and show its sensor version, OS, status, last seen",
                    {"host": ("host", False), "ip": ("ip", False)}, "falcon_search_hosts",
                    lambda p, d: {"filter": f"local_ip:'{p['ip']}',external_ip:'{p['ip']}'" if p.get("ip") else f"hostname:*'*{_fql(p.get('host'))}*'", "limit": 20},
                    ["hostname", "local_ip", "external_ip", "platform_name", "os_version", "agent_version", "status", "reduced_functionality_mode", "last_seen"],
                    ["find host PAY-SER-085", "what is 10.20.0.95"]),
    "hosts_offline": ("Hosts not seen recently", "hosts whose sensor has not checked in for N days (offline / stale sensors)",
                      {}, "falcon_search_hosts", lambda p, d: {"filter": f"last_seen:<'now-{d}d'", "limit": 200, "sort": "last_seen.asc"},
                      ["hostname", "local_ip", "platform_name", "agent_version", "last_seen"], ["hosts offline for more than 7 days"]),
    "hosts_rfm": ("Sensors in reduced functionality", "hosts whose sensor runs in reduced functionality mode (RFM)", {}, "falcon_search_hosts",
                  lambda p, d: {"filter": "reduced_functionality_mode:'yes'", "limit": 200},
                  ["hostname", "local_ip", "platform_name", "os_version", "kernel_version", "agent_version", "last_seen"], ["which sensors are in RFM"]),
    "hosts_contained": ("Contained hosts", "hosts currently network-contained", {}, "falcon_search_hosts",
                        lambda p, d: {"filter": "status:'contained'", "limit": 200}, ["hostname", "local_ip", "platform_name", "status", "last_seen"],
                        ["which hosts are contained"]),
    "hosts_platform": ("Hosts by platform / sensor", "hosts on a platform (Windows, Linux, Mac), optionally one sensor version",
                       {"platform": ("platform", True), "version": ("text", False)}, "falcon_search_hosts",
                       lambda p, d: {"filter": "+".join([f"platform_name:'{p['platform']}'"] + ([f"agent_version:'{_fql(p['version'])}'"] if p.get("version") else [])), "limit": 200},
                       ["hostname", "local_ip", "os_version", "agent_version", "last_seen"], ["linux hosts on sensor 7.16.17710"]),
    "vulns_critical": ("Critical vulnerabilities", "open critical vulnerabilities from Spotlight, optionally only with an exploit, or on one host",
                       {"host": ("host", False), "exploited": ("bool", False)}, "falcon_search_vulnerabilities",
                       lambda p, d: {"filter": "+".join(["status:'open'", "cve.severity:'CRITICAL'"] + ([f"host_info.hostname:'{_fql(p['host'])}'"] if p.get("host") else [])
                                                        + (["cve.exploit_status:!'0'"] if str(p.get("exploited")).lower() in ("true", "yes", "1") else [])),
                                     "limit": 100, "facet": ["cve", "host_info"]},
                       ["cve.id", "cve.severity", "cve.exprt_rating", "cve.exploit_status_label", "host_info.hostname", "host_info.local_ip", "apps"],
                       ["critical vulnerabilities with an exploit"]),
    "vulns_cve": ("Hosts with a CVE", "which hosts have a specific CVE", {"cve": ("cve", True)}, "falcon_search_vulnerabilities",
                  lambda p, d: {"filter": f"status:'open'+cve.id:'{p['cve']}'", "limit": 500, "facet": ["cve", "host_info"]},
                  ["host_info.hostname", "host_info.local_ip", "cve.id", "cve.severity", "cve.exprt_rating", "status", "apps"], ["who has CVE-2021-44228"]),
    "vulns_host": ("Vulnerabilities on a host", "all open vulnerabilities on one host", {"host": ("host", True)}, "falcon_search_vulnerabilities",
                   lambda p, d: {"filter": f"status:'open'+host_info.hostname:'{_fql(p['host'])}'", "limit": 200, "facet": ["cve", "host_info"]},
                   ["cve.id", "cve.severity", "cve.exprt_rating", "cve.exploit_status_label", "apps"], ["vulnerabilities on PAY-SER-085"]),
    "hunt_process": ("Process hunt", "endpoints that ran a process / file name (e.g. powershell.exe, psexec, rclone)",
                     {"process": ("text", True), "host": ("host", False)}, "falcon_search_ngsiem",
                     lambda p, d: {"query_string": f"#event_simpleName=ProcessRollup2 FileName=/{_rx(p['process'])}/i"
                                                   + (f" ComputerName=/{_rx(p['host'])}/i" if p.get("host") else "")
                                                   + " | groupBy([ComputerName, FileName, UserName], limit=200)", "start": _iso(d)},
                     ["ComputerName", "FileName", "UserName", "_count"], ["where did rclone run this week", "psexec usage"]),
    "hunt_cmdline": ("Command-line hunt", "process command lines containing a string (encoded PowerShell, -enc, mimikatz, certutil -urlcache…)",
                     {"text": ("text", True), "host": ("host", False)}, "falcon_search_ngsiem",
                     lambda p, d: {"query_string": f"#event_simpleName=ProcessRollup2 CommandLine=/{_rx(p['text'])}/i"
                                                   + (f" ComputerName=/{_rx(p['host'])}/i" if p.get("host") else "")
                                                   + " | table([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=200)", "start": _iso(d)},
                     ["@timestamp", "ComputerName", "UserName", "FileName", "CommandLine"], ["command lines with -enc", "certutil urlcache"]),
    "hunt_hash": ("File hash hunt", "endpoints where a file with this MD5 / SHA1 / SHA256 hash executed", {"hash": ("hash", True)}, "falcon_search_ngsiem",
                  lambda p, d: {"query_string": f"#event_simpleName=ProcessRollup2 {_hash_field(p['hash'])}={p['hash'].lower()}"
                                                " | groupBy([ComputerName, FileName], limit=200)", "start": _iso(d)},
                  ["ComputerName", "FileName", "_count"], ["did 44d88612fea8a8f36de82e1278abb02f run anywhere"]),
    "hunt_network_ip": ("Connections to an IP", "endpoints that connected to an IP address", {"ip": ("ip", True)}, "falcon_search_ngsiem",
                        lambda p, d: {"query_string": f"#event_simpleName=NetworkConnectIP4 RemoteAddressIP4={p['ip']}"
                                                      " | groupBy([ComputerName, RemotePort], limit=200)", "start": _iso(d)},
                        ["ComputerName", "RemotePort", "_count"], ["who talked to 185.220.101.4"]),
    "hunt_port": ("Outbound to a port", "endpoints making outbound connections to a TCP / UDP port (3389, 445, 4444…)", {"port": ("port", True)},
                  "falcon_search_ngsiem",
                  lambda p, d: {"query_string": f"#event_simpleName=NetworkConnectIP4 RemotePort={int(p['port'])}"
                                                " | groupBy([ComputerName, RemoteAddressIP4], limit=200)", "start": _iso(d)},
                  ["ComputerName", "RemoteAddressIP4", "_count"], ["outbound RDP 3389 in the last day"]),
    "hunt_dns": ("DNS lookups for a domain", "endpoints that looked up a domain (DNS requests)", {"domain": ("domain", True)}, "falcon_search_ngsiem",
                 lambda p, d: {"query_string": f"#event_simpleName=DnsRequest DomainName=/{_rx(p['domain'])}$/i"
                                               " | groupBy([ComputerName, DomainName], limit=200)", "start": _iso(d)},
                 ["ComputerName", "DomainName", "_count"], ["who resolved evil-domain.example"]),
    "hunt_user_logons": ("Where a user logged on", "hosts a user account logged on to", {"user": ("user", True)}, "falcon_search_ngsiem",
                         lambda p, d: {"query_string": f"#event_simpleName=UserLogon UserName=/{_rx(p['user'])}/i"
                                                       " | groupBy([ComputerName, UserName, LogonType], limit=200)", "start": _iso(d)},
                         ["ComputerName", "UserName", "LogonType", "_count"], ["where did svc_backup log on"]),
    "intel_indicator": ("Is it a known bad indicator?", "check an IP, domain or hash against CrowdStrike threat intelligence",
                        {"indicator": ("indicator", True)}, "falcon_search_indicators",
                        lambda p, d: {"filter": f"indicator:'{_fql(p['indicator']).lower()}'", "limit": 20, "include_relations": True},
                        ["indicator", "type", "malicious_confidence", "labels", "published_date", "actors"], ["is 185.220.101.4 malicious"]),
    "intel_actor": ("Threat actor profile", "profile of a threat actor / adversary group (e.g. Scattered Spider, Fancy Bear)", {"text": ("text", True)},
                    "falcon_search_actors", lambda p, d: {"q": p["text"], "limit": 10},
                    ["name", "short_description", "target_industries", "target_countries", "motivations"], ["tell me about scattered spider"]),
    "custom_iocs": ("Custom IOCs", "custom IOCs configured in this tenant, optionally matching a value", {"text": ("text", False)}, "falcon_search_iocs",
                    lambda p, d: {"filter": f"value:*'*{_fql(p['text'])}*'" if p.get("text") else None, "limit": 100},
                    ["type", "value", "action", "severity", "description", "created_on"], ["list our custom IOCs"]),
    # answered from the data fabric (the console's own joined data) — no CrowdStrike call
    "exposed_assets": ("Internet-exposed assets", "every internet-exposed asset (any EDR state): public IPs, private IPs behind NAT, ISP-direct; "
                       "optionally one LOB, with / without EDR, or one address type",
                       {"lob": ("lob", False), "edr": ("edrfilter", False), "ip_kind": ("ipkind", False)}, "fabric:exposed_assets",
                       lambda p, d: {"lob": p.get("lob"), "edr": p.get("edr"), "ip_kind": p.get("ip_kind")},
                       ["ip", "name", "address_type", "public_ips", "lobs", "edr_status", "crit", "high", "exposure_src"],
                       ["show internet exposed hosts", "internet facing assets in Payments", "exposed assets that have EDR"]),
    "exposed_no_edr": ("Exposed assets without EDR", "internet-exposed assets that have no working CrowdStrike agent, optionally in one LOB",
                       {"lob": ("lob", False)}, "fabric:exposed_no_edr", lambda p, d: {"lob": p.get("lob")},
                       ["ip", "name", "lobs", "edr_status", "crit", "high", "exposure_src"], ["exposed assets without EDR in Payments"]),
    "coverage_gaps": ("EDR coverage gaps", "inventory nodes where EDR is feasible but no CrowdStrike agent is installed, optionally in one LOB",
                      {"lob": ("lob", False)}, "fabric:coverage_gaps", lambda p, d: {"lob": p.get("lob")},
                      ["ip", "name", "lobs", "msps", "node_type", "os", "exposed"], ["which servers are missing EDR"]),
    "kev_exposed": ("KEV / critical vulns on exposed assets", "known-exploited (CISA KEV) or critical Spotlight vulnerabilities on internet-exposed assets",
                    {}, "fabric:kev_exposed", lambda p, d: {}, ["hostname", "ip", "cve", "title", "severity", "exprt", "kev", "lobs"],
                    ["known exploited vulnerabilities on exposed hosts"]),
    "riskiest_assets": ("Riskiest assets", "assets ranked by risk score (vulnerabilities, exposure, EDR, scan age), optionally in one LOB",
                        {"lob": ("lob", False)}, "fabric:riskiest_assets", lambda p, d: {"lob": p.get("lob")}, ["ip", "name", "lob", "score", "level"],
                        ["top 10 riskiest assets in Retail Banking"]),
    "lob_posture": ("Posture per LOB", "per LOB: assets, EDR coverage, gaps, internet exposure, critical vulnerabilities", {}, "fabric:lob_posture",
                    lambda p, d: {}, ["lob", "assets", "with_edr", "gaps", "exposed", "exposed_no_edr", "crit_vulns"], ["security posture per LOB"]),
    "asset_owner": ("Who owns an asset", "owner (LOB, MSP), OS, EDR state and exposure of one host or IP", {"host": ("host", False), "ip": ("ip", False)},
                    "fabric:asset_owner", lambda p, d: {"host": p.get("host"), "ip": p.get("ip")}, ["asset", "ips", "lob", "msp", "edr", "os", "exposed"],
                    ["who owns 10.20.0.95"]),
    "asset_timeline": ("Asset timeline", "timeline of one host: detections, agent events, IP changes, scans, NDR alerts, vulnerabilities",
                       {"host": ("host", False), "ip": ("ip", False)}, "fabric:asset_timeline", lambda p, d: {"host": p.get("host"), "ip": p.get("ip"), "days": d},
                       ["at", "kind", "what", "source"], ["timeline of PAY-SER-085"]),
}


def _hash_field(h):
    return {32: "MD5HashData", 40: "SHA1HashData", 64: "SHA256HashData"}.get(len(h), "SHA256HashData")


# ------------------------------------------------------------------ entities and validation
RX = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "hash": re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|in|ru|cn|xyz|top|info|biz|co|example|onion|me|cc|tk|online|site|club|app|dev|local)\b", re.I),
    "port": re.compile(r"\bport\s*(\d{1,5})\b|\b(\d{2,5})/(?:tcp|udp)\b", re.I),
    "days": re.compile(r"\b(?:last|past|in the last)?\s*(\d{1,3})\s*(h|hr|hrs|hours?|d|days?|w|wk|weeks?|m|months?)\b", re.I),
    "host": re.compile(r"\b[A-Z][A-Z0-9]{1,}(?:-[A-Z0-9]+){1,4}\b"),
    "exe": re.compile(r"\b[\w.-]+\.(?:exe|dll|ps1|bat|sh|py|vbs|js)\b", re.I),
}


def entities(q):
    e = {}
    if m := RX["hash"].search(q):
        e["hash"] = m.group(0).lower()
    if m := RX["cve"].search(q):
        e["cve"] = m.group(0).upper()
    if m := RX["ip"].search(q):
        e["ip"] = m.group(0)
    if (m := RX["domain"].search(q)) and not RX["exe"].fullmatch(m.group(0)):
        e["domain"] = m.group(0).lower()
    if m := RX["port"].search(q):
        e["port"] = m.group(1) or m.group(2)
    if m := RX["host"].search(q):
        if not m.group(0).startswith("CVE-"):
            e["host"] = m.group(0)
    if m := RX["exe"].search(q):
        e["process"] = m.group(0)
    e["days"] = _days(q)
    try:  # names the console knows (any case, any hostname format), LOBs, MSPs, users
        from .fabric import resolve
        for k, v in resolve(q).items():
            e.setdefault(k, v)
    except Exception:  # noqa: BLE001
        pass
    return e


def _days(q):
    ql = q.lower()
    if m := RX["days"].search(ql):
        n, u = int(m.group(1)), m.group(2)[0]
        return max(1, min(90, round(n / 24) if u == "h" else n * 7 if u == "w" else n * 30 if u == "m" else n))
    for w, d in (("today", 1), ("24 hours", 1), ("yesterday", 2), ("this week", 7), ("last week", 14), ("this month", 30), ("last month", 60)):
        if w in ql:
            return d
    return None


def _ok(kind, v):
    v = str(v or "").strip()
    if not v:
        return None
    if kind == "ip":
        return v if RX["ip"].fullmatch(v) and all(0 <= int(x) <= 255 for x in v.split(".")) else None
    if kind == "hash":
        return v.lower() if RX["hash"].fullmatch(v) else None
    if kind == "cve":
        return v.upper() if RX["cve"].fullmatch(v) else None
    if kind == "domain":
        return v.lower() if re.fullmatch(r"[a-z0-9.-]{3,253}", v.lower()) and "." in v else None
    if kind == "port":
        return v if v.isdigit() and 0 < int(v) < 65536 else None
    if kind == "host":
        return v if re.fullmatch(r"[A-Za-z0-9._-]{1,63}", v) else None
    if kind == "user":
        return v if re.fullmatch(r"[\w.@\\$-]{1,64}", v) else None
    if kind == "platform":
        m = {"windows": "Windows", "linux": "Linux", "mac": "Mac", "macos": "Mac"}
        return m.get(v.lower())
    if kind == "tactic":
        return next((t for t in TACTICS if t.lower() == v.lower().replace("-", " ")), None)
    if kind == "group":
        return v.lower() if v.lower() in GROUPS else None
    if kind == "severity":
        s = [x.strip().title() for x in re.split(r"[,|/ ]+", v) if x.strip()]
        s = [x for x in s if x in SEVS]
        return ",".join(s) or None
    if kind == "indicator":
        return _ok("ip", v) or _ok("hash", v) or _ok("domain", v)
    if kind == "lob":
        from .fabric import index
        lobs = index()["lobs"]
        return lobs.get(v.lower()) or next((n for k, n in lobs.items() if k.startswith(v.lower()) or v.lower() in k), None)
    if kind == "edrfilter":
        return "with" if re.match(r"(with|yes|installed|has)", v, re.I) else "without" if re.match(r"(without|no|missing|none)", v, re.I) else None
    if kind == "ipkind":
        return "public" if re.match(r"pub", v, re.I) else "nat" if re.match(r"nat|behind", v, re.I) else "private" if re.match(r"priv", v, re.I) else None
    if kind == "bool":
        return "true" if v.lower() in ("true", "yes", "1") else None
    return re.sub(r"[^\w .:@\\/-]", "", v)[:80].strip() or None  # text


def validate(tid, params, ents):
    """Typed, escaped slots for the template (the model's values, else what the regexes found). Returns (slots, missing)."""
    _, _, slots, *_ = TEMPLATES[tid]
    out, missing = {}, []
    for name, (kind, req) in slots.items():
        v = _ok(kind, params.get(name))
        if v is None:  # fall back to what the question itself contains
            src = {"indicator": ents.get("ip") or ents.get("domain") or ents.get("hash"), "process": ents.get("process")}.get(name, ents.get(name))
            v = _ok(kind, src) if src else None
        if v is not None:
            out[name] = v
        elif req:
            missing.append(name)
    if tid in ("host_lookup", "asset_owner", "asset_timeline") and not (out.get("host") or out.get("ip")):
        missing.append("host or ip")
    return out, missing


def render(tid, slots, days):
    _, _, _, tool, build, *_ = TEMPLATES[tid]
    args = {k: v for k, v in build(slots, days).items() if v is not None}
    return tool, args


# ------------------------------------------------------------------ routing
KEYWORDS = [  # (template, words) checked in order after the entity rules
    ("hosts_rfm", ("rfm", "reduced functionality")), ("hosts_contained", ("contained", "containment", "isolated")),
    ("hosts_offline", ("offline", "not seen", "stale", "not checked in", "inactive")),
    ("detection_counts", ("how many", "count", "top ", "most ", "per tactic", "per host", "by tactic", "by host", "by severity", "trend")),
    ("hunt_cmdline", ("command line", "cmdline", "-enc", "encoded", "mimikatz", "urlcache", "base64")),
    ("hunt_user_logons", ("logon", "log on", "logged on", "logged in", "login", "log in")),
    ("intel_actor", ("actor", "adversary", "apt", "spider", " bear", "panda", "kitten", "chollima", "jackal")),
    ("custom_iocs", ("custom ioc", "our ioc", "iocs")),
    ("vulns_critical", ("vuln", "cve", "exploit", "patch", "spotlight")),
    ("hosts_platform", ("windows hosts", "linux hosts", "mac hosts", "sensor version", "on sensor")),
    ("detections_recent", ("detection", "alert", "incident")),
]


TACTIC_WORDS = {"credential dump": "Credential Access", "lsass": "Credential Access", "password spray": "Credential Access",
                "brute force": "Credential Access", "psexec": "Lateral Movement", "remote service": "Lateral Movement",
                "c2": "Command and Control", "beacon": "Command and Control", "exfil": "Exfiltration", "ransomware": "Impact",
                "persistence": "Persistence", "privilege escalation": "Privilege Escalation", "evasion": "Defense Evasion"}


FABRIC_WORDS = [
    ("asset_timeline", ("timeline", "history of", "what happened on", "what happened to")),
    ("asset_owner", ("who owns", "owner of", "which lob is", "belongs to", "who is responsible")),
    ("exposed_no_edr", ("exposed without edr", "exposed and no edr", "exposed with no edr", "exposed assets without", "exposed hosts without", "internet exposed without")),
    ("kev_exposed", ("known exploited", " kev")),
    ("coverage_gaps", ("coverage gap", "without edr", "no edr", "missing edr", "missing crowdstrike", "no agent", "not covered", "without crowdstrike", "without an agent")),
    ("riskiest_assets", ("riskiest", "highest risk", "top risk", "most risky", "risk ranking", "most at risk")),
    ("lob_posture", ("posture", "per lob", "each lob", "lob summary", "lob status", "coverage by lob", "by lob")),
]


def route_keywords(q, ents):
    ql = " " + q.lower()
    exposed = re.search(r"internet[- ]?(exposed|facing)|\bexposed\b|public[- ]facing|exposure", ql)
    if exposed and any(w in ql for w in ("no edr", "without edr", "no agent", "without an agent", "without crowdstrike", "missing edr", "no crowdstrike",
                                         "not covered", "unprotected")):
        return "exposed_no_edr"
    if exposed and not any(w in ql for w in ("vuln", "cve", "kev", "patch", "riskiest")):
        return "exposed_assets"
    for tid, words in FABRIC_WORDS:
        if any(w in ql for w in words):
            return tid
    intel = any(w in ql for w in ("malicious", "known bad", "intel", "reputation", "is it bad", "ioc for"))
    if ents.get("hash"):
        return "intel_indicator" if intel else "hunt_hash"
    if ents.get("cve"):
        return "vulns_cve"
    if ents.get("ip"):
        return "intel_indicator" if intel else "hunt_network_ip" if any(w in ql for w in ("connect", "talk", "traffic", "communicat", "reach")) else "host_lookup"
    if ents.get("domain"):
        return "intel_indicator" if intel else "hunt_dns"
    if ents.get("port") and any(w in ql for w in ("port", "connect", "outbound", "/tcp", "/udp")):
        return "hunt_port"
    if (any(t.lower() in ql for t in TACTICS if t not in ("Execution", "Impact", "Malware")) or any(w in ql for w in TACTIC_WORDS)) \
            and ("detect" in ql or "alert" in ql):
        return "detections_tactic"
    for tid, words in KEYWORDS:
        if any(w in ql for w in words):
            if tid == "vulns_critical" and ents.get("host"):
                return "vulns_host"
            if tid == "detections_recent" and any(t.lower() in ql for t in TACTICS):
                return "detections_tactic"
            return tid
    if ents.get("process") or any(w in ql for w in ("process", " ran ", "executed", "running", "psexec", "rclone", "powershell")):
        return "hunt_process"
    if ents.get("host"):
        return "host_lookup"
    return "detections_recent"


def _guess_slots(tid, q, ents):
    """Slot values the keyword router can infer (the model does this itself)."""
    ql, p = q.lower(), {}
    p["severity"] = ",".join(s for s in SEVS if s.lower() in ql) or None
    p["tactic"] = next((t for t in TACTICS if t.lower() in ql or t.lower().replace(" ", "") in ql.replace("-", "")), None)
    if not p["tactic"]:
        p["tactic"] = next((t for w, t in TACTIC_WORDS.items() if w in ql), None)
    p["group_by"] = next((g for g in GROUPS if f"by {g}" in ql or f"per {g}" in ql or (g == "host" and ("which hosts" in ql or "most detections" in ql))), "severity")
    p["platform"] = next((x for x in ("windows", "linux", "mac") if x in ql), None)
    p["exploited"] = "true" if "exploit" in ql else None
    if tid in ("hunt_process",):
        p["process"] = ents.get("process") or next((w for w in ("psexec", "rclone", "powershell", "mimikatz", "certutil", "wmic", "rundll32", "anydesk")
                                                     if w in ql), None)
    if tid == "hunt_cmdline":
        m = re.search(r"(-enc\w*|mimikatz|urlcache|base64|bypass|downloadstring|invoke-\w+|iex)", ql)
        p["text"] = m.group(1) if m else ("-enc" if "encoded" in ql else None)
    if tid in ("intel_actor",):
        m = re.search(r"(?:about|actor|adversary|profile of)\s+([a-z][\w ]{2,40})", ql)
        p["text"] = (m.group(1) if m else q).strip(" ?.")
    if tid == "hunt_user_logons":
        m = re.search(r"(?:user|account)\s+([\w.@\\$-]+)|did\s+([\w.@\\$-]+)\s+log", ql)
        p["user"] = (m.group(1) or m.group(2)) if m else None
    if tid == "exposed_assets":
        p["edr"] = "with" if re.search(r"\bwith (edr|crowdstrike|an? agent)|\bhave (edr|crowdstrike)|edr installed|protected", ql) else None
        p["ip_kind"] = ("public" if re.search(r"public ip|isp|direct", ql) else "nat" if re.search(r"\bnat|behind", ql)
                        else "private" if re.search(r"private", ql) else None)
    if tid == "custom_iocs":
        p["text"] = ents.get("domain") or ents.get("ip") or ents.get("hash")
    if tid == "hosts_platform":
        m = re.search(r"\b(\d+\.\d+\.\d+)\b", q)
        p["version"] = m.group(1) if m else None
    return {k: v for k, v in p.items() if v}


def _prompt():
    lines = []
    for tid, (title, desc, slots, *_rest) in TEMPLATES.items():
        s = ", ".join(f"{n}{'' if r else '?'}:{k}" for n, (k, r) in slots.items()) or "-"
        lines.append(f"- {tid}: {desc}. slots: {s}")
    return ("You turn a SOC analyst's question into ONE hunt from this library. Reply with JSON only.\n"
            "Pick the template that answers the question; fill only its slots (omit unknown optional slots, never invent values).\n"
            "Slot types: host=hostname, ip=IPv4, hash=md5/sha1/sha256, cve=CVE-YYYY-NNNN, domain, user, port=number, "
            f"severity=comma list of {'/'.join(SEVS)}, tactic=one of [{', '.join(TACTICS)}], group=one of [{', '.join(GROUPS)}], "
            "platform=Windows|Linux|Mac, lob=a line of business name, text=short search text, bool=true.\n"
            "days = how far back to search (default 7, max 90).\n\nLibrary:\n" + "\n".join(lines))


FEWSHOT = [
    ("any critical or high alerts on PAY-SER-085 in the last 2 days?", {"template": "detections_recent", "params": {"severity": "Critical,High", "host": "PAY-SER-085"}, "days": 2}),
    ("which hosts ran psexec this week", {"template": "hunt_process", "params": {"process": "psexec"}, "days": 7}),
    ("is 185.220.101.4 known malicious?", {"template": "intel_indicator", "params": {"indicator": "185.220.101.4"}, "days": 7}),
    ("top hosts by number of detections this month", {"template": "detection_counts", "params": {"group_by": "host"}, "days": 30}),
    ("encoded powershell commands", {"template": "hunt_cmdline", "params": {"text": "-enc"}, "days": 7}),
    ("which servers have log4shell CVE-2021-44228", {"template": "vulns_cve", "params": {"cve": "CVE-2021-44228"}, "days": 7}),
    ("credential access detections", {"template": "detections_tactic", "params": {"tactic": "Credential Access"}, "days": 7}),
    ("sensors not checked in for 10 days", {"template": "hosts_offline", "params": {}, "days": 10}),
]


def _schema():
    names = sorted({n for _, _, slots, *_ in TEMPLATES.values() for n in slots})
    return {"type": "object", "properties": {
        "template": {"type": "string", "enum": list(TEMPLATES)},
        "params": {"type": "object", "properties": {n: {"type": "string"} for n in names}},
        "days": {"type": "integer"}}, "required": ["template", "params", "days"]}


def _pref_include_info():
    try:
        from .learn import pref_flag
        return pref_flag("include_informational")
    except Exception:  # noqa: BLE001
        return False


def ai_settings():
    s = db.get_settings()
    return {"provider": s.get("ai_provider") or "ollama", "url": (s.get("ai_url") or "http://127.0.0.1:11434").rstrip("/"),
            "model": s.get("ai_model") or "qwen3:8b", "key": s.get("ai_api_key") or "", "summarize": (s.get("ai_summarize") or "1") != "0"}


def _llm(messages, schema=None, max_tokens=300, timeout=120):
    """One chat completion from the configured local model (Ollama, or any OpenAI-compatible server: vLLM, LM Studio…)."""
    cfg = ai_settings()
    if cfg["provider"] == "off":
        raise RuntimeError("AI model switched off")
    try:
        from .learn import prefs_text
        pr = prefs_text()
    except Exception:  # noqa: BLE001
        pr = []
    if pr and messages and messages[0]["role"] == "system":
        messages = [{**messages[0], "content": messages[0]["content"] + "\nAnalyst preferences (follow them): " + "; ".join(pr[-8:])}] + messages[1:]
    if cfg["provider"] == "openai":
        body = {"model": cfg["model"], "messages": messages, "temperature": 0, "max_tokens": max_tokens}
        if schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": "plan", "schema": schema}}
        r = requests.post(f"{cfg['url']}/v1/chat/completions", json=body, timeout=timeout,
                          headers={"Authorization": f"Bearer {cfg['key']}"} if cfg["key"] else {})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    body = {"model": cfg["model"], "messages": messages, "stream": False, "think": False, "keep_alive": "4h",
            "options": {"temperature": 0, "num_ctx": 4096, "num_predict": max_tokens}}
    if schema:
        body["format"] = schema
    r = requests.post(f"{cfg['url']}/api/chat", json=body, timeout=timeout)
    if r.status_code == 400 and "think" in r.text:  # older Ollama: no "think" switch
        body.pop("think")
        messages[-1]["content"] += " /no_think"
        r = requests.post(f"{cfg['url']}/api/chat", json=body, timeout=timeout)
    r.raise_for_status()
    return r.json()["message"]["content"]


def warmup():
    """Load the local model into memory in the background (first answers are otherwise slow: model load + prompt)."""
    cfg = ai_settings()
    if cfg["provider"] != "ollama":
        return

    def go():
        try:
            requests.post(f"{cfg['url']}/api/generate", json={"model": cfg["model"], "prompt": "ok", "stream": False, "keep_alive": "4h",
                                                             "options": {"num_predict": 1}}, timeout=180)
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=go, daemon=True).start()


def route_llm(q):
    msgs = [{"role": "system", "content": _prompt()}]
    for fq, fa in FEWSHOT:
        msgs += [{"role": "user", "content": fq}, {"role": "assistant", "content": json.dumps(fa)}]
    msgs.append({"role": "user", "content": q})
    out = json.loads(re.sub(r"<think>.*?</think>", "", _llm(msgs, _schema(), 200), flags=re.S).strip())
    if out.get("template") not in TEMPLATES:
        raise ValueError(f"model chose an unknown template: {out.get('template')}")
    return out


def plan(q, use_model=True):
    """Question -> {template, slots, days, tool, args, router, model_error, seconds, missing}."""
    q = (q or "").strip()[:500]
    if not q:
        raise HTTPException(400, "Ask a question")
    ents = entities(q)
    INCLUDE_INFO[0] = bool(re.search(r"\binformational|\binfo\b|all severities|every severity", q, re.I)) or _pref_include_info()
    t0, router, err, raw = time.time(), "keywords", None, None
    kw = route_keywords(q, ents)
    sure = kw != "detections_recent" or bool(re.search(r"\b(detections?|alerts?|incidents?)\b", q, re.I))
    if use_model == "auto" and sure:  # the rules are certain (37/37 on the test set): answer instantly, keep the model for unclear questions
        use_model = False
    if use_model and ai_settings()["provider"] != "off":
        try:
            raw = route_llm(q)
            router = "model"
        except Exception as e:  # noqa: BLE001 - fall back to keywords
            err = str(e)[:300]
    if raw is None:
        tid = kw
        raw = {"template": tid, "params": _guess_slots(tid, q, ents), "days": ents.get("days")}
    tid = raw["template"]
    if router == "model":  # optional filters must be in the question: a small model likes to add some that are not
        guess = _guess_slots(tid, q, ents)
        for k in ("edr", "ip_kind", "severity", "exploited", "platform"):
            if k in (raw.get("params") or {}) and not guess.get(k):
                raw["params"].pop(k, None)
    days = max(1, min(90, int(raw.get("days") or ents.get("days") or 7)))
    if ents.get("days"):
        days = ents["days"]  # an explicit time range in the question wins
    slots, missing = validate(tid, raw.get("params") or {}, ents)
    tool, args = render(tid, slots, days) if not missing else (TEMPLATES[tid][3], {})
    return {"question": q, "template": tid, "title": TEMPLATES[tid][0], "slots": slots, "days": days, "tool": tool, "args": args,
            "router": router, "model_error": err, "missing": missing, "seconds": round(time.time() - t0, 2), "entities": ents}


# ------------------------------------------------------------------ results
def _get(row, path):
    cur = row
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    if isinstance(cur, list):
        return ", ".join(str(x.get("product_name_version") or x.get("value") or x.get("name") or x) if isinstance(x, dict) else str(x) for x in cur[:5])
    if isinstance(cur, dict):
        return cur.get("name") or cur.get("value") or json.dumps(cur)[:120]
    return cur


def compact(tid, data):
    """The rows of a tool result reduced to the template's columns (what the table and the summary use)."""
    cols = TEMPLATES[tid][5]
    if isinstance(data, dict) and "buckets" in data:  # one aggregation comes back as an object, not a list
        data = {"results": [data]}
    rows = data.get("results") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return cols, []
    flat = []
    for r in rows:
        if isinstance(r, dict) and "buckets" in r:  # aggregations
            flat += [{"label": b.get("label") or b.get("key_as_string") or b.get("key"), "count": b.get("count") or b.get("doc_count")}
                     for b in r.get("buckets") or []]
        elif isinstance(r, dict):
            flat.append({c: _get(r, c) for c in cols})
    return cols, flat


def facts(tid, rows):
    """A deterministic summary (always shown, the model's text comes on top): totals and the most common values."""
    out = [f"{len(rows):,} result{'s' if len(rows) != 1 else ''}"]
    keys = {"detections_recent": ["severity_name", "device.hostname", "tactic"], "detections_tactic": ["device.hostname", "technique"],
            "hunt_process": ["ComputerName"], "hunt_cmdline": ["ComputerName", "UserName"], "vulns_critical": ["cve.id", "host_info.hostname"],
            "vulns_cve": ["host_info.hostname"], "hosts_offline": ["platform_name"], "hosts_rfm": ["os_version"], "hunt_network_ip": ["ComputerName"],
            "hunt_dns": ["ComputerName"], "hunt_port": ["ComputerName"], "exposed_no_edr": ["lobs", "edr_status"], "coverage_gaps": ["lobs", "node_type", "os"],
            "kev_exposed": ["cve", "hostname"], "exposed_assets": ["address_type", "edr_status", "lobs"], "riskiest_assets": ["lob", "level"], "asset_timeline": ["kind"]}.get(tid, [])
    for k in keys:
        cnt = {}
        for r in rows:
            v = r.get(k)
            if v not in (None, ""):
                cnt[v] = cnt.get(v, 0) + 1
        if cnt:
            top = sorted(cnt.items(), key=lambda x: -x[1])[:3]
            out.append(f"{len(cnt):,} distinct {k.split('.')[-1].replace('_', ' ')}: " + ", ".join(f"{a} ({b})" for a, b in top))
    return out


def summarize(question, tid, rows):
    sample = rows[:25]
    msgs = [{"role": "system", "content": "You are a SOC analyst. Summarize hunt results for a colleague in 3 to 5 short bullet points: what was found, "
                                          "which hosts or users stand out, and one sensible next step. Use only the data given; say so if it is empty. "
                                          "No preamble."},
            {"role": "user", "content": f"Question: {question}\nHunt: {TEMPLATES[tid][0]}\nTotal rows: {len(rows)}\n"
                                        f"Rows (first {len(sample)}):\n{json.dumps(sample, default=str)[:6000]}"}]
    txt = _llm(msgs, None, 260)
    return re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()


def ask(question=None, edited=None, summarize_it=None, use_model=True):
    """Plan (or take the analyst's edited plan), run it through Falcon MCP, return compact rows + facts (+ the model's summary)."""
    from . import falconmcp
    p = plan(question, use_model=use_model) if edited is None else _replan(edited)
    if p["missing"]:
        p.update(ok=False, need=p["missing"])
        _log(p, None, None)
        return p
    if p["tool"].startswith("fabric:"):  # answered from the data fabric, no CrowdStrike call
        from . import fabric
        t0 = time.time()
        try:
            data, err = fabric.run_local(p["tool"].split(":", 1)[1], p["args"]), None
        except Exception as e:  # noqa: BLE001
            data, err = [], str(e)[:300]
        res = {"ok": err is None, "error": err, "id": None, "seconds": round(time.time() - t0, 2), "data": {"results": data}}
    elif p["tool"] == "falcon_search_ngsiem":  # event hunts: direct API (or MCP / sample data) through the CQL runner
        from . import cql
        r = cql.run(p["args"]["query_string"], p["days"], p["question"])
        res = {"ok": r["ok"], "error": r["error"], "id": None, "seconds": r["seconds"], "data": {"results": r["rows"]}}
        p["via"] = r["via"]
    else:
        res = falconmcp.call(p["tool"], p["args"], user="ask-falcon")
    cols, rows = compact(p["template"], res.get("data") or {}) if res["ok"] else (TEMPLATES[p["template"]][5], [])
    p.update(ok=res["ok"], error=res.get("error"), run_id=res["id"], run_seconds=res["seconds"], columns=cols, rows=rows[:500], total=len(rows),
             facts=facts(p["template"], rows) if res["ok"] else [], summary=None, summary_error=None)
    want = ai_settings()["summarize"] if summarize_it is None else summarize_it
    if p.get("model_error"):
        p["summary_error"] = "the AI model is not available (see Settings → AI model)"
    elif res["ok"] and want and ai_settings()["provider"] != "off":
        t0 = time.time()
        try:
            p["summary"] = summarize(p["question"], p["template"], rows)
        except Exception as e:  # noqa: BLE001
            p["summary_error"] = str(e)[:200]
        p["summary_seconds"] = round(time.time() - t0, 2)
    p["id"] = _log(p, res, p.get("summary"))
    return p


def _replan(e):
    tid = e.get("template")
    if tid not in TEMPLATES:
        raise HTTPException(400, "Unknown hunt template")
    q = e.get("question") or ""
    ents = entities(q)
    days = max(1, min(90, int(e.get("days") or 7)))
    slots, missing = validate(tid, e.get("slots") or {}, {})
    tool, args = render(tid, slots, days) if not missing else (TEMPLATES[tid][3], {})
    return {"question": q, "template": tid, "title": TEMPLATES[tid][0], "slots": slots, "days": days, "tool": tool, "args": args,
            "router": "edited", "model_error": None, "missing": missing, "seconds": 0, "entities": ents}


def _log(p, res, summary):
    cfg = ai_settings()
    with db.get_conn() as c:
        return c.execute("""INSERT INTO ai_asks(at, question, router, model, template, slots, days, plan_seconds, run_id, ok, total, summary,
                            summary_seconds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (db.now_iso(), p["question"], p["router"], cfg["model"] if p["router"] == "model" else None, p["template"],
                          json.dumps(p["slots"]), p["days"], p["seconds"], res["id"] if res else None, 1 if p.get("ok") else 0, p.get("total"),
                          summary, p.get("summary_seconds"))).lastrowid


# ------------------------------------------------------------------ evaluation (is the model good enough?)
EVAL = [
    ("show me critical detections from today", "detections_recent"), ("any high severity alerts on RB-DAT-143", "detections_recent"),
    ("lateral movement detections last 14 days", "detections_tactic"), ("credential dumping alerts", "detections_tactic"),
    ("which hosts have the most detections", "detection_counts"), ("alerts per tactic this month", "detection_counts"),
    ("find host PAY-SER-085", "host_lookup"), ("what is 10.20.0.95", "host_lookup"),
    ("which machines have been offline for 2 weeks", "hosts_offline"), ("sensors in reduced functionality mode", "hosts_rfm"),
    ("list contained hosts", "hosts_contained"), ("linux hosts running sensor 7.16.17710", "hosts_platform"),
    ("critical vulnerabilities that have an exploit", "vulns_critical"), ("who is affected by CVE-2023-20198", "vulns_cve"),
    ("what vulnerabilities does NC-SER-014 have", "vulns_host"), ("where did rclone.exe run", "hunt_process"),
    ("psexec executions in the last 3 days", "hunt_process"), ("powershell with -encodedcommand", "hunt_cmdline"),
    ("certutil -urlcache downloads", "hunt_cmdline"),
    ("did e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 execute anywhere", "hunt_hash"),
    ("which endpoints connected to 45.83.64.1", "hunt_network_ip"), ("outbound connections on port 4444", "hunt_port"),
    ("who resolved badupdate.xyz", "hunt_dns"), ("where did svc_backup log on", "hunt_user_logons"),
    ("is 45.83.64.1 malicious", "intel_indicator"), ("is the domain badupdate.xyz known bad", "intel_indicator"),
    ("tell me about scattered spider", "intel_actor"), ("show our custom iocs", "custom_iocs"),
    ("any ransomware alerts this week", "detections_tactic"), ("top analysts by alerts handled", "detection_counts"),
    ("which internet exposed assets have no EDR", "exposed_no_edr"), ("show internet exposed hosts", "exposed_assets"),
    ("list all internet facing assets in payments", "exposed_assets"), ("exposed public IPs directly on the ISP link", "exposed_assets"), ("servers missing crowdstrike in payments", "coverage_gaps"),
    ("known exploited vulnerabilities on exposed hosts", "kev_exposed"), ("top 10 riskiest assets", "riskiest_assets"),
    ("security posture per LOB", "lob_posture"), ("who owns 10.20.0.95", "asset_owner"), ("timeline of PAY-SER-085 for the last month", "asset_timeline"),
]
EVAL_STATE = {"running": False, "done": 0, "total": len(EVAL), "result": None}


def run_eval():
    if EVAL_STATE["running"]:
        raise HTTPException(409, "An evaluation is already running")
    EVAL_STATE.update(running=True, done=0, result=None)

    def work():
        rows, t0 = [], time.time()
        try:
            for q, want in EVAL:
                ents, s = entities(q), time.time()
                try:
                    got, err = route_llm(q)["template"], None
                except Exception as e:  # noqa: BLE001
                    got, err = None, str(e)[:120]
                kw = route_keywords(q, ents)
                rows.append({"question": q, "expected": want, "model": got, "keywords": kw, "seconds": round(time.time() - s, 2), "error": err})
                EVAL_STATE["done"] += 1
            n = len(rows)
            res = {"at": db.now_iso(), "model": ai_settings()["model"], "n": n,
                   "model_accuracy": round(100 * sum(r["model"] == r["expected"] for r in rows) / n),
                   "keyword_accuracy": round(100 * sum(r["keywords"] == r["expected"] for r in rows) / n),
                   "avg_seconds": round(sum(r["seconds"] for r in rows) / n, 2), "total_seconds": round(time.time() - t0, 1), "rows": rows}
            EVAL_STATE["result"] = res
            db.set_settings({"ai_eval_last": json.dumps(res)})
        finally:
            EVAL_STATE["running"] = False
    threading.Thread(target=work, daemon=True).start()
    return EVAL_STATE


# ------------------------------------------------------------------ routes
@router.get("/api/ai/config")
def ai_config():
    cfg = ai_settings()
    models, reach = [], None
    if cfg["provider"] == "ollama":
        try:
            r = requests.get(f"{cfg['url']}/api/tags", timeout=3)
            models = [m["name"] for m in r.json().get("models", [])]
            reach = True
        except Exception as e:  # noqa: BLE001
            reach, models = False, []
            cfg["error"] = f"Ollama not reachable at {cfg['url']}: {str(e)[:120]}"
    last = db.jloads(db.get_settings().get("ai_eval_last"), None)
    return {**{k: v for k, v in cfg.items() if k != "key"}, "key_set": bool(cfg["key"]), "reachable": reach, "models": models,
            "model_installed": cfg["model"] in models or f"{cfg['model']}:latest" in models if cfg["provider"] == "ollama" else None,
            "eval": {k: v for k, v in (last or {}).items() if k != "rows"} if last else None, "eval_running": EVAL_STATE["running"]}


@router.put("/api/ai/config")
def ai_config_save(data: dict = Body(...)):
    vals = {}
    if data.get("provider") in ("ollama", "openai", "off"):
        vals["ai_provider"] = data["provider"]
    for k in ("url", "model"):
        if data.get(k):
            vals[f"ai_{k}"] = str(data[k]).strip()
    if data.get("api_key"):
        vals["ai_api_key"] = str(data["api_key"]).strip()
    if "summarize" in data:
        vals["ai_summarize"] = "1" if data["summarize"] else "0"
    db.set_settings(vals)
    warmup()
    return ai_config()


@router.post("/api/ai/test")
def ai_test():
    t0 = time.time()
    try:
        p = route_llm("any critical detections on PAY-SER-085 today?")
        return {"ok": True, "seconds": round(time.time() - t0, 2), "plan": p}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "seconds": round(time.time() - t0, 2), "error": str(e)[:300]}


@router.get("/api/ai/templates")
def ai_templates():
    return {"rows": [{"id": tid, "title": t[0], "description": t[1], "slots": [{"name": n, "type": k, "required": r} for n, (k, r) in t[2].items()],
                      "tool": t[3], "examples": t[6]} for tid, t in TEMPLATES.items()]}


@router.post("/api/ai/plan")
def ai_plan(data: dict = Body(...)):
    p = plan(data.get("question"), use_model=data.get("use_model", True))
    return p


@router.post("/api/ai/ask")
def ai_ask(data: dict = Body(...)):
    return ask(data.get("question"), data.get("plan"), data.get("summarize"), use_model=data.get("use_model", "auto"))


@router.post("/api/ai/summarize")
def ai_summarize(data: dict = Body(...)):
    """On-demand summary of a result table (chat answers show facts instantly; the model summary is a button)."""
    rows = data.get("rows") or []
    tid = data.get("template") if data.get("template") in TEMPLATES else "hunt_process"
    t0 = time.time()
    try:
        txt = summarize(str(data.get("question") or "")[:500], tid, rows[:25])
        return {"summary": txt, "seconds": round(time.time() - t0, 1), "model": ai_settings()["model"]}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"The model did not answer: {str(e)[:160]}") from e


@router.post("/api/ai/feedback")
def ai_feedback(data: dict = Body(...)):
    with db.get_conn() as c:
        c.execute("UPDATE ai_asks SET feedback=?, note=? WHERE id=?", (1 if data.get("good") else -1, str(data.get("note") or "")[:500], int(data["id"])))
    return {"ok": True}


@router.get("/api/ai/asks")
def ai_asks(limit: int = 50):
    with db.get_conn() as c:
        rows = db.rows(c, "SELECT * FROM ai_asks ORDER BY id DESC LIMIT ?", (min(500, limit),))
    for r in rows:
        r["slots"] = db.jloads(r["slots"], {})
    return {"rows": rows}


@router.post("/api/ai/eval")
def ai_eval():
    return run_eval()


@router.get("/api/ai/eval")
def ai_eval_status():
    last = EVAL_STATE["result"] or db.jloads(db.get_settings().get("ai_eval_last"), None)
    return {"running": EVAL_STATE["running"], "done": EVAL_STATE["done"], "total": EVAL_STATE["total"], "result": last}
