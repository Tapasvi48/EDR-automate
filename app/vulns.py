"""Vulnerability scans (Nessus-style exports) per LOB, matched to the LOB inventory and to Falcon."""
import hashlib
import json
import re
from collections import OrderedDict

from fastapi import APIRouter, Body, HTTPException, Request

from . import db, inventory
from .exporter import xlsx_response

router = APIRouter()

VULN_FIELDS = [
    ("ip", "IP Address", True), ("name", "Vulnerability Name", True), ("severity", "Severity", True),
    ("protocol", "Protocol", False), ("port", "Port", False), ("synopsis", "Synopsis", False),
    ("description", "Description", False), ("solution", "Steps to Remediate", False), ("plugin_text", "Plugin Text", False),
    ("see_also", "See Also", False), ("cve", "CVE", False), ("exploit_ease", "Exploit Ease", False),
    ("plugin_id", "Plugin ID", False), ("first_discovered", "First Discovered", False), ("last_observed", "Last Observed", False),
    ("vuln_pub_date", "Vuln Publication Date", False), ("patch_pub_date", "Patch Publication Date", False),
    ("remarks", "Remarks", False), ("os", "Operating System", False),
]
VULN_KEYS = [k for k, _, _ in VULN_FIELDS]
ALIASES = {
    "ip": ["ipaddress", "ip", "host", "hostip", "ipv4", "asset", "target"],
    "name": ["vulnerabilityname", "name", "pluginname", "vulnerability", "title", "vulnname"],
    "severity": ["severity", "risk", "riskfactor", "sev"],
    "protocol": ["protocol", "proto"],
    "port": ["port"],
    "synopsis": ["synopsis", "summary"],
    "description": ["description", "details"],
    "solution": ["stepstoremediate", "solution", "remediation", "fix", "recommendation"],
    "plugin_text": ["plugintext", "pluginoutput", "output", "evidence"],
    "see_also": ["seealso", "references", "reference"],
    "cve": ["cve", "cves", "cveid"],
    "exploit_ease": ["exploitease", "exploitability", "exploitavailable"],
    "plugin_id": ["pluginid", "plugin", "id", "qid"],
    "first_discovered": ["firstdiscovered", "firstseen", "firstfound", "discovered"],
    "last_observed": ["lastobserved", "lastseen", "lastfound", "observed"],
    "vuln_pub_date": ["vulnpublicationdate", "vulnerabilitypublicationdate", "publicationdate", "published"],
    "patch_pub_date": ["patchpublicationdate", "patchdate", "patchpublished"],
    "remarks": ["remarks", "remark", "comments", "comment", "notes"],
    "os": ["operatingsystem", "os", "osname", "ostype", "osversion", "hostos"],
}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SEV_MAP = {"critical": "Critical", "4": "Critical", "high": "High", "3": "High", "medium": "Medium", "moderate": "Medium",
           "2": "Medium", "low": "Low", "1": "Low", "info": "Info", "informational": "Info", "none": "Info", "0": "Info", "": "Info"}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    from .filetemplates import custom_aliases
    custom = custom_aliases("vulnerability")
    for f in VULN_KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == alias), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def norm_severity(v):
    s = str(v or "").strip().lower()
    return SEV_MAP.get(s, s.title() if s.title() in SEV_RANK else "Info")


def build_findings(parsed, mapping):
    if not mapping.get("ip"):
        raise ValueError("Map the IP Address column")
    if not mapping.get("name") and not mapping.get("plugin_id"):
        raise ValueError("Map the Vulnerability Name or Plugin ID column")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    mapped = set(v for v in mapping.values() if v)
    extra_headers = [h for h in parsed["headers"] if h not in mapped and _norm(h) not in ("sno", "srno", "slno", "serialno", "sn")]
    out, warnings, dups, no_ip = OrderedDict(), [], 0, 0
    for r in parsed["rows"]:
        f = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in VULN_KEYS}
        f["ip"] = inventory.norm_ip(f["ip"])
        if not f["ip"]:
            no_ip += 1
            continue
        f["severity"] = norm_severity(f["severity"])
        f["protocol"] = f["protocol"].lower()
        for k in ("first_discovered", "last_observed", "vuln_pub_date", "patch_pub_date"):
            f[k] = db.parse_ts(f[k]) or f[k]
        f["extra"] = {h: r[idx[h]] for h in extra_headers if r[idx[h]]}
        key = "|".join([f["ip"], f["plugin_id"] or hashlib.sha1(f["name"].encode()).hexdigest()[:12], f["port"], f["protocol"]])
        if key in out:
            dups += 1
            continue
        out[key] = f
    if dups:
        warnings.append(f"{dups:,} repeated rows (same IP + plugin + port) merged")
    if no_ip:
        warnings.append(f"{no_ip:,} rows skipped: no IP address")
    return out, warnings


def _scan_date(findings):
    dates = [f["last_observed"] for f in findings.values() if re.match(r"^\d{4}-\d\d-\d\dT", f["last_observed"] or "")]
    return max(dates) if dates else db.now_iso()


def _plan(c, lob_id, findings):
    existing = {r["finding_key"]: r for r in c.execute(
        "SELECT id, finding_key, ip, status, first_discovered FROM vuln_findings WHERE lob_id=?", (lob_id,))}
    scanned = {f["ip"] for f in findings.values()}
    new = [k for k in findings if k not in existing]
    reopened = [k for k in findings if k in existing and existing[k]["status"] == "fixed"]
    still = [k for k in findings if k in existing and existing[k]["status"] in ("open", "accepted")]
    fixed = [r for k, r in existing.items() if r["status"] in ("open", "accepted") and r["ip"] in scanned and k not in findings]
    return existing, scanned, new, reopened, still, fixed


def preview(c, lob_id, findings, warnings):
    _, scanned, new, reopened, still, fixed = _plan(c, lob_id, findings)
    sev = {}
    for f in findings.values():
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    first = not c.execute("SELECT 1 FROM vuln_scans WHERE lob_id=? LIMIT 1", (lob_id,)).fetchone()
    return {"rows": len(findings), "hosts": len(scanned), "new": len(new), "reopened": len(reopened), "still_open": len(still),
            "fixed": len(fixed), "severity": sev, "warnings": warnings, "scan_date": _scan_date(findings), "first_scan": first,
            "sample": [{k: findings[key][k] for k in ("ip", "severity", "name", "port", "plugin_id")} for key in list(findings)[:50]]}


COLS = ["ip", "ip_num", "plugin_id", "name", "severity", "sev_rank", "protocol", "port", "synopsis", "description", "solution",
        "plugin_text", "see_also", "cve", "exploit_ease", "first_discovered", "last_observed", "vuln_pub_date", "patch_pub_date",
        "remarks", "os", "extra"]


def commit(c, lob_id, findings, warnings, *, filename, note, uploaded_by, mapping):
    existing, scanned, new, reopened, still, fixed = _plan(c, lob_id, findings)
    scan_date = _scan_date(findings)
    sid = c.execute("""INSERT INTO vuln_scans(lob_id, filename, note, uploaded_by, uploaded_at, scan_date, rows, hosts,
                       new_findings, fixed_findings, reopened, still_open, mapping, warnings) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (lob_id, filename, note, uploaded_by, db.now_iso(), scan_date, len(findings), len(scanned), len(new),
                     len(fixed), len(reopened), len(still), json.dumps(mapping), json.dumps(warnings))).lastrowid

    def vals(f):
        return [f["ip"], db.ip_to_num(f["ip"]), f["plugin_id"], f["name"], f["severity"], SEV_RANK[f["severity"]], f["protocol"],
                f["port"], f["synopsis"], f["description"], f["solution"], f["plugin_text"], f["see_also"], f["cve"],
                f["exploit_ease"], f["first_discovered"], f["last_observed"], f["vuln_pub_date"], f["patch_pub_date"],
                f["remarks"], f["os"], json.dumps(f["extra"])]

    c.executemany(f"""INSERT INTO vuln_findings(lob_id, finding_key, {', '.join(COLS)}, status, first_scan_id, last_scan_id)
                      VALUES (?,?,{','.join('?' * len(COLS))},'open',?,?)""",
                  [(lob_id, k, *vals(findings[k]), sid, sid) for k in new])
    # a later scan with an empty cell must not wipe a value we already have
    upd = ", ".join(f"{col}=COALESCE(NULLIF(?, ''), {col})" for col in COLS)
    reopened_set = set(reopened)
    for k in still + reopened:  # first discovered = earliest date seen in any scan
        old_fd, new_fd = existing[k]["first_discovered"] or "", findings[k]["first_discovered"] or ""
        findings[k]["first_discovered"] = min(d for d in (old_fd, new_fd) if d) if (old_fd or new_fd) else ""
    c.executemany(f"""UPDATE vuln_findings SET {upd}, status='open', last_scan_id=?, fixed_scan_id=NULL, fixed_at=NULL,
                      reopened=reopened + ? WHERE id=?""",
                  [(*vals(findings[k]), sid, 1 if k in reopened_set else 0, existing[k]["id"]) for k in still + reopened])
    c.executemany("UPDATE vuln_findings SET status='fixed', fixed_scan_id=?, fixed_at=? WHERE id=?",
                  [(sid, scan_date, r["id"]) for r in fixed])
    last_by_ip = {}
    for f in findings.values():
        d = f["last_observed"] if re.match(r"^\d{4}-", f["last_observed"] or "") else scan_date
        last_by_ip[f["ip"]] = max(last_by_ip.get(f["ip"], ""), d)
    c.executemany("INSERT OR REPLACE INTO vuln_scan_hosts(lob_id, ip, scan_id, scanned_at) VALUES (?,?,?,?)",
                  [(lob_id, ip, sid, d) for ip, d in last_by_ip.items()])
    from .inventory import refresh_soon  # full re-join: vuln assets, NIAM, risk, asset registry
    refresh_soon(c, label="Matching the scan with inventory and CrowdStrike")
    return {"scan_id": sid, "rows": len(findings), "hosts": len(scanned), "new": len(new), "reopened": len(reopened),
            "still_open": len(still), "fixed": len(fixed), "scan_date": scan_date, "warnings": warnings}


# Nessus plugin 11936 "OS Identification" (severity None / Info) reports the detected OS in its plugin output:
#   Remote operating system : Microsoft Windows Server 2019 Standard
#   Confidence level : 99
#   Method : MSRPC
# When Nessus is unsure it lists several candidates, one per line; the first is its best guess.
OS_PLUGIN = "11936"
_OS_LINE = re.compile(r"Remote operating system\s*:\s*(.+)", re.I)


def os_from_plugin(text):
    m = _OS_LINE.search(re.sub(r"</?plugin_output>", "", text or ""))
    return m.group(1).strip()[:200] if m else None


def scan_os(c):
    """{ip: (os, method)} from uploaded scans: plugin 11936 output, else an Operating System column. Latest scan wins."""
    out = {}
    for r in c.execute("""SELECT ip, plugin_id, name, plugin_text, os FROM vuln_findings
                          WHERE plugin_id=? OR name LIKE 'OS Identification%' OR COALESCE(os,'')<>''
                          ORDER BY COALESCE(last_observed,''), id""", (OS_PLUGIN,)):
        found = None
        if r["plugin_id"] == OS_PLUGIN or (r["name"] or "").lower().startswith("os identification"):
            found = os_from_plugin(r["plugin_text"])
        if found:
            out[r["ip"]] = (found, "plugin")
        elif r["os"] and out.get(r["ip"], (None, None))[1] != "plugin":
            out[r["ip"]] = (r["os"].strip()[:200], "column")
    return out


def refresh_assets(c, lob_id=None):
    """Rebuild vuln_assets: every scanned IP with open-finding counts, inventory row and Falcon status."""
    where, params = ("WHERE lob_id=?", (lob_id,)) if lob_id else ("", ())
    c.execute(f"DELETE FROM vuln_assets {where}", params)
    counts = {}
    for r in c.execute(f"""SELECT lob_id, ip, SUM(status='open' AND sev_rank=4) crit, SUM(status='open' AND sev_rank=3) high,
            SUM(status='open' AND sev_rank=2) med, SUM(status='open' AND sev_rank=1) low, SUM(status='open' AND sev_rank=0) info,
            SUM(status='fixed') fixed, SUM(status='accepted') accepted, SUM(status='open' AND sev_rank>=3 AND LOWER(COALESCE(exploit_ease,'')) LIKE '%exploit%'
            AND LOWER(exploit_ease) NOT LIKE 'no %') exploitable FROM vuln_findings {where} GROUP BY lob_id, ip""", params):
        counts[(r["lob_id"], r["ip"])] = r
    scans = {(r["lob_id"], r["ip"]): r for r in c.execute(f"SELECT * FROM vuln_scan_hosts {where}", params)}
    keys = set(counts) | set(scans)
    if not keys:
        return
    inv = {}
    for r in c.execute(f"""SELECT lob_id, ip, item_key, node_name, msp, msp_id, node_type, live, edr_state, matched_aid, cs_hostname
                           FROM inventory_current {where} ORDER BY applicable DESC""", params):
        inv.setdefault((r["lob_id"], (r["ip"] or "").strip()), r)
    hosts = {}
    for r in c.execute("""SELECT aid, hostname, connection_ip, console_state, online_state, last_seen FROM hosts
                          WHERE console_state<>'hidden' ORDER BY console_state='active' DESC, online_state='online' DESC, last_seen DESC"""):
        if r["connection_ip"]:  # CrowdStrike assets by connection IP
            hosts.setdefault(r["connection_ip"], r)
    hmap = {}
    for r in c.execute("SELECT aid, lob_id, msp_id FROM host_map"):
        hmap.setdefault((r["aid"], r["lob_id"]), r["msp_id"])
    mspname = {r["id"]: r["name"] for r in c.execute("SELECT id, name FROM msps")}
    rows = []
    for key in keys:
        lid, ip = key
        cn, sc, iv = counts.get(key), scans.get(key), inv.get(key)
        h = hosts.get(ip)
        if iv:
            status, aid, hostname = iv["edr_state"], iv["matched_aid"], iv["cs_hostname"]
            if status == "Not Installed":  # a weak match to a different machine is not this node's agent
                aid, hostname = None, None
            msp, msp_id = iv["msp"], iv["msp_id"]
        else:
            aid = h["aid"] if h else None
            hostname = h["hostname"] if h else None
            if not h:
                status = "Not Installed"
            elif h["console_state"] == "removed":
                status = "Offline"  # agent left the console (policy removal / deleted / old import)
            else:
                status = "Online" if h["online_state"] == "online" else "Offline"
            msp_id = hmap.get((aid, lid)) if aid else None
            msp = mspname.get(msp_id)
        rows.append((lid, ip, db.ip_to_num(ip), sc["scan_id"] if sc else None, sc["scanned_at"] if sc else None,
                     (cn["crit"] or 0) if cn else 0, (cn["high"] or 0) if cn else 0, (cn["med"] or 0) if cn else 0,
                     (cn["low"] or 0) if cn else 0, (cn["info"] or 0) if cn else 0, (cn["fixed"] or 0) if cn else 0,
                     1 if iv else 0, iv["item_key"] if iv else None, iv["node_name"] if iv else None, msp, msp_id,
                     iv["node_type"] if iv else None, iv["live"] if iv else None, aid, hostname, status, (cn["exploitable"] or 0) if cn else 0,
                     (cn["accepted"] or 0) if cn else 0))
    c.executemany("""INSERT INTO vuln_assets(lob_id, ip, ip_num, last_scan_id, last_scanned_at, crit, high, med, low, info, fixed,
                     in_inventory, item_key, node_name, msp, msp_id, node_type, live, aid, hostname, edr_status, exploitable, accepted)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    # top-vulnerability panels read this small table instead of grouping crores of findings on every page load
    c.execute(f"DELETE FROM vuln_plugin_stats {where}", params)
    c.execute(f"""INSERT INTO vuln_plugin_stats(lob_id, plugin_id, name, severity, sev_rank, hosts, findings, cve)
                  SELECT lob_id, plugin_id, MAX(name), MAX(severity), MAX(sev_rank), COUNT(DISTINCT ip), COUNT(*), MAX(cve) FROM vuln_findings
                  {where + (' AND' if where else 'WHERE')} status='open' AND sev_rank>=2 GROUP BY lob_id, plugin_id, name""", params)


# ------------------------------------------------------------------ queries
def _filters(p, alias_f="f", alias_a="a"):
    w, params = [], []
    db.add_filter(w, params, db.id_filter(p, "lob", f"{alias_a}.lob_id"))
    db.add_filter(w, params, db.id_filter(p, "msp", f"{alias_a}.msp_id", f"{alias_a}.msp_id IS NULL"))
    if p.get("edr_status"):
        vals = p["edr_status"].split("|")
        w.append(f"{alias_a}.edr_status IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("no_edr") == "1":
        w.append(f"{alias_a}.edr_status NOT IN ('Online','Offline')")
    if p.get("in_inventory") in ("0", "1"):
        w.append(f"{alias_a}.in_inventory=?")
        params.append(int(p["in_inventory"]))
    return w, params


FINDING_SORTS = {"severity": "f.sev_rank", "ip": "f.ip_num", "name": "f.name COLLATE NOCASE", "last_observed": "f.last_observed",
                 "first_discovered": "f.first_discovered", "port": "CAST(f.port AS INTEGER)", "plugin_id": "CAST(f.plugin_id AS INTEGER)",
                 "status": "f.status", "lob": "l.name", "msp": "a.msp"}


def findings_query(p):
    w, params = _filters(p)
    sts = [x for x in (db.multi(p, "status") or (["open"] if "status" not in p else [])) if x in ("open", "fixed", "accepted")]
    if sts:
        db.add_filter(w, params, db.in_clause("f.status", sts))
    if p.get("severity"):
        vals = p["severity"].split("|")
        w.append(f"f.severity IN ({','.join('?' * len(vals))})")
        params += vals
    elif p.get("min_sev"):
        w.append("f.sev_rank>=?")
        params.append(int(p["min_sev"]))
    if p.get("ip"):
        w.append("f.ip=?")
        params.append(p["ip"])
    if p.get("plugin_id"):
        w.append("f.plugin_id=?")
        params.append(p["plugin_id"])
    if p.get("exploit") == "1":
        w.append("LOWER(f.exploit_ease) LIKE '%exploit%' AND LOWER(f.exploit_ease) NOT LIKE 'no %'")
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            w.append(f"f.ip IN ({','.join('?' * len(terms))})")
            params += [db.canon_ip(t) for t in terms]
        else:
            like = f"%{q}%"
            w.append("(f.ip LIKE ? OR f.name LIKE ? OR f.cve LIKE ? OR f.plugin_id=? OR a.hostname LIKE ? OR a.node_name LIKE ?)")
            params += [q + "%", like, like, q, like, like]
    sort = FINDING_SORTS.get(p.get("sort") or "", "f.sev_rank")
    direction = "ASC" if (p.get("dir") or "desc") == "asc" else "DESC"
    frm = """vuln_findings f JOIN lobs l ON l.id=f.lob_id
             LEFT JOIN vuln_assets a ON a.lob_id=f.lob_id AND a.ip=f.ip"""
    where = ("WHERE " + " AND ".join(w)) if w else ""
    order = f"ORDER BY {sort} {direction}, f.sev_rank DESC, f.ip_num, f.id"
    return frm, where, params, order


FINDING_LIST_COLS = """f.id, f.lob_id, l.name lob, f.ip, f.plugin_id, f.name, f.severity, f.sev_rank, f.protocol, f.port, f.cve,
    f.exploit_ease, f.first_discovered, f.last_observed, f.status, f.fixed_at, f.reopened, f.exception_ref, a.msp, a.msp_id, a.node_name,
    a.hostname, a.aid, a.edr_status, a.in_inventory, a.last_scanned_at"""

ASSET_SORTS = {"ip": "a.ip_num", "crit": "a.crit", "high": "a.high", "med": "a.med", "low": "a.low", "last_scanned_at": "a.last_scanned_at",
               "edr_status": "a.edr_status", "msp": "a.msp", "lob": "l.name", "node_name": "a.node_name COLLATE NOCASE",
               "total": "(a.crit+a.high+a.med+a.low)"}


def assets_query(p):
    w, params = _filters(p, alias_a="a")
    if p.get("vulnerable") == "1":
        w.append("(a.crit + a.high + a.med + a.low) > 0")
    if p.get("min_sev") == "4":
        w.append("a.crit > 0")
    elif p.get("min_sev") == "3":
        w.append("(a.crit + a.high) > 0")
    if p.get("stale_scan"):
        w.append("(a.last_scanned_at IS NULL OR a.last_scanned_at < datetime('now', ?))")
        params.append(f"-{int(p['stale_scan'])} days")
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            w.append(f"a.ip IN ({','.join('?' * len(terms))})")
            params += [db.canon_ip(t) for t in terms]
        else:
            like = f"%{q}%"
            w.append("(a.ip LIKE ? OR a.hostname LIKE ? OR a.node_name LIKE ?)")
            params += [q + "%", like, like]
    sort = ASSET_SORTS.get(p.get("sort") or "", "a.crit DESC, a.high")
    direction = "ASC" if (p.get("dir") or "desc") == "asc" else "DESC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return "vuln_assets a JOIN lobs l ON l.id=a.lob_id", where, params, f"ORDER BY {sort} {direction}, a.ip_num"


def summary(c, lob_id=None):
    where, params = ("WHERE f.lob_id=?", (lob_id,)) if lob_id else ("", ())
    aw, ap = ("WHERE a.lob_id=?", (lob_id,)) if lob_id else ("", ())
    # from the per-IP counts (vuln_assets), not by scanning every finding
    sev = db.one(c, f"""SELECT SUM(a.crit) crit, SUM(a.high) high, SUM(a.med) med, SUM(a.low) low, SUM(a.info) info, SUM(a.fixed) fixed,
        SUM(COALESCE(a.accepted, 0)) accepted, COUNT(DISTINCT CASE WHEN a.crit + a.high + a.med + a.low > 0 THEN a.ip END) vulnerable_hosts
        FROM vuln_assets a {aw}""", ap)
    assets = db.one(c, f"""SELECT COUNT(*) scanned, SUM(a.crit + a.high > 0 AND a.edr_status NOT IN ('Online','Offline')) crit_high_no_edr,
        SUM(a.edr_status NOT IN ('Online','Offline')) no_edr, SUM(a.in_inventory=0) not_in_inventory,
        MAX(a.last_scanned_at) last_scan FROM vuln_assets a {aw}""", ap)
    by_lob = db.rows(c, """SELECT l.id, l.name, SUM(a.crit) crit, SUM(a.high) high, SUM(a.med) med, SUM(a.low) low, COUNT(*) scanned,
        SUM(a.crit + a.high + a.med + a.low > 0) vulnerable, SUM(a.crit + a.high > 0 AND a.edr_status NOT IN ('Online','Offline')) crit_high_no_edr,
        SUM(a.in_inventory=0) not_in_inventory, MAX(a.last_scanned_at) last_scan
        FROM vuln_assets a JOIN lobs l ON l.id=a.lob_id GROUP BY l.id ORDER BY crit DESC, high DESC""")
    by_msp = db.rows(c, f"""SELECT a.lob_id, l.name lob, a.msp_id, COALESCE(a.msp, 'Unassigned') msp, SUM(a.crit) crit, SUM(a.high) high,
        SUM(a.med) med, SUM(a.low) low, COUNT(*) scanned, SUM(a.crit + a.high + a.med + a.low > 0) vulnerable,
        SUM(a.crit + a.high > 0 AND a.edr_status NOT IN ('Online','Offline')) crit_high_no_edr, MAX(a.last_scanned_at) last_scan
        FROM vuln_assets a JOIN lobs l ON l.id=a.lob_id {aw} GROUP BY a.lob_id, a.msp_id ORDER BY crit DESC, high DESC""", ap)
    top = db.rows(c, f"""SELECT plugin_id, name, MAX(severity) severity, MAX(sev_rank) sev_rank, SUM(hosts) hosts, MAX(cve) cve
        FROM vuln_plugin_stats {'WHERE lob_id=?' if lob_id else ''} GROUP BY plugin_id, name ORDER BY sev_rank DESC, hosts DESC LIMIT 15""",
        (lob_id,) if lob_id else ())
    edr = db.rows(c, f"""SELECT a.edr_status label, COUNT(*) n, SUM(a.crit) crit, SUM(a.high) high FROM vuln_assets a {aw}
        GROUP BY 1 ORDER BY n DESC""", ap)
    scans = db.rows(c, f"""SELECT s.*, l.name lob FROM vuln_scans s JOIN lobs l ON l.id=s.lob_id
        {'WHERE s.lob_id=?' if lob_id else ''} ORDER BY s.id DESC LIMIT 50""", (lob_id,) if lob_id else ())
    return {"severity": {k: (v or 0) for k, v in sev.items()}, "assets": {k: (v or 0) if k != "last_scan" else v for k, v in assets.items()},
            "by_lob": by_lob, "by_msp": by_msp, "top": top, "edr": edr, "scans": scans}


# ------------------------------------------------------------------ routes
def _page(p):
    return db.page_args(p)


@router.post("/api/vulns/parse")
def vuln_parse(data: dict = Body(...)):
    parsed = inventory.peek_upload(data["token"], data.get("sheet"), data.get("header_row"))  # streams: any size
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": parsed["row_count"],
            "sample": parsed["sample"], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in VULN_FIELDS]}


def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    findings, warnings = build_findings(parsed, mapping)
    if not findings:
        raise ValueError("No vulnerability rows found with this mapping")
    return parsed, mapping, findings, warnings


@router.post("/api/lobs/{lob_id}/vulns/preview")
def vuln_preview(lob_id: int, data: dict = Body(...)):
    """Stage the file (streamed, any size) and count what the import would change. Small files answer at once; big ones return
    {job, status} to poll at /api/vulns/jobs/{job}."""
    with db.get_conn() as c:
        if not db.one(c, "SELECT id FROM lobs WHERE id=?", (lob_id,)):
            raise HTTPException(404, "LOB not found")
    job = start_stage(lob_id, data)
    j = _wait(job)
    if j.get("status") == "error":
        raise HTTPException(400, j.get("error") or "The file could not be read")
    if j.get("status") == "ready":
        return {**j["preview"], "job": job}
    return {"job": job, "status": j.get("status"), "read": j.get("read", 0)}


@router.post("/api/lobs/{lob_id}/vulns/commit")
def vuln_commit(lob_id: int, data: dict = Body(...)):
    job = data.get("job")
    if not job:  # older clients: stage first
        job = start_stage(lob_id, data)
        j = _wait(job)
        if j.get("status") != "ready":
            raise HTTPException(409, j.get("error") or "Large file: check it first, then import")
    start_commit(job, lob_id, data)
    j = _wait(job, until=("done", "error"))
    if j.get("status") == "error":
        raise HTTPException(500, j.get("error"))
    if j.get("status") == "done":
        return j["result"]
    return {"job": job, "status": j.get("status"), "step": j.get("step")}


@router.get("/api/vulns/summary")
def vuln_summary(lob: int = 0):
    with db.get_conn() as c:
        return summary(c, lob or None)


@router.get("/api/vulns/findings")
def vuln_findings(request: Request):
    p = dict(request.query_params)
    page, size = _page(p)
    frm, where, params, order = findings_query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {FINDING_LIST_COLS} FROM {frm} {where} {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
        _add_fixes(c, rows)
    return {"total": total, "rows": rows}


def _add_fixes(c, rows):
    """'Fix available': the Satellite errata that fix a finding's CVEs on that host."""
    from .satellite import cve_fixes, fix_for
    fixes = cve_fixes(c, {r["ip"] for r in rows})
    for r in rows:
        fx = fix_for(fixes, r["ip"], r.get("cve"))
        r["fix"] = fx
        r["fix_text"] = ", ".join(e["id"] + ("" if e["installable"] else " (not yet installable)") for e in fx)


FINDING_EXPORT = [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP Address"), ("hostname", "Falcon Hostname"), ("node_name", "Inventory Node Name"),
                  ("edr_status", "EDR Status"), ("severity", "Severity"), ("name", "Vulnerability Name"), ("plugin_id", "Plugin ID"),
                  ("protocol", "Protocol"), ("port", "Port"), ("cve", "CVE"), ("exploit_ease", "Exploit Ease"),
                  ("status", "Status"), ("first_discovered", "First Discovered"), ("last_observed", "Last Observed"),
                  ("fixed_at", "Fixed At"), ("synopsis", "Synopsis"), ("solution", "Steps to Remediate"),
                  ("vuln_pub_date", "Vuln Publication Date"), ("patch_pub_date", "Patch Publication Date"), ("see_also", "See Also"),
                  ("remarks", "Remarks"), ("last_scanned_at", "Last Scan")]


@router.get("/api/vulns/findings/export")
def vuln_findings_export(request: Request):
    p = dict(request.query_params)
    frm, where, params, order = findings_query(p)
    with db.get_conn() as c:
        rows = db.rows(c, f"""SELECT {FINDING_LIST_COLS}, f.synopsis, f.solution, f.vuln_pub_date, f.patch_pub_date, f.see_also, f.remarks
                              FROM {frm} {where} {order} LIMIT 500000""", params)
        _add_fixes(c, rows)
    return xlsx_response([("Vulnerabilities", FINDING_EXPORT + [("fix_text", "Fix Available (Satellite erratum)")], rows)], "vulnerabilities")


@router.get("/api/vulns/findings/{fid}")
def vuln_finding(fid: int):
    with db.get_conn() as c:
        f = db.one(c, f"""SELECT f.*, l.name lob, a.msp, a.node_name, a.hostname, a.aid, a.edr_status, a.in_inventory, a.last_scanned_at
                          FROM vuln_findings f JOIN lobs l ON l.id=f.lob_id LEFT JOIN vuln_assets a ON a.lob_id=f.lob_id AND a.ip=f.ip
                          WHERE f.id=?""", (fid,))
        if not f:
            raise HTTPException(404)
        f["extra"] = db.jloads(f["extra"], {})
        f["exception"] = db.one(c, "SELECT * FROM vuln_exceptions WHERE exception_id=?", (f["exception_ref"],)) if f.get("exception_ref") else None
        f["other_hosts"] = c.execute("SELECT COUNT(DISTINCT ip) FROM vuln_findings WHERE plugin_id=? AND status='open'",
                                     (f["plugin_id"],)).fetchone()[0]
    return f


ASSET_COLS = """a.*, l.name lob"""
ASSET_EXPORT = [("lob", "LOB"), ("msp", "MSP"), ("ip", "IP Address"), ("hostname", "Falcon Hostname"), ("node_name", "Inventory Node Name"),
                ("node_type", "Node Type"), ("in_inventory", "In Inventory"), ("edr_status", "EDR Status"), ("crit", "Critical"),
                ("high", "High"), ("med", "Medium"), ("low", "Low"), ("fixed", "Fixed"), ("last_scanned_at", "Last Scan")]


@router.get("/api/vulns/assets")
def vuln_assets(request: Request):
    p = dict(request.query_params)
    page, size = _page(p)
    frm, where, params, order = assets_query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {ASSET_COLS} FROM {frm} {where} {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@router.get("/api/vulns/assets/export")
def vuln_assets_export(request: Request):
    frm, where, params, order = assets_query(dict(request.query_params))
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT {ASSET_COLS} FROM {frm} {where} {order}", params)
    for r in rows:
        r["in_inventory"] = "Yes" if r["in_inventory"] else "No"
    return xlsx_response([("Scanned hosts", ASSET_EXPORT, rows)], "vulnerable_hosts")


@router.delete("/api/lobs/{lob_id}/vulns")
def vuln_clear(lob_id: int):
    with db.get_conn() as c:
        for t in ("vuln_findings", "vuln_scans", "vuln_scan_hosts", "vuln_assets"):
            c.execute(f"DELETE FROM {t} WHERE lob_id=?", (lob_id,))
        from .inventory import refresh_soon
        refresh_soon(c)
    return {"ok": True}


# ------------------------------------------------------------------ scale: streaming, staged scan import (crores of rows)
# The file is streamed into vuln_stage in chunks (never held in memory), the preview counts (new / still open / reopened /
# fixed) are SQL over the staged rows, and the commit is a handful of set-based statements. Both run as background jobs with
# progress, so a 1-crore-row scan never blocks the site. After the commit only what a scan changes is refreshed: the scanned
# assets of that LOB, exceptions, risk scores and the registry's vulnerability counts (exposure is rebuilt in the background).
import threading
import time
import uuid as _uuid

STAGE_COLS = ["finding_key", "ip", "ip_num", "plugin_id", "name", "severity", "sev_rank", "protocol", "port", "synopsis", "description",
              "solution", "plugin_text", "see_also", "cve", "exploit_ease", "first_discovered", "last_observed", "vuln_pub_date",
              "patch_pub_date", "remarks", "os", "extra"]
JOBS = {}
_JOBS_LOCK = threading.Lock()
CHUNK = 50_000
WAIT_SMALL = 25  # seconds a preview / commit request waits before handing back a job id to poll


def _job(job_id, **kw):
    with _JOBS_LOCK:
        j = JOBS.setdefault(job_id, {"id": job_id})
        j.update(kw)
        for old in [k for k, v in JOBS.items() if v.get("finished_at", "9") < db.now_iso()[:10]]:  # forget yesterday's jobs
            JOBS.pop(old, None)
        return dict(j)


def _stage_table(job_id):
    if not re.fullmatch(r"[0-9a-f]{16}|[a-z]+", job_id or ""):
        raise ValueError("bad job id")
    return f"vstage_{job_id}"


def _ensure_stage(c):  # old shared staging table (kept for databases that have it)
    pass


_KEY_IDX = None


def _row_fn(idx, mapping, extra_headers):
    """A fast per-row converter: column positions resolved once, repeated IPs / dates parsed once (an IP has many findings)."""
    from functools import lru_cache
    pos = {k: idx[mapping[k]] for k in VULN_KEYS if mapping.get(k) in idx}
    xpos = [(h, idx[h]) for h in extra_headers]
    ip_c = lru_cache(maxsize=200_000)(lambda v: inventory.norm_ip(v))
    num_c = lru_cache(maxsize=200_000)(db.ip_to_num)
    ts_c = lru_cache(maxsize=50_000)(lambda v: (db.parse_ts(v) or v) if v else "")
    sev_c = lru_cache(maxsize=1000)(norm_severity)

    def get(r, k):
        i = pos.get(k)
        return r[i].strip() if i is not None else ""

    def conv(r):
        ip = ip_c(get(r, "ip"))
        if not ip:
            return None
        sev = sev_c(get(r, "severity"))
        plugin, name, port, proto = get(r, "plugin_id"), get(r, "name"), get(r, "port"), get(r, "protocol").lower()
        extra = {h: r[i] for h, i in xpos if r[i]}
        key = "|".join([ip, plugin or hashlib.sha1(name.encode()).hexdigest()[:12], port, proto])
        return (key, ip, num_c(ip), plugin, name, sev, SEV_RANK[sev], proto, port, get(r, "synopsis"), get(r, "description"),
                get(r, "solution"), get(r, "plugin_text"), get(r, "see_also"), get(r, "cve"), get(r, "exploit_ease"),
                ts_c(get(r, "first_discovered")), ts_c(get(r, "last_observed")), ts_c(get(r, "vuln_pub_date")),
                ts_c(get(r, "patch_pub_date")), get(r, "remarks"), get(r, "os"), json.dumps(extra) if extra else "{}")
    return conv


def _stage(job_id, lob_id, token, sheet, header_row, mapping):
    if not mapping.get("ip"):
        raise ValueError("Map the IP Address column")
    if not mapping.get("name") and not mapping.get("plugin_id"):
        raise ValueError("Map the Vulnerability Name or Plugin ID column")
    st = inventory.stream_upload(token, sheet, header_row)
    idx = {h: i for i, h in enumerate(st["headers"])}
    mapped = set(v for v in mapping.values() if v)
    extra_headers = [h for h in st["headers"] if h not in mapped and _norm(h) not in ("sno", "srno", "slno", "serialno", "sn")]
    conv = _row_fn(idx, mapping, extra_headers)
    tbl = _stage_table(job_id)
    read = no_ip = 0
    t0 = time.time()
    with db.get_conn() as c:
        db.bulk(c)
        cols = ", ".join(f"{k} {'INTEGER' if k in ('ip_num', 'sev_rank') else 'TEXT'}" for k in STAGE_COLS)
        c.execute(f"DROP TABLE IF EXISTS {tbl}")
        c.execute(f"CREATE TABLE {tbl} ({cols})")  # no index while loading: appends are cheap
        ins = f"INSERT INTO {tbl}({', '.join(STAGE_COLS)}) VALUES ({','.join('?' * len(STAGE_COLS))})"
        buf = []
        for r in st["rows"]:
            read += 1
            f = conv(r)
            if f is None:
                no_ip += 1
            else:
                buf.append(f)
            if len(buf) >= CHUNK:
                c.executemany(ins, buf)
                buf = []
                if read % (CHUNK * 4) == 0:
                    c.commit()
                    _job(job_id, read=read, rate=round(read / max(0.1, time.time() - t0)))
        if buf:
            c.executemany(ins, buf)
        _job(job_id, read=read, step="removing repeated rows")
        # repeated IP + plugin + port rows: keep the first one, then index once (one sort instead of millions of random inserts)
        c.execute(f"""DELETE FROM {tbl} WHERE rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER (PARTITION BY finding_key ORDER BY rowid) rn
                      FROM {tbl}) WHERE rn > 1)""")
        c.execute(f"CREATE UNIQUE INDEX ix_{tbl}_k ON {tbl}(finding_key)")
        c.execute(f"CREATE INDEX ix_{tbl}_ip ON {tbl}(ip)")
        staged = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
    warnings = []
    if read - no_ip - staged:
        warnings.append(f"{read - no_ip - staged:,} repeated rows (same IP + plugin + port) merged")
    if no_ip:
        warnings.append(f"{no_ip:,} rows skipped: no IP address")
    if not staged:
        raise ValueError("No vulnerability rows found with this mapping")
    return {"filename": st["filename"], "read": read, "staged": staged, "warnings": warnings, "mapping": mapping, "lob_id": lob_id}


def _stage_preview(c, job_id, lob_id, warnings):
    tbl = _stage_table(job_id)
    q = lambda sql, *a: c.execute(sql, a).fetchone()[0]  # noqa: E731
    rows = q(f"SELECT COUNT(*) FROM {tbl}")
    hosts = q(f"SELECT COUNT(DISTINCT ip) FROM {tbl}")
    seen = q(f"""SELECT COUNT(*), SUM(f.status='fixed') FROM {tbl} s JOIN vuln_findings f ON f.lob_id=? AND f.finding_key=s.finding_key""", lob_id)
    reopened = q(f"""SELECT COUNT(*) FROM {tbl} s JOIN vuln_findings f ON f.lob_id=? AND f.finding_key=s.finding_key WHERE f.status='fixed'""", lob_id)
    fixed = q(f"""SELECT COUNT(*) FROM vuln_findings f WHERE f.lob_id=? AND f.status IN ('open','accepted')
                  AND f.ip IN (SELECT ip FROM {tbl}) AND NOT EXISTS (SELECT 1 FROM {tbl} s WHERE s.finding_key=f.finding_key)""", lob_id)
    sev = {r[0]: r[1] for r in c.execute(f"SELECT severity, COUNT(*) FROM {tbl} GROUP BY 1")}
    scan_date = q(f"SELECT MAX(last_observed) FROM {tbl} WHERE last_observed GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*'") or db.now_iso()
    first = not c.execute("SELECT 1 FROM vuln_scans WHERE lob_id=? LIMIT 1", (lob_id,)).fetchone()
    sample = db.rows(c, f"SELECT ip, severity, name, port, plugin_id FROM {tbl} LIMIT 50")
    new = rows - seen
    return {"rows": rows, "hosts": hosts, "new": new, "reopened": reopened, "still_open": seen - reopened, "fixed": fixed,
            "severity": sev, "warnings": warnings, "scan_date": scan_date, "first_scan": first, "sample": sample}


def _commit_stage(c, job_id, lob_id, filename, note, uploaded_by, mapping, warnings, progress=lambda s: None, pv=None):
    tbl = _stage_table(job_id)
    pv = pv or _stage_preview(c, job_id, lob_id, warnings)
    scan_date = pv["scan_date"]
    sid = c.execute("""INSERT INTO vuln_scans(lob_id, filename, note, uploaded_by, uploaded_at, scan_date, rows, hosts,
                       new_findings, fixed_findings, reopened, still_open, mapping, warnings) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (lob_id, filename, note, uploaded_by, db.now_iso(), scan_date, pv["rows"], pv["hosts"], pv["new"], pv["fixed"],
                     pv["reopened"], pv["still_open"], json.dumps(mapping), json.dumps(warnings))).lastrowid
    lo, hi = c.execute(f"SELECT MIN(rowid), MAX(rowid) FROM {tbl}").fetchone()
    BATCH = 250_000  # rows per transaction: other writers (tagging, edits) wait for one batch, not the whole crore-row import

    def batches(label):
        for a in range(lo or 0, (hi or 0) + 1, BATCH):
            progress(f"{label} · {min(100, round(100 * (a - (lo or 0)) / max(1, (hi or 0) - (lo or 0) + 1)))}%")
            yield a, a + BATCH - 1
            c.commit()
    for a, b in batches("marking fixed findings"):  # the scanned IPs of this batch: their findings this scan no longer reports
        c.execute(f"""UPDATE vuln_findings SET status='fixed', fixed_scan_id=?, fixed_at=? WHERE lob_id=? AND status IN ('open','accepted')
                      AND ip IN (SELECT DISTINCT ip FROM {tbl} WHERE rowid BETWEEN ? AND ?)
                      AND NOT EXISTS (SELECT 1 FROM {tbl} s WHERE s.finding_key=vuln_findings.finding_key)""", (sid, scan_date, lob_id, a, b))
    # three narrow updates instead of one wide one: SQLite re-indexes every row whose indexed columns appear in SET, even when the
    # value is the same, so the bulk statement leaves the indexed ones (ip, plugin, port, status, severity) alone
    keyed = {"finding_key", "first_discovered", "ip", "ip_num", "plugin_id", "port", "protocol", "severity", "sev_rank"}
    sets = ", ".join(f"{k}=COALESCE(NULLIF(s.{k}, ''), vuln_findings.{k})" for k in STAGE_COLS if k not in keyed)  # empty cell keeps our value
    for a, b in batches("updating findings seen again"):
        c.execute(f"""UPDATE vuln_findings SET status='open', reopened=reopened + (vuln_findings.status='fixed'), fixed_scan_id=NULL, fixed_at=NULL
                      FROM {tbl} s WHERE s.rowid BETWEEN ? AND ? AND vuln_findings.lob_id=? AND vuln_findings.finding_key=s.finding_key
                      AND vuln_findings.status<>'open'""", (a, b, lob_id))
        c.execute(f"""UPDATE vuln_findings SET severity=s.severity, sev_rank=s.sev_rank FROM {tbl} s
                      WHERE s.rowid BETWEEN ? AND ? AND vuln_findings.lob_id=? AND vuln_findings.finding_key=s.finding_key
                      AND vuln_findings.sev_rank<>s.sev_rank""", (a, b, lob_id))
        c.execute(f"""UPDATE vuln_findings SET {sets},
                      first_discovered=CASE WHEN COALESCE(vuln_findings.first_discovered,'')='' THEN s.first_discovered
                                            WHEN COALESCE(s.first_discovered,'')='' THEN vuln_findings.first_discovered
                                            ELSE MIN(vuln_findings.first_discovered, s.first_discovered) END, last_scan_id=?
                      FROM {tbl} s WHERE s.rowid BETWEEN ? AND ? AND vuln_findings.lob_id=? AND vuln_findings.finding_key=s.finding_key""",
                  (sid, a, b, lob_id))
    if pv["new"]:
        cols = ", ".join(STAGE_COLS)
        for a, b in batches("adding new findings"):
            c.execute(f"""INSERT INTO vuln_findings(lob_id, {cols}, status, first_scan_id, last_scan_id)
                          SELECT ?, {', '.join('s.' + k for k in STAGE_COLS)}, 'open', ?, ? FROM {tbl} s WHERE s.rowid BETWEEN ? AND ?
                          AND NOT EXISTS (SELECT 1 FROM vuln_findings f WHERE f.lob_id=? AND f.finding_key=s.finding_key)""",
                      (lob_id, sid, sid, a, b, lob_id))
    c.execute(f"""INSERT OR REPLACE INTO vuln_scan_hosts(lob_id, ip, scan_id, scanned_at)
                 SELECT ?, ip, ?, MAX(CASE WHEN last_observed GLOB '[0-9][0-9][0-9][0-9]-*' THEN last_observed ELSE ? END)
                 FROM {tbl} GROUP BY ip""", (lob_id, sid, scan_date))
    c.execute(f"DROP TABLE IF EXISTS {tbl}")
    return {"scan_id": sid, **{k: pv[k] for k in ("rows", "hosts", "new", "reopened", "still_open", "fixed", "scan_date")}, "warnings": warnings}


def after_scan(c, lob_id, progress=lambda s: None):
    """What a scan changes, and nothing else: exceptions, the LOB's scanned assets, risk scores, registry vulnerability counts.
    IPs no source knew before need a registry rebuild (new rows, exposure by a public scanned IP): queued in the background."""
    from . import posture, registry, sod
    progress("applying exceptions (SOD)")
    sod.apply(c)
    progress("matching scanned IPs with inventory and CrowdStrike")
    refresh_assets(c, lob_id)
    progress("risk scores")
    posture.refresh(c)
    progress("asset registry counts")
    new_ips = registry.refresh_vuln_counts(c)
    if new_ips:
        from .inventory import refresh_soon
        refresh_soon(c, label="Adding newly scanned IPs to the asset registry", registry_only=True)


def _run_job(job_id, fn):
    def go():
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            _job(job_id, status="error", error=str(e)[:500], finished_at=db.now_iso())
    threading.Thread(target=go, daemon=True, name=f"vuln-{job_id[:6]}").start()


def _wait(job_id, until=("ready", "done", "error")):
    t = time.time()
    while time.time() - t < WAIT_SMALL:
        j = JOBS.get(job_id) or {}
        if j.get("status") in until:
            return dict(j)
        time.sleep(0.15)
    return dict(JOBS.get(job_id) or {})


def _cleanup_stage():
    """Drop staging tables of previews that were never imported (other jobs, or from before a restart)."""
    try:
        with db.get_conn() as c:
            live = {_stage_table(j) for j, v in JOBS.items() if v.get("status") in ("staging", "ready", "committing")}
            for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vstage_%'").fetchall():
                if t not in live:
                    c.execute(f"DROP TABLE IF EXISTS {t}")
            c.execute("DROP TABLE IF EXISTS vuln_stage")
    except Exception:  # noqa: BLE001
        pass


def start_stage(lob_id, data):
    _cleanup_stage()
    job_id = _uuid.uuid4().hex[:16]
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    _job(job_id, status="staging", lob_id=lob_id, read=0, started_at=db.now_iso(), token=data["token"])

    def work():
        info = _stage(job_id, lob_id, data["token"], data.get("sheet"), data.get("header_row"), mapping)
        with db.get_conn() as c:
            pv = _stage_preview(c, job_id, lob_id, info["warnings"])
        _job(job_id, status="ready", preview=pv, info=info, read=info["read"], finished_at=db.now_iso())
    _run_job(job_id, work)
    return job_id


def start_commit(job_id, lob_id, data):
    j = JOBS.get(job_id)
    if not j or j.get("status") != "ready" or j.get("lob_id") != lob_id:
        raise HTTPException(409, "Check the file again before importing (the staged scan expired or belongs to another LOB)")
    info = j["info"]
    _job(job_id, status="committing", step="starting", started_at=db.now_iso())

    def work():
        t0 = time.time()
        with db.get_conn() as c:
            db.bulk(c)
            res = _commit_stage(c, job_id, lob_id, info["filename"], data.get("note", ""), data.get("uploaded_by", ""), info["mapping"],
                                info["warnings"], progress=lambda s: _job(job_id, step=s), pv=j.get("preview"))
            c.commit()
            after_scan(c, lob_id, progress=lambda s: _job(job_id, step=s))
        _job(job_id, status="done", result={**res, "seconds": round(time.time() - t0, 1)}, finished_at=db.now_iso())
    _run_job(job_id, work)


@router.get("/api/vulns/jobs/{job_id}")
def vuln_job(job_id: str):
    j = JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "Unknown or expired import job")
    return {k: v for k, v in j.items() if k != "info"}
