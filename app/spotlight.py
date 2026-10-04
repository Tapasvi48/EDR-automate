"""CrowdStrike Spotlight vulnerabilities as their own section (CrowdStrike → Spotlight vulnerabilities).

Read-only view of spotlight_vulns (fetched on each sync with the "Vulnerabilities: Read" scope). It is deliberately kept
apart from the VA-scan vulnerabilities: nothing here is written to vuln_findings / vuln_assets, so vulnerability counts,
risk scores, exposure and the Overview stay exactly as they were. Each finding is linked to its agent (hostname, connection
IP, LOB) and says whether the VA scan reports the same CVE on that IP."""
from fastapi import APIRouter, Request

from . import config, db
from .exporter import xlsx_response

router = APIRouter()
SEV_ORDER = "CASE s.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
EXPLOITABLE = ("Available", "Easily accessible", "Actively used")


def _scanner_cves(c):
    """{ip: {CVE, ...}} of open VA-scan findings (for the 'also in VA scan' column)."""
    out = {}
    for r in c.execute("SELECT ip, cve FROM vuln_findings WHERE status='open' AND COALESCE(cve,'')<>''"):
        out.setdefault(r["ip"], set()).update(x.strip().upper() for x in r["cve"].split(",") if x.strip())
    return out


def _va_names(c):
    """{CVE: VA-scan finding name}: a readable name for Spotlight findings that come without one."""
    out = {}
    for r in c.execute("SELECT cve, name FROM vuln_findings WHERE COALESCE(cve,'')<>'' AND COALESCE(name,'')<>''"):
        for x in r["cve"].split(","):
            out.setdefault(x.strip().upper(), r["name"])
    return out


def _where(p):
    w, params = [], []
    if p.get("severity"):
        vals = [v.upper() for v in p["severity"].split("|")]
        w.append(f"UPPER(s.severity) IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("exprt"):
        vals = [v.upper() for v in p["exprt"].split("|")]
        w.append(f"UPPER(s.exprt) IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("exploit") == "1":
        w.append(f"s.exploit_status IN ({','.join('?' * len(EXPLOITABLE))})")
        params += list(EXPLOITABLE)
    if p.get("cve"):
        w.append("UPPER(s.cve)=?")
        params.append(p["cve"].upper())
    if p.get("aid"):
        w.append("s.aid=?")
        params.append(p["aid"])
    if db.multi(p, "lob"):
        lobs = [int(x) for x in db.multi(p, "lob")]
        w.append(f"EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=s.aid AND hm.lob_id IN ({','.join('?' * len(lobs))}))")
        params += lobs
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(s.cve LIKE ? OR s.hostname LIKE ? OR h.connection_ip LIKE ? OR s.product LIKE ? OR s.remediation LIKE ? OR s.title LIKE ? "
                 "OR s.description LIKE ?)")
        params += [like] * 7
    return ("WHERE " + " AND ".join(w)) if w else "", params


BASE = """FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid"""
COLS = """s.id, s.aid, s.hostname, COALESCE(NULLIF(h.connection_ip,''), s.ip) ip, s.cve, s.severity, s.score, s.exprt, s.exploit_status,
          s.product, s.remediation, s.status, s.created_at, s.updated_at, h.online_state, h.console_state, s.title, s.published, s.kev,
          s.app_vendor, s.vector,
          (SELECT GROUP_CONCAT(DISTINCT l.name) FROM host_map hm JOIN lobs l ON l.id=hm.lob_id WHERE hm.aid=s.aid) lob"""


def _rows(c, p, limit=None, offset=0):
    where, params = _where(p)
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"SELECT {COLS} {BASE} {where} ORDER BY {SEV_ORDER}, s.score DESC, s.hostname {lim}", params)
    scan = _scanner_cves(c)
    names = _va_names(c)
    for r in rows:
        r["in_scanner"] = (r["cve"] or "").upper() in scan.get(r["ip"] or "", set())
        r["title"] = r.get("title") or names.get((r["cve"] or "").upper()) or display_name(r)
    if p.get("in_scanner") in ("0", "1"):  # applied after the join with the VA scan
        rows = [r for r in rows if r["in_scanner"] == (p["in_scanner"] == "1")]
    return rows


@router.get("/api/spotlight/summary")
def spotlight_summary():
    with db.get_conn() as c:
        s = db.one(c, f"""SELECT COUNT(*) findings, COUNT(DISTINCT aid) hosts, COUNT(DISTINCT cve) cves,
            SUM(UPPER(severity)='CRITICAL') critical, SUM(UPPER(severity)='HIGH') high, SUM(UPPER(severity)='MEDIUM') medium,
            SUM(UPPER(severity)='LOW') low, SUM(exploit_status IN ({','.join('?' * len(EXPLOITABLE))})) exploitable,
            SUM(UPPER(exprt) IN ('CRITICAL','HIGH')) exprt_high, MAX(fetched_at) fetched_at FROM spotlight_vulns""", list(EXPLOITABLE))
        scan = _scanner_cves(c)
        both = only_spot = 0
        for r in c.execute("SELECT COALESCE(NULLIF(h.connection_ip,''), s.ip) ip, s.cve FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid"):
            if (r["cve"] or "").upper() in scan.get(r["ip"] or "", set()):
                both += 1
            else:
                only_spot += 1
        lobs = db.rows(c, """SELECT l.id, l.name, COUNT(*) n FROM spotlight_vulns s JOIN host_map hm ON hm.aid=s.aid JOIN lobs l ON l.id=hm.lob_id
                             GROUP BY l.id ORDER BY n DESC""")
    return {**{k: (v or 0) if k != "fetched_at" else v for k, v in s.items()}, "in_scanner": both, "spotlight_only": only_spot,
            "lobs": lobs, "demo": config.DEMO}


@router.get("/api/spotlight")
def spotlight_list(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    with db.get_conn() as c:
        if p.get("in_scanner") in ("0", "1"):
            rows = _rows(c, p)
            return {"total": len(rows), "rows": rows[(page - 1) * size: page * size]}
        where, params = _where(p)
        total = c.execute(f"SELECT COUNT(*) {BASE} {where}", params).fetchone()[0]
        return {"total": total, "rows": _rows(c, p, size, (page - 1) * size)}


@router.get("/api/spotlight/by-cve")
def spotlight_by_cve(request: Request):
    p = dict(request.query_params)
    where, params = _where(p)
    with db.get_conn() as c:
        names = _va_names(c)
        rows = db.rows(c, f"""SELECT s.cve, MAX(s.title) title, MAX(s.kev) kev, MAX(s.severity) severity, MAX(s.score) score, MAX(s.exprt) exprt,
            MAX(CASE WHEN s.exploit_status IN ('Actively used','Easily accessible','Available') THEN s.exploit_status END) exploit_status,
            COUNT(DISTINCT s.aid) hosts, GROUP_CONCAT(DISTINCT s.product) product, MAX(s.remediation) remediation
            {BASE} {where} GROUP BY s.cve ORDER BY hosts DESC, MAX(s.score) DESC LIMIT 2000""", params)
    for r in rows:
        r["title"] = r["title"] or names.get((r["cve"] or "").upper()) or display_name(r)
    return {"total": len(rows), "rows": rows}


def display_name(r):
    """CrowdStrike often sends no vulnerability name: show the CVE with the affected product (first one) instead of a blank."""
    prod = (r.get("product") or "").split(",")[0].strip()
    return f"{r.get('cve') or 'Unnamed vulnerability'}" + (f" · {prod}" if prod else "")


@router.get("/api/spotlight/by-host")
def spotlight_by_host(request: Request):
    p = dict(request.query_params)
    where, params = _where(p)
    with db.get_conn() as c:
        rows = db.rows(c, f"""SELECT s.aid, MAX(s.hostname) hostname, MAX(COALESCE(NULLIF(h.connection_ip,''), s.ip)) ip, COUNT(*) findings,
            SUM(UPPER(s.severity)='CRITICAL') critical, SUM(UPPER(s.severity)='HIGH') high,
            SUM(s.exploit_status IN ('Actively used','Easily accessible','Available')) exploitable, MAX(h.online_state) online_state,
            (SELECT GROUP_CONCAT(DISTINCT l.name) FROM host_map hm JOIN lobs l ON l.id=hm.lob_id WHERE hm.aid=s.aid) lob
            {BASE} {where} GROUP BY s.aid ORDER BY critical DESC, high DESC, findings DESC LIMIT 5000""", params)
    return {"total": len(rows), "rows": rows}


EXPORT = [("hostname", "Hostname"), ("ip", "Connection IP"), ("lob", "LOB"), ("cve", "CVE"), ("title", "Vulnerability"), ("severity", "Severity"), ("score", "CVSS"),
          ("exprt", "ExPRT rating"), ("exploit_status", "Exploit status"), ("product", "Product"), ("remediation", "Remediation"),
          ("in_scanner_text", "Also in VA scan"), ("created_at", "First seen"), ("updated_at", "Updated"), ("aid", "Agent ID")]


@router.get("/api/spotlight/export")
def spotlight_export(request: Request):
    with db.get_conn() as c:
        rows = _rows(c, dict(request.query_params))
    for r in rows:
        r["in_scanner_text"] = "Yes" if r["in_scanner"] else "No"
    return xlsx_response([("Spotlight vulnerabilities", EXPORT, rows)], "crowdstrike_spotlight")


@router.get("/api/spotlight/item")
def spotlight_item(id: str):
    """One Spotlight finding in full: the vulnerability (name, description, CVSS vector, ExPRT, exploit status, CISA KEV,
    published), the affected software, how to fix it, the host, the VA scan's view of the same CVE, and the raw record."""
    with db.get_conn() as c:
        r = db.one(c, f"SELECT {COLS}, s.description, s.kev_due, s.vendor_advisory, s.refs, s.remediation_link, s.raw {BASE} WHERE s.id=?", (id,))
        if not r:
            from fastapi import HTTPException
            raise HTTPException(404, "Finding not found")
        names = _va_names(c)
        va = db.rows(c, """SELECT name, severity, port, protocol, status, last_observed, solution FROM vuln_findings
                           WHERE ip=? AND (',' || REPLACE(UPPER(cve),' ','') || ',') LIKE ? ORDER BY sev_rank DESC LIMIT 10""",
                     (r["ip"] or "", f"%,{(r['cve'] or '').upper()},%"))
        others = db.one(c, "SELECT COUNT(DISTINCT aid) n FROM spotlight_vulns WHERE cve=?", (r["cve"],))["n"]
        host = db.one(c, """SELECT aid, hostname, connection_ip, platform_name, os_version, agent_version, online_state, last_seen FROM hosts WHERE aid=?""",
                      (r["aid"],))
    raw = db.jloads(r.pop("raw", None), {}) or {}
    cve = raw.get("cve") or {}
    apps = raw.get("apps") or []
    r["title"] = r.get("title") or names.get((r["cve"] or "").upper()) or display_name(r)
    vuln = {k: v for k, v in {
        "Vulnerability": r["title"], "CVE": r["cve"], "Description": r.get("description"), "Severity": r["severity"], "CVSS": r["score"],
        "CVSS vector": r.get("vector"), "ExPRT rating": r["exprt"], "Exploit status": r["exploit_status"],
        "CISA known exploited": ("Yes" + (f" · fix by {r['kev_due']}" if r.get("kev_due") else "")) if r.get("kev") else None,
        "Published": r.get("published"), "Exploitability score": cve.get("exploitability_score"), "Impact score": cve.get("impact_score"),
        "Types": ", ".join(cve.get("types") or []) if isinstance(cve.get("types"), list) else None,
        "Threat actors": ", ".join(cve.get("actors") or []) if isinstance(cve.get("actors"), list) else None,
        "Vendor advisory": r.get("vendor_advisory"), "References": r.get("refs"),
    }.items() if v not in (None, "", [])}
    software = [{k: v for k, v in {"Software": a.get("product_name_version"), "Vendor": a.get("vendor_normalized"),
                                   "Product": a.get("product_name_normalized"), "Status": a.get("sub_status"),
                                   "Fix": (a.get("remediation") or {}).get("ids") and ", ".join((a.get("remediation") or {}).get("ids") or [])}.items() if v}
                for a in apps] or ([{"Software": r["product"], "Vendor": r.get("app_vendor")}] if r["product"] else [])
    fix = {k: v for k, v in {"Remediation": r["remediation"], "Links": r.get("remediation_link")}.items() if v}
    finding = {k: v for k, v in {"Status": r["status"], "First seen": r["created_at"], "Updated": r["updated_at"], "Finding ID": r["id"],
                                 "Hosts with this CVE": others}.items() if v not in (None, "")}
    return {"row": r, "vuln": vuln, "software": software, "fix": fix, "finding": finding, "host": host, "va": va, "raw": raw}
