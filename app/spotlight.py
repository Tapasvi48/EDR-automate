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
    if p.get("lob"):
        w.append("EXISTS (SELECT 1 FROM host_map hm WHERE hm.aid=s.aid AND hm.lob_id=?)")
        params.append(int(p["lob"]))
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(s.cve LIKE ? OR s.hostname LIKE ? OR h.connection_ip LIKE ? OR s.product LIKE ? OR s.remediation LIKE ?)")
        params += [like] * 5
    return ("WHERE " + " AND ".join(w)) if w else "", params


BASE = """FROM spotlight_vulns s LEFT JOIN hosts h ON h.aid=s.aid"""
COLS = """s.id, s.aid, s.hostname, COALESCE(NULLIF(h.connection_ip,''), s.ip) ip, s.cve, s.severity, s.score, s.exprt, s.exploit_status,
          s.product, s.remediation, s.status, s.created_at, s.updated_at, h.online_state, h.console_state,
          (SELECT GROUP_CONCAT(DISTINCT l.name) FROM host_map hm JOIN lobs l ON l.id=hm.lob_id WHERE hm.aid=s.aid) lob"""


def _rows(c, p, limit=None, offset=0):
    where, params = _where(p)
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"SELECT {COLS} {BASE} {where} ORDER BY {SEV_ORDER}, s.score DESC, s.hostname {lim}", params)
    scan = _scanner_cves(c)
    for r in rows:
        r["in_scanner"] = (r["cve"] or "").upper() in scan.get(r["ip"] or "", set())
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
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
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
        rows = db.rows(c, f"""SELECT s.cve, MAX(s.severity) severity, MAX(s.score) score, MAX(s.exprt) exprt,
            MAX(CASE WHEN s.exploit_status IN ('Actively used','Easily accessible','Available') THEN s.exploit_status END) exploit_status,
            COUNT(DISTINCT s.aid) hosts, GROUP_CONCAT(DISTINCT s.product) product, MAX(s.remediation) remediation
            {BASE} {where} GROUP BY s.cve ORDER BY hosts DESC, MAX(s.score) DESC LIMIT 2000""", params)
    return {"total": len(rows), "rows": rows}


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


EXPORT = [("hostname", "Hostname"), ("ip", "Connection IP"), ("lob", "LOB"), ("cve", "CVE"), ("severity", "Severity"), ("score", "CVSS"),
          ("exprt", "ExPRT rating"), ("exploit_status", "Exploit status"), ("product", "Product"), ("remediation", "Remediation"),
          ("in_scanner_text", "Also in VA scan"), ("created_at", "First seen"), ("updated_at", "Updated"), ("aid", "Agent ID")]


@router.get("/api/spotlight/export")
def spotlight_export(request: Request):
    with db.get_conn() as c:
        rows = _rows(c, dict(request.query_params))
    for r in rows:
        r["in_scanner_text"] = "Yes" if r["in_scanner"] else "No"
    return xlsx_response([("Spotlight vulnerabilities", EXPORT, rows)], "crowdstrike_spotlight")
