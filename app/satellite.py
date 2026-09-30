"""Red Hat Satellite 6 (Foreman + Katello + OpenSCAP): what is installed on each Linux host, which errata (security
fixes) apply and which can be installed right now (remediation available), and MBSS compliance from the latest
OpenSCAP report. Shown per asset on Asset 360.

API calls (read only, basic auth with a Satellite user + password or personal access token):
  GET /api/v2/hosts                               hosts with errata counts and upgradable package counts
  GET /api/v2/hosts/:id/packages?per_page=1       installed package count (subtotal)
  GET /katello/api/hosts/:id/errata               installable errata (remediation available now)
      ...?include_applicable=true                 every applicable erratum
  GET /api/v2/compliance/arf_reports?search=host  latest OpenSCAP report: passed / failed / other rules (MBSS)
The sync runs in the background (Integrations -> Red Hat Satellite -> Sync now); the page polls its status."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Body, HTTPException, Query, Request

from . import config, db

router = APIRouter()
STATUS = {"running": False, "message": "", "done": 0, "total": 0, "started_at": None, "finished_at": None, "error": None}
_lock = threading.Lock()


def settings():
    s = db.get_settings()
    return {"url": (s.get("satellite_url") or "").rstrip("/"), "user": s.get("satellite_user") or "",
            "token": s.get("satellite_token") or "", "verify": s.get("satellite_verify_ssl", "1") != "0"}


class Client:
    def __init__(self, cfg):
        import requests
        if not cfg["url"] or not cfg["user"] or not cfg["token"]:
            raise ValueError("Satellite is not configured: enter the URL, user and password / token")
        self.base, self.s = cfg["url"], requests.Session()
        self.s.auth = (cfg["user"], cfg["token"])
        self.s.verify = cfg["verify"]
        self.s.headers["Accept"] = "application/json"

    def get(self, path, **params):
        r = self.s.get(self.base + path, params=params, timeout=60)
        if r.status_code == 401:
            raise ValueError("Satellite: authentication failed (HTTP 401) - check the user and password / token")
        if r.status_code == 403:
            raise ValueError(f"Satellite: access denied (HTTP 403) on {path} - the user needs Viewer rights on hosts, content and compliance")
        r.raise_for_status()
        return r.json()

    def pages(self, path, per_page=500, **params):
        page = 1
        while True:
            d = self.get(path, page=page, per_page=per_page, **params)
            res = d.get("results") or []
            yield from res
            if not res or page * per_page >= int(d.get("subtotal") or d.get("total") or 0):
                return
            page += 1


def _host_detail(cli, h):
    hid = h["id"]
    try:
        pk = cli.get(f"/api/v2/hosts/{hid}/packages", per_page=1).get("subtotal")
    except Exception:  # noqa: BLE001 - host without content facet
        pk = None
    errata = []
    try:
        applicable = {e["errata_id"]: e for e in cli.pages(f"/katello/api/hosts/{hid}/errata", include_applicable="true")}
        installable = {e["errata_id"] for e in cli.pages(f"/katello/api/hosts/{hid}/errata")}
        for eid, e in applicable.items():
            errata.append((hid, eid, e.get("title") or "", e.get("type") or "", e.get("severity") or "", e.get("issued") or "",
                           ", ".join(e.get("cves") and [x.get("cve_id", x) if isinstance(x, dict) else x for x in e["cves"]] or []),
                           1 if eid in installable else 0))
    except Exception:  # noqa: BLE001
        pass
    comp = {}
    try:
        rep = (cli.get("/api/v2/compliance/arf_reports", search=f'host = "{h["name"]}"', per_page=1, order="reported_at DESC").get("results") or [])
        if rep:
            comp = rep[0]
    except Exception:  # noqa: BLE001 - OpenSCAP plugin not installed
        pass
    rules = []
    if comp.get("id"):
        try:
            full = cli.get(f"/api/v2/compliance/arf_reports/{comp['id']}")
            for lg in full.get("logs") or []:  # every rule of the report: passed ones too, so the host report is complete
                res = result_of(lg.get("result"))
                rules.append((hid, lg.get("source") or lg.get("rule_id") or "", lg.get("title") or lg.get("message") or "",
                              str(lg.get("severity") or "").title(), res, control_of(lg), fix_text(lg) if res == "fail" else ""))
        except Exception:  # noqa: BLE001 - older foreman_openscap without logs in the report API
            pass
    return h, pk, errata, comp, rules


def result_of(v):
    """OpenSCAP rule result -> pass | fail | other (not applicable, not checked, informational, error...)."""
    v = str(v or "").strip().lower()
    return "pass" if v in ("pass", "passed", "fixed") else "fail" if v in ("fail", "failed") else "other"


def control_of(lg):
    """MBSS / CIS control a rule belongs to: the first reference (e.g. CIS 5.2.8), else the rule's section in its id."""
    for r in lg.get("references") or lg.get("scap_references") or []:
        t = (r.get("title") or r.get("href") or "") if isinstance(r, dict) else str(r)
        if t:
            return t[:80]
    src = str(lg.get("source") or "")
    return src.replace("xccdf_org.ssgproject.content_rule_", "").split("_")[0] or "Other"


def fix_text(lg):
    fx = lg.get("fixes") or lg.get("fix") or ""
    if isinstance(fx, list):
        fx = "\n".join(str(f.get("full_text") or f.get("text") or f) if isinstance(f, dict) else str(f) for f in fx)
    return (str(fx) or lg.get("description") or "")[:4000]


def _sync():
    now = db.now_iso()
    cli = Client(settings())
    hosts = list(cli.pages("/api/v2/hosts", thin="false"))
    STATUS.update(total=len(hosts), message=f"{len(hosts):,} hosts")
    out_hosts, out_errata, out_rules = [], [], []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for h, pk, errata, comp, rules in ex.map(lambda h: _host_detail(cli, h), hosts):
            cf = h.get("content_facet_attributes") or {}
            ec = cf.get("errata_counts") or {}
            out_hosts.append((h["id"], h.get("name") or "", db.norm_hostname(h.get("name")), db.canon_ip(h.get("ip") or h.get("ip6") or ""),
                              h.get("operatingsystem_name") or "", h.get("last_checkin") or h.get("last_report") or "",
                              h.get("subscription_status_label") or "", pk, cf.get("upgradable_package_count"),
                              ec.get("security"), ec.get("bugfix"), ec.get("enhancement"),
                              sum(1 for e in errata if e[7] and e[3] == "security"), sum(1 for e in errata if e[7]),
                              comp.get("policy_name") or "", comp.get("passed"), comp.get("failed"), comp.get("othered"),
                              comp.get("reported_at") or "", now))
            out_errata += errata
            out_rules += rules
            STATUS["done"] += 1
    with db.get_conn() as c:
        c.execute("DELETE FROM satellite_hosts")
        c.execute("DELETE FROM satellite_errata")
        c.executemany(f"INSERT INTO satellite_hosts VALUES ({','.join('?' * 20)})", out_hosts)
        c.executemany("INSERT INTO satellite_errata VALUES (?,?,?,?,?,?,?,?)", out_errata)
        c.execute("DELETE FROM satellite_mbss")
        c.executemany("INSERT INTO satellite_mbss VALUES (?,?,?,?,?,?,?)", out_rules)
    return f"{len(out_hosts):,} hosts · {len(out_errata):,} applicable errata · {sum(1 for r in out_rules if r[4] == 'fail'):,} failed MBSS rule checks"


def _run():
    try:
        STATUS["message"] = _sync()
    except Exception as e:  # noqa: BLE001
        STATUS["error"] = str(e)
    finally:
        STATUS.update(running=False, finished_at=db.now_iso())
        with db.get_conn() as c:
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('satellite_last_sync', ?)",
                      (json.dumps({k: STATUS[k] for k in ("message", "error", "finished_at")}),))


# ------------------------------------------------------------------ API
@router.get("/api/satellite/config")
def satellite_config():
    cfg = settings()
    with db.get_conn() as c:
        n = db.one(c, "SELECT COUNT(*) hosts, MAX(fetched_at) at FROM satellite_hosts")
    return {"url": cfg["url"], "user": cfg["user"], "token_set": bool(cfg["token"]), "verify_ssl": cfg["verify"],
            "hosts": n["hosts"], "fetched_at": n["at"], "status": STATUS, "demo": config.DEMO}


@router.put("/api/satellite/config")
def satellite_config_save(data: dict = Body(...)):
    vals = {"satellite_url": str(data.get("url") or "").strip().rstrip("/"), "satellite_user": str(data.get("user") or "").strip(),
            "satellite_verify_ssl": "0" if data.get("verify_ssl") is False else "1"}
    if data.get("token"):  # never sent back to the page; blank = keep the saved one
        vals["satellite_token"] = str(data["token"]).strip()
    if vals["satellite_url"] and not vals["satellite_url"].startswith(("https://", "http://")):
        raise HTTPException(400, "The Satellite URL must start with https://")
    db.set_settings(vals)
    return satellite_config()


@router.post("/api/satellite/test")
def satellite_test():
    try:
        d = Client(settings()).get("/api/v2/hosts", per_page=1)
        return {"ok": True, "detail": f"Connected: {int(d.get('total') or 0):,} hosts visible"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": str(e)}


@router.post("/api/satellite/sync")
def satellite_sync():
    if config.DEMO:
        raise HTTPException(400, "Sample data mode: Satellite data is simulated")
    with _lock:
        if STATUS["running"]:
            return STATUS
        STATUS.update(running=True, message="Starting", done=0, total=0, started_at=db.now_iso(), finished_at=None, error=None)
    threading.Thread(target=_run, daemon=True).start()
    return STATUS


@router.get("/api/asset/satellite")
def asset_satellite(ips: str = "", names: str = "", errata: str = Query("installable")):
    """Satellite view of an asset (matched by IP or hostname): packages, errata and MBSS compliance."""
    ip_l = [db.canon_ip(i) for i in ips.split(",") if i]
    nm_l = [db.norm_hostname(n) for n in names.split(",") if n]
    if not ip_l and not nm_l:
        return {"hosts": [], "errata": []}
    w, params = [], []
    if ip_l:
        w.append(f"ip IN ({','.join('?' * len(ip_l))})")
        params += ip_l
    if nm_l:
        w.append(f"name_norm IN ({','.join('?' * len(nm_l))})")
        params += nm_l
    with db.get_conn() as c:
        hosts = db.rows(c, f"SELECT * FROM satellite_hosts WHERE {' OR '.join(w)}", params)
        ids = [h["host_id"] for h in hosts]
        er = db.rows(c, f"""SELECT * FROM satellite_errata WHERE host_id IN ({','.join('?' * len(ids))})
            {'AND installable=1' if errata == 'installable' else ''}
            ORDER BY installable DESC, CASE severity WHEN 'Critical' THEN 0 WHEN 'Important' THEN 1 WHEN 'Moderate' THEN 2 ELSE 3 END,
            issued DESC LIMIT 500""", ids) if ids else []
        mbss = db.rows(c, f"""SELECT * FROM satellite_mbss WHERE result='fail' AND host_id IN ({','.join('?' * len(ids))})
            ORDER BY control, CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END""", ids) if ids else []
    for h in hosts:
        _pct(h)
    return {"hosts": hosts, "errata": er, "mbss": mbss, "configured": bool(settings()["url"]) or config.DEMO}


def _pct(h):
    p, f = h.get("compliance_passed"), h.get("compliance_failed")
    h["compliance_pct"] = round(100.0 * p / (p + f), 1) if p is not None and f is not None and (p + f) else None
    return h


def cve_fixes(c, ips):
    """{(ip, CVE): [erratum ids]} for the Satellite hosts on these IPs: which errata fix a scanner's CVE."""
    if not ips:
        return {}
    out = {}
    for r in c.execute(f"""SELECT h.ip, e.errata_id, e.cves, e.installable FROM satellite_errata e JOIN satellite_hosts h ON h.host_id=e.host_id
                           WHERE h.ip IN ({','.join('?' * len(ips))}) AND COALESCE(e.cves,'')<>''""", list(ips)):
        for cve in (x.strip().upper() for x in r["cves"].split(",")):
            if cve:
                out.setdefault((r["ip"], cve), []).append({"id": r["errata_id"], "installable": bool(r["installable"])})
    return out


def fix_for(fixes, ip, cve_field):
    """The errata fixing any CVE of one finding."""
    seen, out = set(), []
    for cve in (x.strip().upper() for x in str(cve_field or "").replace(";", ",").split(",")):
        for e in fixes.get((ip, cve), []):
            if e["id"] not in seen:
                seen.add(e["id"])
                out.append(e)
    return out


# ------------------------------------------------------------------ fleet views (Patch & MBSS section)
def _host_where(p):
    w, params = [], []
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(h.name LIKE ? OR h.ip LIKE ? OR h.os LIKE ?)")
        params += [like, like, like]
    if p.get("state") == "fix_now":
        w.append("h.installable_security > 0")
    elif p.get("state") == "upgradable":
        w.append("h.upgradable > 0")
    elif p.get("state") == "noncompliant":
        w.append("h.compliance_failed > 0")
    elif p.get("state") == "no_report":
        w.append("h.compliance_passed IS NULL")
    if p.get("lob"):
        w.append("EXISTS (SELECT 1 FROM inventory_current ic WHERE ic.ip=h.ip AND ic.lob_id=?)")
        params.append(int(p["lob"]))
    return ("WHERE " + " AND ".join(w)) if w else "", params


HOST_SORTS = {"name": "h.name", "installable_security": "h.installable_security", "upgradable": "h.upgradable",
              "compliance": "CAST(h.compliance_passed AS REAL) / NULLIF(h.compliance_passed + h.compliance_failed, 0)",
              "errata_security": "h.errata_security", "packages": "h.packages"}


@router.get("/api/satellite/hosts")
def satellite_hosts(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params = _host_where(p)
    order = f"ORDER BY {HOST_SORTS.get(p.get('sort') or '', 'h.installable_security')} {'ASC' if p.get('dir') == 'asc' else 'DESC'}, h.name"
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM satellite_hosts h {where}", params).fetchone()[0]
        rows = db.rows(c, f"""SELECT h.*, (SELECT GROUP_CONCAT(DISTINCT l.name) FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
                              WHERE ic.ip=h.ip) lob FROM satellite_hosts h {where} {order} LIMIT ? OFFSET ?""", params + [size, (page - 1) * size])
    return {"total": total, "rows": [_pct(r) for r in rows]}


@router.get("/api/satellite/summary")
def satellite_summary():
    with db.get_conn() as c:
        s = db.one(c, """SELECT COUNT(*) hosts, SUM(installable_security > 0) fix_now_hosts, SUM(installable_security) fix_now,
            SUM(errata_security) security, SUM(upgradable > 0) upgradable_hosts, SUM(compliance_passed IS NOT NULL) reported,
            SUM(compliance_failed > 0) noncompliant, SUM(compliance_passed) passed, SUM(compliance_failed) failed,
            MAX(fetched_at) fetched_at FROM satellite_hosts""")
        sev = db.rows(c, """SELECT severity, COUNT(*) n, SUM(installable) installable FROM satellite_errata WHERE type='security'
                            GROUP BY severity""")
        linux = c.execute("""SELECT COUNT(*) FROM inventory_current WHERE os_resolved LIKE '%RHEL%' OR os_resolved LIKE '%Red Hat%'
                             OR os_resolved LIKE '%CentOS%' OR os_resolved LIKE '%Oracle Linux%' OR os_resolved LIKE '%Rocky%'
                             OR os_resolved LIKE '%Alma%'""").fetchone()[0]
    s = {k: v or 0 for k, v in s.items()} | {"fetched_at": s["fetched_at"]}
    s["compliance_pct"] = round(100.0 * s["passed"] / (s["passed"] + s["failed"]), 1) if s["passed"] + s["failed"] else None
    return {**s, "severity": sev, "rhel_family_nodes": linux, "configured": bool(settings()["url"]) or config.DEMO}


@router.get("/api/satellite/errata")
def satellite_errata(request: Request):
    """Errata across the fleet, one row each: how many hosts need it and on how many it can be installed now."""
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    w, params = [], []
    if p.get("type"):
        w.append("e.type=?")
        params.append(p["type"])
    if p.get("severity"):
        w.append("e.severity=?")
        params.append(p["severity"])
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(e.errata_id LIKE ? OR e.title LIKE ? OR e.cves LIKE ?)")
        params += [like, like, like]
    where = ("WHERE " + " AND ".join(w)) if w else ""
    q = f"""SELECT e.errata_id, MAX(e.title) title, MAX(e.type) type, MAX(e.severity) severity, MAX(e.issued) issued, MAX(e.cves) cves,
            COUNT(DISTINCT e.host_id) hosts, SUM(e.installable) installable FROM satellite_errata e {where} GROUP BY e.errata_id"""
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM ({q})", params).fetchone()[0]
        rows = db.rows(c, f"""{q} ORDER BY CASE MAX(e.severity) WHEN 'Critical' THEN 0 WHEN 'Important' THEN 1 WHEN 'Moderate' THEN 2
                              WHEN 'Low' THEN 3 ELSE 4 END, hosts DESC LIMIT ? OFFSET ?""", params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


SEV_ORDER = "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END"


def host_report(c, host_id):
    """One host's MBSS report: every rule of its latest OpenSCAP report (pass / fail / other) and a summary per control."""
    h = db.one(c, "SELECT * FROM satellite_hosts WHERE host_id=?", (host_id,))
    if not h:
        return None
    rules = db.rows(c, f"""SELECT rule_id, title, severity, result, control, fix FROM satellite_mbss WHERE host_id=?
                           ORDER BY control, CASE result WHEN 'fail' THEN 0 WHEN 'pass' THEN 1 ELSE 2 END, {SEV_ORDER}, title""", (host_id,))
    controls = {}
    for r in rules:
        k = controls.setdefault(r["control"] or "Other", {"control": r["control"] or "Other", "pass": 0, "fail": 0, "other": 0, "high_fail": 0})
        k[r["result"] if r["result"] in ("pass", "fail") else "other"] += 1
        k["high_fail"] += r["result"] == "fail" and r["severity"] == "High"
    for k in controls.values():
        k["pct"] = round(100.0 * k["pass"] / (k["pass"] + k["fail"]), 1) if k["pass"] + k["fail"] else None
    counts = {x: sum(1 for r in rules if r["result"] == x) for x in ("pass", "fail", "other")}
    listed = counts["pass"] + counts["fail"] > 0 and counts["pass"] > 0  # older Satellite: only failed rules come back
    return {"host": _pct(h), "rules": rules, "controls": sorted(controls.values(), key=lambda k: (k["pct"] if k["pct"] is not None else 101, k["control"])),
            "counts": counts, "complete": listed}


@router.get("/api/satellite/mbss/host/{host_id}")
def satellite_mbss_host(host_id: int):
    with db.get_conn() as c:
        rep = host_report(c, host_id)
    if not rep:
        raise HTTPException(404, "Host not found")
    return rep


@router.get("/api/satellite/mbss/host/{host_id}/export")
def satellite_mbss_host_export(host_id: int):
    """MBSS compliance report of one host (Excel): summary, per-control compliance, every rule with its result and fix."""
    from .exporter import xlsx_response
    with db.get_conn() as c:
        rep = host_report(c, host_id)
    if not rep:
        raise HTTPException(404, "Host not found")
    h = rep["host"]
    summary = [{"k": k, "v": v} for k, v in [("Host", h["name"]), ("IP", h["ip"]), ("OS", h["os"]), ("Policy", h["compliance_policy"]),
                                             ("Report date", (h["compliance_at"] or "")[:10]), ("Compliance %", h["compliance_pct"]),
                                             ("Rules passed", h["compliance_passed"]), ("Rules failed", h["compliance_failed"]),
                                             ("Other (not applicable / not checked)", h["compliance_other"])]]
    for r in rep["rules"]:
        r["result_text"] = {"pass": "Compliant", "fail": "Not compliant"}.get(r["result"], "Not applicable / not checked")
    return xlsx_response([("Summary", [("k", "Item"), ("v", "Value")], summary),
                          ("By control", [("control", "Control"), ("pct", "Compliance %"), ("pass", "Passed"), ("fail", "Failed"), ("other", "Other"),
                                          ("high_fail", "High-severity failed")], rep["controls"]),
                          ("All rules", [("control", "Control"), ("title", "Rule"), ("severity", "Severity"), ("result_text", "Result"),
                                         ("rule_id", "Rule ID"), ("fix", "Remediation")], rep["rules"])],
                         f"mbss_report_{h['name'].split('.')[0]}")


@router.get("/api/satellite/mbss/controls")
def satellite_mbss_controls():
    """Fleet compliance per control: rule checks passed vs failed, and how many hosts fail at least one rule of it."""
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT COALESCE(control,'Other') control, COUNT(DISTINCT rule_id) rules, SUM(result='pass') pass, SUM(result='fail') fail,
                             COUNT(DISTINCT host_id) hosts, COUNT(DISTINCT CASE WHEN result='fail' THEN host_id END) hosts_failing,
                             SUM(result='fail' AND severity='High') high_fail FROM satellite_mbss GROUP BY 1""")
    for r in rows:
        r["pct"] = round(100.0 * r["pass"] / (r["pass"] + r["fail"]), 1) if (r["pass"] or 0) + (r["fail"] or 0) else None
    return {"rows": sorted(rows, key=lambda r: (r["pct"] if r["pct"] is not None else 101, r["control"]))}


@router.get("/api/satellite/mbss/rule")
def satellite_mbss_rule(rule_id: str):
    """Every host failing one MBSS rule."""
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT h.host_id, h.name, h.ip, h.os, h.compliance_policy, h.compliance_at, h.compliance_passed, h.compliance_failed,
                             (SELECT GROUP_CONCAT(DISTINCT l.name) FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id WHERE ic.ip=h.ip) lob
                             FROM satellite_mbss m JOIN satellite_hosts h ON h.host_id=m.host_id WHERE m.rule_id=? AND m.result='fail' ORDER BY h.name""", (rule_id,))
    return {"rows": [_pct(r) for r in rows]}


@router.get("/api/satellite/mbss")
def satellite_mbss(request: Request):
    """Failed MBSS (OpenSCAP) rules across the fleet, grouped by control, with the fix text."""
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    w, params = [], []
    if p.get("severity"):
        w.append("m.severity=?")
        params.append(p["severity"])
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(m.title LIKE ? OR m.control LIKE ? OR m.rule_id LIKE ?)")
        params += [like, like, like]
    where = ("WHERE " + " AND ".join(w)) if w else ""
    having = "" if p.get("all") == "1" else "HAVING hosts > 0"
    q = f"""SELECT m.control, m.rule_id, MAX(m.title) title, MAX(m.severity) severity,
            COUNT(DISTINCT CASE WHEN m.result='fail' THEN m.host_id END) hosts, COUNT(DISTINCT CASE WHEN m.result='pass' THEN m.host_id END) passed,
            MAX(m.fix) fix FROM satellite_mbss m {where} GROUP BY m.control, m.rule_id {having}"""
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM ({q})", params).fetchone()[0]
        rows = db.rows(c, f"""{q} ORDER BY m.control, CASE MAX(m.severity) WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, hosts DESC
                              LIMIT ? OFFSET ?""", params + [size, (page - 1) * size])
        controls = db.rows(c, """SELECT control, COUNT(DISTINCT rule_id) rules, COUNT(DISTINCT host_id) hosts FROM satellite_mbss
                                 WHERE result='fail' GROUP BY control ORDER BY hosts DESC""")
    return {"total": total, "rows": rows, "controls": controls}
