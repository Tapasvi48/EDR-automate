"""Security posture: per-asset risk score, vulnerability-scan coverage gaps and MSP scorecards.

`asset_risk` has one row per asset of a LOB: every inventory node plus every scanned IP that is not in the inventory.
It is rebuilt at the end of inventory.refresh_matches() (after every sync, inventory upload, scan and NIAM upload), and
today's per-MSP numbers are written to `msp_daily` at the same time, so scorecards get one history point per day."""
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Request

from . import db, queries
from .exporter import xlsx_response

router = APIRouter()

LEVELS = ["Critical", "High", "Medium", "Low"]
SCAN_BUCKETS = ["0-30", "31-60", "61-90", "90+", "never"]
NO_EDR = ("Not Installed",)
TARGET_DEFAULTS = {"target_coverage": "95", "target_offline_pct": "5", "target_scan_days": "30", "target_scan_coverage": "90",
                   "target_max_critical": "0", "target_max_risk_critical": "0"}


def level_of(score):
    return "Critical" if score >= 60 else "High" if score >= 35 else "Medium" if score >= 15 else "Low"


def _days_since(ts, now):
    if not ts:
        return None
    try:  # fromisoformat is C-fast; strptime cost 1.4 s per lakh assets
        return max(0, int((now - datetime.fromisoformat(ts[:19]).replace(tzinfo=timezone.utc)).total_seconds() // 86400))
    except ValueError:
        return None


def scan_bucket(age):
    if age is None:
        return "never"
    return "0-30" if age <= 30 else "31-60" if age <= 60 else "61-90" if age <= 90 else "90+"


def score_asset(a, now):
    """Returns (score 0-100, [(factor, points)]). Transparent, additive: every point is explained by a factor."""
    f = []
    edr = a["edr_status"]
    if a["in_inventory"] and not a["applicable"]:
        if a["coverage_status"] == "Not Feasible":
            f.append(("EDR not feasible on this node", 10))
    elif edr in NO_EDR:
        f.append(("No EDR agent", 35))
    elif edr == "Offline":  # offline in the console, or the agent left it (policy removal / old EDR import)
        d = _days_since(a["edr_last_seen"], now)
        if d is not None and d > 30:
            f.append(("EDR offline > 30 days", 25))
        elif d is not None and d > 7:
            f.append(("EDR offline > 7 days", 15))
        else:
            f.append(("EDR offline", 8))
    if a["crit"]:
        f.append((f"{a['crit']} open critical", min(30, 12 + 6 * (a["crit"] - 1))))
    if a["high"]:
        f.append((f"{a['high']} open high", min(15, 5 + 2 * (a["high"] - 1))))
    if a["med"]:
        f.append((f"{a['med']} open medium", min(5, a["med"])))
    if a["exploitable"]:
        # from the scan's "Exploit Ease" column (e.g. Nessus "Exploits are available") on a critical / high finding
        f.append(("Exploit available (critical / high)", 10))
    score = sum(p for _, p in f)
    if a["live"] == "Non Live":
        score = score * 0.3
        f.append(("Non Live node (score × 0.3)", 0))
    return min(100, round(score)), f


def refresh(c):
    now = datetime.now(timezone.utc)
    assets = {}
    for r in db.rows(c, """SELECT lob_id, ip, node_name, node_type, msp, msp_id, live, applicable, coverage_status, edr_state,
                           edr_installed, matched_aid, cs_hostname, cs_last_seen, item_key FROM inventory_current
                           ORDER BY applicable DESC"""):
        key = r["ip"] or ("name:" + (r["node_name"] or r["item_key"]).lower())
        if (r["lob_id"], key) in assets:
            continue
        weak = r["edr_state"] == "Not Installed"
        assets[(r["lob_id"], key)] = {
            "lob_id": r["lob_id"], "asset_key": key, "ip": r["ip"] or None, "item_key": r["item_key"], "node_name": r["node_name"],
            "node_type": r["node_type"], "msp": r["msp"], "msp_id": r["msp_id"], "live": r["live"], "applicable": r["applicable"] or 0,
            "in_inventory": 1, "coverage_status": r["coverage_status"], "edr_status": r["edr_state"] or "Not Installed",
            "edr_installed": r["edr_installed"], "aid": None if weak else r["matched_aid"], "hostname": None if weak else r["cs_hostname"],
            "edr_last_seen": None if weak else r["cs_last_seen"], "crit": 0, "high": 0, "med": 0, "low": 0, "exploitable": 0, "last_scan": None}
    for v in db.rows(c, "SELECT * FROM vuln_assets"):
        a = assets.get((v["lob_id"], v["ip"]))
        if a is None:
            a = assets[(v["lob_id"], v["ip"])] = {
                "lob_id": v["lob_id"], "asset_key": v["ip"], "ip": v["ip"], "item_key": None, "node_name": None, "node_type": None,
                "msp": v["msp"], "msp_id": v["msp_id"], "live": None, "applicable": 0, "in_inventory": 0, "coverage_status": None,
                "edr_status": v["edr_status"] or "Not Installed", "edr_installed": None, "aid": v["aid"], "hostname": v["hostname"],
                "edr_last_seen": None, "crit": 0, "high": 0, "med": 0, "low": 0, "exploitable": 0, "last_scan": None}
        a.update(crit=v["crit"] or 0, high=v["high"] or 0, med=v["med"] or 0, low=v["low"] or 0, last_scan=v["last_scanned_at"],
                 exploitable=(v["exploitable"] if "exploitable" in v.keys() else 0) or 0)
    # last scan also for inventory nodes whose scan found nothing (vuln_assets covers every scanned IP, this is a safety net)
    for s in db.rows(c, "SELECT lob_id, ip, scanned_at FROM vuln_scan_hosts"):
        a = assets.get((s["lob_id"], s["ip"]))
        if a and not a["last_scan"]:
            a["last_scan"] = s["scanned_at"]
    # exploitable critical / high counts come with vuln_assets (computed in the same pass as the other counts)
    offline_seen = {r["aid"]: r["last_seen"] for r in c.execute("SELECT aid, last_seen FROM hosts WHERE aid IS NOT NULL")}
    rows = []
    for a in assets.values():
        if a["aid"] and not a["edr_last_seen"]:
            a["edr_last_seen"] = offline_seen.get(a["aid"])
        a["scan_age_days"] = _days_since(a["last_scan"], now)
        a["scan_bucket"] = scan_bucket(a["scan_age_days"])
        score, factors = score_asset(a, now)
        rows.append((a["lob_id"], a["asset_key"], a["ip"], db.ip_to_num(a["ip"]), a["item_key"], a["node_name"], a["node_type"], a["msp"],
                     a["msp_id"], a["live"], a["applicable"], a["in_inventory"], a["coverage_status"], a["aid"], a["hostname"],
                     a["edr_status"], a["edr_last_seen"], a["crit"], a["high"], a["med"], a["low"], a["exploitable"], a["last_scan"],
                     a["scan_age_days"], a["scan_bucket"], score, level_of(score), json.dumps(factors)))
    cols = """lob_id, asset_key, ip, ip_num, item_key, node_name, node_type, msp, msp_id, live, applicable,
              in_inventory, coverage_status, aid, hostname, edr_status, edr_last_seen, crit, high, med, low, exploitable,
              last_scan, scan_age_days, scan_bucket, score, level, factors"""
    # write only changed rows (a scan or sync changes few scores; rewriting lakhs of rows was most of this step)
    old = {(r[0], r[1]): tuple(r) for r in c.execute(f"SELECT {cols} FROM asset_risk")}
    keys = {(r[0], r[1]) for r in rows}
    gone = [k for k in old if k not in keys]
    changed = [r for r in rows if old.get((r[0], r[1])) != tuple(r)]
    ins = f"INSERT OR REPLACE INTO asset_risk({cols}) VALUES ({','.join('?' * 28)})"
    if len(changed) + len(gone) > 0.6 * max(1, len(rows)):
        c.execute("DELETE FROM asset_risk")
        c.executemany(ins, rows)
    else:
        c.executemany("DELETE FROM asset_risk WHERE lob_id=? AND asset_key=?", gone)
        c.executemany(ins, changed)
    capture_msp_day(c)


# ------------------------------------------------------------------ scorecards
def targets(settings):
    return {k: float(settings.get(k) or v) for k, v in TARGET_DEFAULTS.items()}


def _posture_by_msp(c, scan_days):
    return {(r["lob_id"], r["msp_id"] or 0): r for r in db.rows(c, """SELECT lob_id, msp_id,
        SUM(crit) crit, SUM(high) high, SUM(crit + high > 0 AND edr_status NOT IN ('Online','Offline')) crit_high_no_edr,
        SUM(in_inventory=1 AND COALESCE(live,'')<>'Non Live') live_nodes,
        SUM(in_inventory=1 AND COALESCE(live,'')<>'Non Live' AND scan_age_days IS NOT NULL AND scan_age_days <= ?) scanned_recent,
        SUM(in_inventory=1 AND COALESCE(live,'')<>'Non Live' AND scan_age_days IS NULL) never_scanned,
        SUM(level='Critical') risk_critical, SUM(level='High') risk_high, ROUND(AVG(score), 1) avg_score
        FROM asset_risk GROUP BY lob_id, msp_id""", (scan_days,))}


def capture_msp_day(c, day=None):
    day = day or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    settings = db.get_settings(c)
    post = _posture_by_msp(c, int(targets(settings)["target_scan_days"]))
    rows = []
    for m in queries.msp_summaries(c, settings):
        p = post.get((m["lob_id"], m["msp_id"] or 0), {})
        rows.append((day, m["lob_id"], m["msp_id"] or 0, m["nodes"], m["applicable"], m["installed"], m["online"], m["offline"],
                     m["pending"], m["coverage"], p.get("crit") or 0, p.get("high") or 0, p.get("crit_high_no_edr") or 0,
                     p.get("live_nodes") or 0, p.get("scanned_recent") or 0, p.get("never_scanned") or 0,
                     p.get("risk_critical") or 0, p.get("risk_high") or 0))
    c.execute("DELETE FROM msp_daily WHERE day=?", (day,))
    c.executemany("""INSERT INTO msp_daily(day, lob_id, msp_id, nodes, applicable, installed, online, offline, pending, coverage, crit, high,
                     crit_high_no_edr, live_nodes, scanned_recent, never_scanned, risk_critical, risk_high)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def _pct(a, b):
    return round(100.0 * a / b, 1) if b else None


def scorecards(c, lob_id=None):
    settings = db.get_settings(c)
    t = targets(settings)
    post = _posture_by_msp(c, int(t["target_scan_days"]))
    hist = {}
    for h in db.rows(c, "SELECT * FROM msp_daily WHERE day >= date('now', '-90 days') ORDER BY day"):
        hist.setdefault((h["lob_id"], h["msp_id"]), []).append(h)
    out = []
    for m in queries.msp_summaries(c, settings, lob_id):
        if not m.get("nodes"):
            continue
        key = (m["lob_id"], m["msp_id"] or 0)
        p = post.get(key, {})
        r = {"lob_id": m["lob_id"], "lob": m["lob"], "msp_id": m["msp_id"], "msp": m["msp"], "nodes": m["nodes"],
             "applicable": m["applicable"], "installed": m["installed"], "online": m["online"], "offline": m["offline"],
             "pending": m["pending"], "coverage": m["coverage"], "offline_pct": _pct(m["offline"], m["installed"]),
             "crit": p.get("crit") or 0, "high": p.get("high") or 0, "crit_high_no_edr": p.get("crit_high_no_edr") or 0,
             "live_nodes": p.get("live_nodes") or 0, "never_scanned": p.get("never_scanned") or 0,
             "scan_coverage": _pct(p.get("scanned_recent") or 0, p.get("live_nodes") or 0),
             "risk_critical": p.get("risk_critical") or 0, "risk_high": p.get("risk_high") or 0, "avg_score": p.get("avg_score")}
        checks = [
            ("coverage", r["coverage"] is not None and r["coverage"] >= t["target_coverage"], r["coverage"] is None),
            ("offline_pct", r["offline_pct"] is not None and r["offline_pct"] <= t["target_offline_pct"], r["offline_pct"] is None),
            ("scan_coverage", r["scan_coverage"] is not None and r["scan_coverage"] >= t["target_scan_coverage"], r["scan_coverage"] is None),
            ("crit", r["crit"] <= t["target_max_critical"], False),
            ("risk_critical", r["risk_critical"] <= t["target_max_risk_critical"], False),
        ]
        r["checks"] = {k: (None if na else bool(ok)) for k, ok, na in checks}
        scored = [v for v in r["checks"].values() if v is not None]
        r["on_target"], r["measured"] = sum(scored), len(scored)
        r["grade"] = "ABCDE"[min(4, len(scored) - sum(scored))] if scored else "–"
        series = hist.get(key, [])
        r["trend"] = [{"day": h["day"], "coverage": h["coverage"], "crit": h["crit"], "pending": h["pending"], "offline": h["offline"],
                       "risk_critical": h["risk_critical"],
                       "scan_coverage": _pct(h["scanned_recent"], h["live_nodes"])} for h in series]
        past = next((h for h in series if h["day"] >= _ago_day(30)), None)
        r["delta_30d"] = {"coverage": round((r["coverage"] or 0) - (past["coverage"] or 0), 1) if past and past["coverage"] is not None else None,
                          "crit": r["crit"] - past["crit"] if past else None,
                          "pending": r["pending"] - past["pending"] if past else None}
        out.append(r)
    out.sort(key=lambda r: (-(r["measured"] - r["on_target"]), r["coverage"] if r["coverage"] is not None else 999))
    return {"targets": t, "rows": out}


def _ago_day(days):
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


# ------------------------------------------------------------------ queries
RISK_SORTS = {"score": "r.score", "ip": "r.ip_num", "crit": "r.crit", "high": "r.high", "last_scan": "r.last_scan",
              "scan_age_days": "COALESCE(r.scan_age_days, 99999)", "lob": "l.name", "msp": "r.msp", "node_name": "r.node_name COLLATE NOCASE",
              "edr_status": "r.edr_status"}


def risk_query(p):
    w, params = [], []
    db.add_filter(w, params, db.id_filter(p, "lob", "r.lob_id"))
    db.add_filter(w, params, db.id_filter(p, "msp", "r.msp_id", "r.msp_id IS NULL"))
    if p.get("level"):
        vals = p["level"].split("|")
        w.append(f"r.level IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("scan"):
        vals = p["scan"].split("|")
        w.append(f"r.scan_bucket IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("stale_scan"):  # not scanned within N days (incl. never)
        w.append("(r.scan_age_days IS NULL OR r.scan_age_days > ?)")
        params.append(int(p["stale_scan"]))
    if p.get("inventory_live") == "1":  # scan-gap view: live inventory nodes only
        w.append("r.in_inventory=1 AND COALESCE(r.live,'')<>'Non Live'")
    if p.get("in_inventory") in ("0", "1"):
        w.append("r.in_inventory=?")
        params.append(int(p["in_inventory"]))
    if p.get("no_edr") == "1":
        w.append("r.edr_status NOT IN ('Online','Offline') AND (r.applicable=1 OR r.in_inventory=0)")
    if p.get("exploitable") == "1":
        w.append("r.exploitable > 0")
    if p.get("crit_high") == "1":
        w.append("(r.crit + r.high) > 0")
    if p.get("factor"):
        w.append("r.factors LIKE ?")
        params.append(f"%{p['factor']}%")
    if p.get("edr_status"):
        vals = p["edr_status"].split("|")
        w.append(f"r.edr_status IN ({','.join('?' * len(vals))})")
        params += vals
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            w.append(f"r.ip IN ({','.join('?' * len(terms))})")
            params += [db.canon_ip(t) for t in terms]
        elif db.is_range_query(q):
            w.append("ip_in(r.ip, ?)")
            params.append(q)
        elif db.is_ip(q):
            w.append("r.ip = ?")
            params.append(db.canon_ip(q))
        else:
            like = f"%{q}%"
            w.append("(r.node_name LIKE ? OR r.hostname LIKE ? OR r.ip LIKE ?)")
            params += [like, like, q + "%"]
    sort = RISK_SORTS.get(p.get("sort") or "", "r.score")
    direction = "ASC" if (p.get("dir") or "desc") == "asc" else "DESC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return "asset_risk r JOIN lobs l ON l.id=r.lob_id", where, params, f"ORDER BY {sort} {direction}, r.score DESC, r.ip_num"


def _page(p):
    return db.page_args(p)


def _lobmsp(p):
    w, params = [], []
    db.add_filter(w, params, db.id_filter(p, "lob", "r.lob_id"))
    db.add_filter(w, params, db.id_filter(p, "msp", "r.msp_id", "r.msp_id IS NULL"))
    return w, params


# ------------------------------------------------------------------ routes
@router.get("/api/risk/summary")
def risk_summary(request: Request):
    p = dict(request.query_params)
    w, params = _lobmsp(p)
    where = ("WHERE " + " AND ".join(w)) if w else ""
    with db.get_conn() as c:
        levels = {r["level"]: r["n"] for r in db.rows(c, f"SELECT r.level, COUNT(*) n FROM asset_risk r {where} GROUP BY 1", params)}
        tot = db.one(c, f"""SELECT COUNT(*) assets, ROUND(AVG(score),1) avg_score, SUM(exploitable>0) exploitable,
            SUM(level='Critical' AND edr_status NOT IN ('Online','Offline')) critical_no_edr FROM asset_risk r {where}""", params)
        dist = db.rows(c, f"SELECT (score/10)*10 bucket, COUNT(*) n FROM asset_risk r {where} GROUP BY 1 ORDER BY 1", params)
        factors = {}
        for r in c.execute(f"SELECT factors FROM asset_risk r {where + (' AND' if where else 'WHERE')} r.level IN ('Critical','High')", params):
            for name, pts in json.loads(r[0]):
                if pts:
                    k = re.sub(r"^\d+ ", "", name)
                    factors[k] = factors.get(k, 0) + 1
        by = db.rows(c, f"""SELECT r.lob_id, l.name lob, r.msp_id, COALESCE(r.msp, 'Unassigned') msp, COUNT(*) assets,
            SUM(level='Critical') critical, SUM(level='High') high, SUM(level='Medium') medium, ROUND(AVG(score),1) avg_score,
            MAX(score) max_score FROM asset_risk r JOIN lobs l ON l.id=r.lob_id {where}
            GROUP BY r.lob_id, r.msp_id ORDER BY critical DESC, high DESC""", params)
    return {"levels": {k: levels.get(k, 0) for k in LEVELS}, **{k: (v or 0) for k, v in tot.items()},
            "distribution": dist, "factors": sorted(({"factor": k, "n": v} for k, v in factors.items()), key=lambda x: -x["n"]),
            "by_msp": by}


def _risk_rows(c, p, limit=None, offset=0):
    frm, where, params, order = risk_query(p)
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"SELECT r.*, l.name lob FROM {frm} {where} {order} {lim}", params)
    for r in rows:
        r["factors"] = [f for f in json.loads(r["factors"] or "[]") if f[1]] + [f for f in json.loads(r["factors"] or "[]") if not f[1]]
    return rows


@router.get("/api/risk/assets")
def risk_assets(request: Request):
    p = dict(request.query_params)
    page, size = _page(p)
    frm, where, params, _ = risk_query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = _risk_rows(c, p, size, (page - 1) * size)
    return {"total": total, "rows": rows}


RISK_EXPORT = [("score", "Risk Score"), ("level", "Risk Level"), ("factors_text", "Why"), ("lob", "LOB"), ("msp", "MSP"), ("ip", "IP"),
               ("node_name", "Inventory Node Name"), ("hostname", "Falcon Hostname"), ("node_type", "Node Type"), ("live", "Live"),
               ("in_inventory", "In Inventory"), ("edr_status", "EDR Status"), ("edr_last_seen", "EDR Last Seen"), ("crit", "Critical"),
               ("high", "High"), ("med", "Medium"), ("low", "Low"), ("exploitable", "Exploitable Crit/High"), ("last_scan", "Last Scan"),
               ("scan_age_days", "Days Since Scan")]


def export_rows(rows):
    for r in rows:
        r["factors_text"] = "; ".join(f"{n} (+{pts})" if pts else n for n, pts in r["factors"])
        r["in_inventory"] = "Yes" if r["in_inventory"] else "No"
        r["last_scan"] = r["last_scan"] or "Never"
    return rows


@router.get("/api/risk/assets/export")
def risk_export(request: Request):
    p = dict(request.query_params)
    with db.get_conn() as c:
        rows = export_rows(_risk_rows(c, p))
    return xlsx_response([("Risk ranking", RISK_EXPORT, rows)], "risk_ranking" if p.get("inventory_live") != "1" else "scan_gaps")


@router.get("/api/scan-gaps/summary")
def scan_gaps(request: Request):
    p = dict(request.query_params)
    w, params = _lobmsp(p)
    w.append("r.in_inventory=1 AND COALESCE(r.live,'')<>'Non Live'")
    where = "WHERE " + " AND ".join(w)
    cols = ", ".join(f"SUM(scan_bucket='{b}') \"{b}\"" for b in SCAN_BUCKETS)
    with db.get_conn() as c:
        tot = db.one(c, f"SELECT COUNT(*) nodes, {cols}, SUM(scan_bucket='never' AND edr_status NOT IN ('Online','Offline')) never_no_edr "
                        f"FROM asset_risk r {where}", params)
        by = db.rows(c, f"""SELECT r.lob_id, l.name lob, r.msp_id, COALESCE(r.msp,'Unassigned') msp, COUNT(*) nodes, {cols},
            MAX(last_scan) last_scan FROM asset_risk r JOIN lobs l ON l.id=r.lob_id {where}
            GROUP BY r.lob_id, r.msp_id ORDER BY l.name, msp""", params)
        by_type = db.rows(c, f"""SELECT COALESCE(NULLIF(node_type,''),'Unknown') node_type, COUNT(*) nodes, {cols}
            FROM asset_risk r {where} GROUP BY 1 ORDER BY nodes DESC""", params)
    for r in [tot] + by + by_type:
        for b in SCAN_BUCKETS:
            r[b] = r[b] or 0
        r["scanned_30d_pct"] = _pct(r["0-30"], r["nodes"])
    return {"buckets": SCAN_BUCKETS, "total": tot, "by_msp": by, "by_type": by_type}


@router.get("/api/scorecards")
def scorecards_api(lob: int = 0):
    with db.get_conn() as c:
        return scorecards(c, lob or None)


SC_EXPORT = [("lob", "LOB"), ("msp", "MSP"), ("grade", "Grade"), ("on_target_text", "Targets Met"), ("nodes", "Nodes"),
             ("applicable", "Applicable"), ("installed", "Installed"), ("coverage", "Coverage %"), ("online", "Online"),
             ("offline", "Offline"), ("offline_pct", "Offline % of Installed"), ("pending", "Pending Install"),
             ("scan_coverage", "Scan Coverage %"), ("never_scanned", "Never Scanned"), ("crit", "Open Critical"), ("high", "Open High"),
             ("crit_high_no_edr", "Crit/High Hosts Without EDR"), ("risk_critical", "Critical-Risk Assets"),
             ("risk_high", "High-Risk Assets"), ("coverage_30d", "Coverage Change 30d"), ("crit_30d", "Critical Change 30d")]


def scorecard_export_rows(c):
    rows = scorecards(c)["rows"]
    for r in rows:
        r["on_target_text"] = f"{r['on_target']}/{r['measured']}"
        r["coverage_30d"] = r["delta_30d"]["coverage"]
        r["crit_30d"] = r["delta_30d"]["crit"]
    return rows


@router.get("/api/scorecards/export")
def scorecards_export():
    with db.get_conn() as c:
        rows = scorecard_export_rows(c)
        t = targets(db.get_settings(c))
    tr = [{"k": k.replace("target_", "").replace("_", " "), "v": v} for k, v in t.items()]
    return xlsx_response([("MSP scorecards", SC_EXPORT, rows), ("Targets", [("k", "Target"), ("v", "Value")], tr)], "msp_scorecards")
