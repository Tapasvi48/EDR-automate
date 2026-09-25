"""Bulk lookup, cross-LOB coverage summary and the executive Excel report."""
import re

from fastapi import APIRouter, Body

from . import db, queries
from .exporter import xlsx_response
from .sync import exclusion_patterns, ip_excluded

router = APIRouter()


def _chunks(seq, n=500):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _terms(text):
    seen, out = set(), []
    for t in re.split(r"[\s,;]+", text or ""):
        t = t.strip().strip('"').strip("'")
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out[:20000]


def _lookup(c, text, stale_h):
    terms = _terms(text)
    ips = [t for t in terms if db.ip_to_num(t) is not None]
    names = [t for t in terms if t not in ips]
    host_cols = "aid, hostname, hostname_norm, local_ip, console_state, online_state, last_seen, first_seen, agent_version, os_version, platform_name"
    by_ip, by_hn, hist = {}, {}, {}
    for ch in _chunks(ips):
        ph = ",".join("?" * len(ch))
        for r in db.rows(c, f"SELECT {host_cols} FROM hosts WHERE local_ip IN ({ph})", ch):
            by_ip.setdefault(r["local_ip"], []).append(r)
        for r in db.rows(c, f"""SELECT ih.ip, h.aid, h.hostname, h.local_ip, h.console_state, h.online_state, h.last_seen
                               FROM ip_history ih JOIN hosts h ON h.aid=ih.aid WHERE ih.kind='local' AND ih.ip IN ({ph})""", ch):
            hist.setdefault(r["ip"], {})[r["aid"]] = r
    norms = [db.norm_hostname(n) for n in names]
    for ch in _chunks(norms):
        ph = ",".join("?" * len(ch))
        for r in db.rows(c, f"SELECT {host_cols} FROM hosts WHERE hostname_norm IN ({ph})", ch):
            by_hn.setdefault(r["hostname_norm"], []).append(r)
    inv = {}
    for ch in _chunks(terms):
        ph = ",".join("?" * len(ch))
        low = [t.lower() for t in ch]
        for r in db.rows(c, f"""SELECT l.name lob, ic.ip, LOWER(ic.node_name) nn, ic.edr_installed, ic.verification FROM inventory_current ic
                               JOIN lobs l ON l.id=ic.lob_id WHERE ic.ip IN ({ph}) OR LOWER(ic.node_name) IN ({ph})""", ch + low):
            for key in (r["ip"], r["nn"], db.norm_hostname(r["nn"])):
                if key:
                    inv.setdefault(key, []).append(r)
    stale_cut = queries.iso_ago(hours=stale_h)
    out = []
    for t in terms:
        is_ip = t in ips
        cands = by_ip.get(t, []) if is_ip else by_hn.get(db.norm_hostname(t), [])
        rank = lambda h: ({"active": 0, "hidden": 1}.get(h["console_state"], 2), "" if not h["last_seen"] else h["last_seen"])  # noqa: E731
        cands = sorted(cands, key=lambda h: (rank(h)[0], -int(re.sub(r"\D", "", h["last_seen"] or "0") or 0)))
        historical = []
        if is_ip and not cands:
            historical = sorted(hist.get(t, {}).values(), key=lambda h: h["last_seen"] or "", reverse=True)
        best = cands[0] if cands else None
        if best:
            if best["console_state"] != "active":
                status = "Removed" if best["console_state"] == "removed" else "Hidden"
            elif best["online_state"] == "online":
                status = "Online (stale)" if (best["last_seen"] or "") < stale_cut else "Online"
            elif best["online_state"] == "offline":
                status = "Offline"
            else:
                status = "Unknown"
        elif historical:
            status = "IP seen in history only"
        else:
            status = "Not Found"
        inv_rows = inv.get(t if is_ip else t.lower(), []) or ([] if is_ip else inv.get(db.norm_hostname(t), []))
        out.append({
            "term": t, "type": "ip" if is_ip else "hostname", "status": status,
            "active_agents": sum(1 for h in cands if h["console_state"] == "active"), "total_agents": len(cands),
            "hostname": best["hostname"] if best else (historical[0]["hostname"] if historical else ""),
            "aid": best["aid"] if best else (historical[0]["aid"] if historical else ""),
            "local_ip": best["local_ip"] if best else (historical[0]["local_ip"] if historical else ""),
            "last_seen": best["last_seen"] if best else (historical[0]["last_seen"] if historical else ""),
            "first_seen": best["first_seen"] if best else "",
            "os_version": best["os_version"] if best else "", "agent_version": best["agent_version"] if best else "",
            "lobs": ", ".join(sorted({r["lob"] for r in inv_rows})),
            "inv_edr_installed": ", ".join(sorted({r["edr_installed"] for r in inv_rows if r["edr_installed"]})),
            "inv_verification": ", ".join(sorted({r["verification"] for r in inv_rows if r["verification"]})),
        })
    return out


LOOKUP_COLS = [("term", "Input"), ("type", "Type"), ("status", "EDR Status"), ("hostname", "Falcon Hostname"), ("aid", "Agent ID"),
               ("local_ip", "Current IP"), ("last_seen", "Last Seen (UTC)"), ("first_seen", "First Seen (UTC)"),
               ("active_agents", "Active Agents"), ("total_agents", "Total Agents"), ("os_version", "OS"),
               ("agent_version", "Sensor"), ("lobs", "LOB"), ("inv_edr_installed", "Inventory EDR Installed"),
               ("inv_verification", "Inventory Verification")]


@router.post("/api/lookup")
def lookup(data: dict = Body(...)):
    with db.get_conn() as c:
        s = db.get_settings(c)
        rows = _lookup(c, data.get("text", ""), float(s.get("stale_online_hours") or 1))
    summary = {}
    for r in rows:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return {"rows": rows, "summary": summary, "total": len(rows)}


@router.post("/api/lookup/export")
def lookup_export(data: dict = Body(...)):
    with db.get_conn() as c:
        s = db.get_settings(c)
        rows = _lookup(c, data.get("text", ""), float(s.get("stale_online_hours") or 1))
    return xlsx_response([("Lookup", LOOKUP_COLS, rows)], "bulk_lookup")


@router.get("/api/coverage")
def coverage():
    with db.get_conn() as c:
        settings = db.get_settings(c)
        by_type = db.rows(c, """SELECT COALESCE(NULLIF(node_type,''),'(blank)') label, COUNT(*) nodes, SUM(applicable=1) applicable,
            SUM(applicable=1 AND edr_state IN ('Online','Offline')) installed, SUM(applicable=1 AND edr_state='Offline') offline,
            SUM(applicable=1 AND edr_state NOT IN ('Online','Offline')) pending
            FROM inventory_current GROUP BY 1 ORDER BY nodes DESC LIMIT 15""")
        status = db.rows(c, """SELECT coverage_status label, COUNT(*) n FROM inventory_current GROUP BY 1 ORDER BY n DESC""")
        unmapped = c.execute("SELECT COUNT(*) FROM hosts h LEFT JOIN host_map hm ON hm.aid=h.aid WHERE h.console_state='active' AND hm.aid IS NULL").fetchone()[0]
        return {"lobs": queries.lob_summaries(c, settings), "msps": queries.msp_summaries(c, settings), "status": status,
                "by_node_type": by_type, "unmapped": unmapped}


@router.get("/api/reports/executive")
def executive_report():
    with db.get_conn() as c:
        s = db.get_settings(c)
        d = queries.dashboard(c, s)
        k = d["kpi"]
        summary = [{"metric": m, "value": v} for m, v in [
            ("Hosts in console", k["active"]), ("Online", k["online"]), ("Offline", k["offline"]),
            (f"Online but last seen > {d['stale_hours']}h", k["stale_online"]), ("Hidden", k["hidden"]),
            ("Removed from console (tracked)", k["removed"]), ("Removed last 7 days", k["removed_7d"]),
            ("  - auto-removed (inactive)", k["auto_removed_7d"]), ("  - deleted", k["deleted_7d"]),
            ("New installs today", k["new_today"]), ("New installs 7 days", k["new_7d"]), ("New installs 30 days", k["new_30d"]),
            ("Reinstalls 7 days", k["reinstall_7d"]), ("Reinstalls 30 days", k["reinstall_30d"]),
            ("Went offline last 24h", k["went_offline_24h"]), ("Went offline last 7 days", k["went_offline_7d"]),
            ("Offline > 30 days", k["offline_gt30d"]), ("Duplicate IP groups", k["dup_ip_groups"]),
            ("Hosts sharing an IP", k["dup_ip_hosts"]), ("Duplicate hostname groups", k["dup_hn_groups"]),
            ("Outdated sensor (older than N-2)", k["outdated_sensor"]), ("Reduced functionality mode", k["rfm"]),
            ("Contained", k["contained"]), ("Unmapped agents (no LOB)", k["not_in_inventory"]),
        ]]
        cov_cols = [("nodes", "Nodes"), ("applicable", "Applicable"), ("installed", "Installed"), ("online", "Online"),
                    ("offline", "Offline"), ("pending", "Pending"), ("not_installed", "Not Installed"), ("hidden", "Hidden"),
                    ("removed", "Removed"), ("coverage", "Coverage %"), ("not_feasible", "Not Feasible"), ("non_live", "Non Live"),
                    ("unlisted", "Not in Inventory"), ("edr_dup_ips", "Duplicate IPs (EDR)"),
                    ("claimed_missing", "Inventory Yes - Not Installed"), ("marked_no", "Inventory No - Installed")]
        lob_cols = [("name", "LOB"), ("msp_count", "MSPs")] + cov_cols + [("cross_msp_dup_ips", "IPs in >1 MSP"),
                                                                          ("current_version", "Inventory Version"), ("uploaded_at", "Last Upload")]
        msp_cols = [("lob", "LOB"), ("msp", "MSP")] + cov_cols

        def hosts(params):
            if params.get("outdated") == "1":
                queries.prepare_outdated_temp(c)
            frm, where, prm, order = queries.build_host_query(params, s)
            return db.rows(c, f"SELECT {queries.HOST_LIST_COLS} FROM {frm} {where} {order} LIMIT 50000", prm)

        hc = queries.HOST_EXPORT_COLUMNS
        dups = []
        g = queries.duplicate_groups(c, s, "ip", "", False, 100000, 0)
        for grp in g["rows"]:
            for m in queries.duplicate_members(c, "ip", grp["value"]):
                dups.append({"group": grp["value"], "group_size": grp["n"], **m})
        inv_issues = db.rows(c, """SELECT l.name lob, ic.* FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
            WHERE ic.applicable=1 AND ic.edr_state<>'Online' ORDER BY l.name, ic.msp, ic.coverage_status""")
        inv_cols = [("lob", "LOB"), ("msp", "MSP"), ("coverage_status", "EDR Status"), ("ip", "IP"), ("node_name", "Node Name"), ("node_type", "Node Type"), ("live", "Live"),
                    ("edr_feasible", "EDR Feasible"), ("edr_installed", "EDR Installed (Inventory)"), ("edr_actual", "EDR Actual"),
                    ("verification", "Verification"), ("cs_hostname", "Falcon Hostname"), ("cs_last_seen", "Falcon Last Seen"),
                    ("remarks", "Remarks")]
        sheets = [
            ("Summary", [("metric", "Metric"), ("value", "Value")], summary),
            ("LOB Coverage", lob_cols, d["lobs"]),
            ("MSP Coverage", msp_cols, queries.msp_summaries(c, s)),
            ("Pending & Offline Nodes", inv_cols, inv_issues),
            ("Online - Stale", hc, hosts({"online": "online", "stale_online": "1", "sort": "last_seen", "dir": "asc"})),
            ("Offline over 7d", hc, hosts({"online": "offline", "seen_bucket": "gt7d", "sort": "last_seen", "dir": "asc"})),
            ("Went offline 7d", hc, hosts({"online": "offline", "last_from": queries.iso_ago(days=7)})),
            ("New installs 30d", hc, hosts({"state": "all", "first_from": queries.iso_ago(days=30), "sort": "first_seen"})),
            ("Reinstalls 30d", hc, hosts({"state": "all", "reinstall": "1", "first_from": queries.iso_ago(days=30), "sort": "first_seen"})),
            ("Removed 30d", hc, hosts({"state": "removed", "removed_from": queries.iso_ago(days=30), "sort": "removed_at"})),
            ("Duplicate IPs", [("group", "IP"), ("group_size", "Agents"), ("hostname", "Hostname"), ("aid", "Agent ID"),
                               ("console_state", "Console"), ("online_state", "Online"), ("first_seen", "First Seen"),
                               ("last_seen", "Last Seen"), ("os_version", "OS")], dups),
            ("Not in Inventory", hc, hosts({"unlisted": "1"})),
            ("Unmapped Agents", hc, hosts({"unmapped": "1"})),
            ("Outdated Sensor", hc, hosts({"outdated": "1"})),
        ]
    return xlsx_response(sheets, "edr_executive_report")


def ip_is_excluded(ip, settings):
    return ip_excluded(ip, exclusion_patterns(settings))
