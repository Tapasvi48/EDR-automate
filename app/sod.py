"""Vulnerability exceptions (SOD / risk acceptance).

The uploaded sheet is the complete exception register: each upload replaces the previous list (history is kept in
sod_uploads). An active exception (Valid Till empty or not passed) turns matching open findings into status 'accepted':
they stay visible, but leave open counts, risk scores and exposure numbers. When an exception expires or is removed, its
findings go back to 'open' on the next re-join (every sync / upload), so nothing stays hidden by accident.

A finding matches when the vulnerability matches (Plugin ID, or a CVE in the finding's CVE list, or the exact name),
the port matches (blank = any port) and the scope covers it: All, IP, Subnet (IPv4 / IPv6 CIDR) or LOB."""
import json
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Request

from . import db, inventory
from .exporter import xlsx_response

router = APIRouter()

FIELDS = [("exception_id", "Exception ID", True), ("scope", "Scope", False), ("target", "IP / Subnet", False), ("lob", "LOB", False),
          ("plugin_id", "Plugin ID", False), ("cve", "CVE", False), ("name", "Vulnerability Name", False), ("port", "Port", False),
          ("justification", "Justification", True), ("control", "Compensating Control", False), ("approved_by", "Approved By", True),
          ("approval_date", "Approval Date", False), ("valid_till", "Valid Till", True), ("ticket", "Ticket / CR No.", False),
          ("remarks", "Remarks", False)]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "exception_id": ["exceptionid", "exception", "sodid", "sod", "id", "exceptionno", "riskacceptanceid"],
    "scope": ["scope", "type", "exceptiontype", "level"],
    "target": ["ipsubnet", "ip", "ipaddress", "subnet", "target", "host", "asset"],
    "lob": ["lob", "lineofbusiness", "businessunit"],
    "plugin_id": ["pluginid", "plugin", "nessusid"],
    "cve": ["cve", "cves", "cveid"],
    "name": ["vulnerabilityname", "vulnerability", "name", "pluginname", "title"],
    "port": ["port", "ports"],
    "justification": ["justification", "reason", "businessjustification", "rationale"],
    "control": ["compensatingcontrol", "control", "mitigation"],
    "approved_by": ["approvedby", "approver", "approvedauthority"],
    "approval_date": ["approvaldate", "approvedon", "dateofapproval"],
    "valid_till": ["validtill", "validuntil", "expiry", "expirydate", "expireson", "enddate"],
    "ticket": ["ticketcrno", "ticket", "crno", "cr", "changerequest", "riskid"],
    "remarks": ["remarks", "comments", "notes"],
}
COLS = [k for k in KEYS] + ["status"]


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    from .filetemplates import custom_aliases
    custom = custom_aliases("sod")
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    for f in KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == alias), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def build(parsed, mapping):
    if not mapping.get("exception_id"):
        raise ValueError("Map the Exception ID column")
    if not any(mapping.get(k) for k in ("plugin_id", "cve", "name")):
        raise ValueError("Map at least one of: Plugin ID, CVE or Vulnerability Name")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    out, warnings, seen = [], [], set()
    bad = {"no vulnerability": 0, "bad scope": 0, "missing approval": 0, "duplicate": 0}
    for r in parsed["rows"]:
        v = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        if not v["exception_id"] and not any(v[k] for k in ("plugin_id", "cve", "name")):
            continue
        if not any(v[k] for k in ("plugin_id", "cve", "name")):
            bad["no vulnerability"] += 1
            continue
        scope = v["scope"].lower()
        target = v["target"]
        if not scope:
            scope = "subnet" if "/" in target else "ip" if target else "lob" if v["lob"] else "all"
        scope = {"host": "ip", "ip address": "ip", "cidr": "subnet", "range": "subnet", "network": "subnet", "global": "all",
                 "any": "all", "line of business": "lob"}.get(scope, scope)
        if scope not in ("ip", "subnet", "lob", "all"):
            bad["bad scope"] += 1
            continue
        if scope == "ip":
            if not db.is_ip(target):
                bad["bad scope"] += 1
                continue
            target = db.canon_ip(target)
        elif scope == "subnet":
            net = db.parse_net(target)
            if not net:
                bad["bad scope"] += 1
                continue
            target = str(net)
        elif scope == "lob" and not v["lob"]:
            bad["bad scope"] += 1
            continue
        if not (v["justification"] and v["approved_by"] and v["valid_till"]):
            bad["missing approval"] += 1
            continue
        key = v["exception_id"] or f"row-{len(out) + 1}"
        if key in seen:
            bad["duplicate"] += 1
            continue
        seen.add(key)
        v.update(exception_id=key, scope={"ip": "IP", "subnet": "Subnet", "lob": "LOB", "all": "All"}[scope], target=target,
                 port=re.sub(r"\D", "", v["port"]), valid_till=(db.parse_ts(v["valid_till"]) or v["valid_till"])[:10],
                 approval_date=(db.parse_ts(v["approval_date"]) or v["approval_date"])[:10], plugin_id=re.sub(r"\.0$", "", v["plugin_id"]))
        out.append(v)
    for k, n in bad.items():
        if n:
            warnings.append({"no vulnerability": f"{n} rows skipped: no Plugin ID, CVE or name",
                             "bad scope": f"{n} rows skipped: scope / IP / subnet / LOB not valid",
                             "missing approval": f"{n} rows skipped: Justification, Approved By and Valid Till are required",
                             "duplicate": f"{n} rows skipped: repeated Exception ID"}[k])
    return out, warnings


# ------------------------------------------------------------------ matching
def _cves(text):
    return {c.upper() for c in re.findall(r"CVE-\d{4}-\d+", text or "", re.I)}


def apply(c):
    """Mark findings covered by an active exception as accepted, and reopen those that no longer are."""
    now = today()
    ex = [e for e in db.rows(c, "SELECT * FROM vuln_exceptions") if not e["valid_till"] or e["valid_till"] >= now]
    by_plugin, by_cve, by_name = {}, {}, {}
    for e in ex:
        e["_net"] = db.parse_net(e["target"]) if e["scope"] == "Subnet" else None
        if e["plugin_id"]:
            by_plugin.setdefault(e["plugin_id"], []).append(e)
        for cv in _cves(e["cve"]):
            by_cve.setdefault(cv, []).append(e)
        if e["name"]:
            by_name.setdefault(e["name"].strip().lower(), []).append(e)
    lobs = {r["id"]: (r["name"] or "").lower() for r in c.execute("SELECT id, name FROM lobs")}
    import ipaddress
    upd, counts = [], {}
    for f in db.rows(c, """SELECT id, lob_id, ip, plugin_id, cve, name, port, status, exception_ref FROM vuln_findings
                          WHERE status IN ('open','accepted')"""):
        cands = list(by_plugin.get(f["plugin_id"] or "", []))
        for cv in _cves(f["cve"]):
            cands += by_cve.get(cv, [])
        cands += by_name.get((f["name"] or "").strip().lower(), [])
        hit = None
        for e in cands:
            if e["port"] and e["port"] != str(f["port"] or ""):
                continue
            sc = e["scope"]
            if sc == "IP" and f["ip"] != e["target"]:
                continue
            if sc == "Subnet":
                try:
                    if not e["_net"] or ipaddress.ip_address(f["ip"]) not in e["_net"]:
                        continue
                except ValueError:
                    continue
            if sc == "LOB" and lobs.get(f["lob_id"]) != (e["lob"] or "").strip().lower():
                continue
            hit = e
            break
        if hit:
            counts[hit["id"]] = counts.get(hit["id"], 0) + 1
            if f["status"] != "accepted" or f["exception_ref"] != hit["exception_id"]:
                upd.append(("accepted", hit["exception_id"], f["id"]))
        elif f["status"] == "accepted":
            upd.append(("open", None, f["id"]))
    c.executemany("UPDATE vuln_findings SET status=?, exception_ref=? WHERE id=?", upd)
    c.execute("UPDATE vuln_exceptions SET matched=0")
    c.executemany("UPDATE vuln_exceptions SET matched=? WHERE id=?", [(n, i) for i, n in counts.items()])


def _status(e, now, soon):
    if e["valid_till"] and e["valid_till"] < now:
        return "Expired"
    if e["valid_till"] and e["valid_till"] <= soon:
        return "Expiring"
    return "Active"


# ------------------------------------------------------------------ routes
def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    rows, warnings = build(parsed, mapping)
    if not rows:
        raise ValueError("No valid exceptions found with this mapping" + (": " + "; ".join(warnings) if warnings else ""))
    return parsed, mapping, rows, warnings


@router.post("/api/sod/parse")
def sod_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/sod/preview")
def sod_preview(data: dict = Body(...)):
    _, _, rows, warnings = _load(data)
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        cur = {r[0] for r in c.execute("SELECT exception_id FROM vuln_exceptions")}
    new_ids = {r["exception_id"] for r in rows}
    st = [_status(r, now, soon) for r in rows]
    return {"stats": [["Exceptions in file", len(rows), ""], ["Active", st.count("Active") + st.count("Expiring"), "good"],
                      ["Already expired", st.count("Expired"), "crit"], ["Expire in 30 days", st.count("Expiring"), "warn"],
                      ["New", len(new_ids - cur), "info"], ["Removed (not in this file)", len(cur - new_ids), "crit"]],
            "warnings": warnings, "note": "The file replaces the current exception list.",
            "sample_cols": [["exception_id", "Exception"], ["scope", "Scope"], ["target", "IP / Subnet / LOB"], ["plugin_id", "Plugin"],
                            ["cve", "CVE"], ["valid_till", "Valid till"]],
            "sample": [{**r, "target": r["target"] or r["lob"] or "All"} for r in rows[:50]]}


@router.post("/api/sod/commit")
def sod_commit(data: dict = Body(...)):
    parsed, mapping, rows, warnings = _load(data)
    with db.get_conn() as c:
        cur = {r[0] for r in c.execute("SELECT exception_id FROM vuln_exceptions")}
        new_ids = {r["exception_id"] for r in rows}
        uid = c.execute("""INSERT INTO sod_uploads(filename, note, uploaded_by, uploaded_at, rows, added, removed, mapping, warnings)
                           VALUES (?,?,?,?,?,?,?,?,?)""", (parsed["filename"], data.get("note", ""), data.get("uploaded_by", ""), db.now_iso(),
                                                          len(rows), len(new_ids - cur), len(cur - new_ids), json.dumps(mapping),
                                                          json.dumps(warnings))).lastrowid
        c.execute("DELETE FROM vuln_exceptions")
        c.executemany(f"INSERT INTO vuln_exceptions({', '.join(KEYS)}, upload_id, created_at) VALUES ({','.join('?' * (len(KEYS) + 2))})",
                      [(*[r[k] for k in KEYS], uid, db.now_iso()) for r in rows])
        inventory.refresh_soon(c)  # re-join: accepted findings leave open counts, risk and exposure
        accepted = c.execute("SELECT COUNT(*) FROM vuln_findings WHERE status='accepted'").fetchone()[0]
    return {"message": f"{len(rows)} exceptions loaded · {accepted} findings now accepted", "rows": len(rows)}


@router.get("/api/sod/summary")
def sod_summary():
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        ex = db.rows(c, "SELECT valid_till, matched FROM vuln_exceptions")
        acc = db.one(c, """SELECT COUNT(*) n, SUM(sev_rank=4) crit, SUM(sev_rank=3) high, COUNT(DISTINCT ip) hosts
                           FROM vuln_findings WHERE status='accepted'""")
        last = db.one(c, "SELECT * FROM sod_uploads ORDER BY id DESC LIMIT 1")
    st = [_status(e, now, soon) for e in ex]
    return {"exceptions": len(ex), "active": st.count("Active") + st.count("Expiring"), "expiring": st.count("Expiring"),
            "expired": st.count("Expired"), "unused": sum(1 for e, s in zip(ex, st) if s != "Expired" and not e["matched"]),
            "accepted": acc["n"] or 0, "accepted_crit": acc["crit"] or 0, "accepted_high": acc["high"] or 0,
            "accepted_hosts": acc["hosts"] or 0, "last_upload": last}


def _query(p):
    w, params = [], []
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    st = p.get("status")
    if st == "Expired":
        w.append("valid_till<>'' AND valid_till<?")
        params.append(now)
    elif st == "Expiring":
        w.append("valid_till>=? AND valid_till<=?")
        params += [now, soon]
    elif st == "Active":
        w.append("(valid_till='' OR valid_till>=?)")
        params.append(now)
    if p.get("unused") == "1":
        w.append("matched=0 AND (valid_till='' OR valid_till>=?)")
        params.append(now)
    q = (p.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        w.append("(exception_id LIKE ? OR target LIKE ? OR lob LIKE ? OR plugin_id=? OR cve LIKE ? OR name LIKE ? OR approved_by LIKE ? OR ticket LIKE ?)")
        params += [like, like, like, q, like, like, like, like]
    return ("WHERE " + " AND ".join(w)) if w else "", params


@router.get("/api/sod/exceptions")
def sod_list(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params = _query(p)
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM vuln_exceptions {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT * FROM vuln_exceptions {where} ORDER BY valid_till, exception_id LIMIT ? OFFSET ?",
                       params + [size, (page - 1) * size])
    for r in rows:
        r["state"] = _status(r, now, soon)
    return {"total": total, "rows": rows}


@router.get("/api/sod/exceptions/export")
def sod_export(request: Request):
    where, params = _query(dict(request.query_params))
    now = today()
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT * FROM vuln_exceptions {where} ORDER BY valid_till, exception_id", params)
    for r in rows:
        r["state"] = _status(r, now, soon)
    cols = [(k, l) for k, l, _ in FIELDS] + [("state", "Status"), ("matched", "Findings Accepted")]
    return xlsx_response([("Exceptions", cols, rows)], "vulnerability_exceptions")


@router.delete("/api/sod")
def sod_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM vuln_exceptions")
        inventory.refresh_soon(c)
    return {"ok": True}


@router.get("/api/sod/uploads")
def sod_uploads():
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT id, filename, note, uploaded_by, uploaded_at, rows, added, removed FROM sod_uploads ORDER BY id DESC")}
