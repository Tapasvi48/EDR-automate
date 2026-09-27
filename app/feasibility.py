"""EDR feasibility: decided by the console, not taken from the inventory sheet. It depends only on the node's OS and
node type / domain (Live / Non Live does not matter).

Result per inventory node: Yes (feasible) | No (not feasible) | Legacy | To be decided.
  1. a manual decision set on the EDR feasibility page wins
  2. the OS, looked up in the OS support catalog (sensor_support.py: what the supported sensors run on):
       Legacy OS         -> Legacy: only end-of-life sensor versions ever ran on it (that package is no longer
                            maintained and the current cloud certificates do not cover it)
       Not supported OS  -> No; Legacy if an agent is somehow installed
       an "OS contains" rule you added on the page counts as Not supported
  3. an agent installed on a supported OS -> Yes
  4. rules you added: OS / node type / domain marked as feasible -> Yes, marked as not feasible -> No
  5. optionally the inventory's own "EDR Feasible" column (off by default: it is often wrong)
  6. OS Supported -> Yes
  7. OS unknown, or known but not in the support catalog -> To be decided (needs a decision: the catalog cannot say
     whether any sensor can run on it)
EDR applicable = Yes, or Legacy with an agent installed (the agent runs, on an old sensor). A Legacy node without an agent
is not applicable: no current sensor can be installed. "To be decided" is not applicable until it is decided, and is
reported separately so the pending count stays visible. Assets in no inventory: feasible when CrowdStrike has them,
otherwise "Unidentified" (VA scan / NIAM only) and left out of the applicable count.

The OS is resolved per node: CrowdStrike (the agent reports it), else the inventory OS column, else the VA scan (Nessus
plugin 11936 "OS Identification", or an Operating System column)."""
import json

from fastapi import APIRouter, Body, HTTPException, Request

from . import db
from .exporter import xlsx_response

router = APIRouter()

KEY = "feasibility_rules"
DEFAULT = {"os": [], "node_type": [], "domain": [], "os_yes": [], "node_type_yes": [], "domain_yes": [],
           "use_inventory_column": False}
# rules the page lets you edit: "*" = mark not feasible, "*_yes" = mark feasible
RULE_KEYS = ("os", "node_type", "domain", "os_yes", "node_type_yes", "domain_yes")
TO_DECIDE = "To be decided"
VALID = ("Yes", "No", "Legacy", TO_DECIDE)


def get_rules(c):
    r = c.execute("SELECT value FROM settings WHERE key=?", (KEY,)).fetchone()
    rules = dict(DEFAULT)
    rules.update(db.jloads(r["value"], {}) if r else {})
    return rules


def _clean(vals):
    out = []
    for v in vals or []:
        v = " ".join(str(v or "").split())
        if v and v.lower() not in [x.lower() for x in out]:
            out.append(v)
    return out


def overrides(c):
    return {(r["lob_id"], r["item_key"]): r for r in db.rows(c, "SELECT * FROM feasibility_overrides")}


class Decider:
    def __init__(self, rules, ovr, classify):
        self.os = [(v, v.lower()) for v in rules.get("os") or []]
        self.os_yes = [(v, v.lower()) for v in rules.get("os_yes") or []]
        self.nt = {v.lower(): v for v in rules.get("node_type") or []}
        self.nt_yes = {v.lower(): v for v in rules.get("node_type_yes") or []}
        self.dom = {v.lower(): v for v in rules.get("domain") or []}
        self.dom_yes = {v.lower(): v for v in rules.get("domain_yes") or []}
        self.use_inv = bool(rules.get("use_inventory_column"))
        self.ovr = ovr
        self.classify = classify

    def __call__(self, lob_id, item_key, *, installed, os_, node_type, domain, inv_feasible):
        """-> (feasible Yes | No | Legacy | To be decided, reason, OS support status or None)"""
        e = self.classify(os_)
        status = e["status"] if e else None
        osl = (os_ or "").lower()
        rule = next((v for v, vl in self.os if vl in osl), None)
        if rule and status != "Legacy":
            status = "Not supported"
        o = self.ovr.get((lob_id, item_key))
        if o:
            return o["feasible"], "Set manually" + (f": {o['note']}" if o.get("note") else ""), status
        label = f"OS rule: {rule}" if rule else (f"{e['pattern']}" if e else "")
        if status == "Legacy":
            return "Legacy", (f"Legacy OS: {label or os_} · only end-of-life sensors ran on it (that package is no longer "
                              "maintained and the current cloud certificates do not cover it)"
                              + (" · agent installed" if installed else " · no current sensor runs on it")), status
        if status == "Not supported":
            if installed:
                return "Legacy", f"OS not supported: {label} · agent installed anyway", status
            return "No", (label if rule else f"OS not supported by CrowdStrike: {label}"), status
        if installed:
            return "Yes", "EDR installed", status
        nt = (node_type or "").strip().lower()
        d = (domain or "").strip().lower()
        yes = next((v for v, vl in self.os_yes if vl in osl), None)
        if yes:
            return "Yes", f"OS rule (feasible): {yes}", status
        if nt and nt in self.nt_yes:
            return "Yes", f"Node type rule (feasible): {self.nt_yes[nt]}", status
        if d and d in self.dom_yes:
            return "Yes", f"Domain rule (feasible): {self.dom_yes[d]}", status
        if nt and nt in self.nt:
            return "No", f"Node type rule: {self.nt[nt]}", status
        if d and d in self.dom:
            return "No", f"Domain rule: {self.dom[d]}", status
        if self.use_inv and inv_feasible == "No":
            return "No", "Inventory sheet says No", status
        if status == "Supported":
            return "Yes", f"OS supported: {e['pattern']}", status
        if os_:
            return TO_DECIDE, f"OS not in the support catalog ({os_}) · Feasibility to be decided", status
        return TO_DECIDE, "OS unknown (no agent, no inventory OS column, no VA scan) · Feasibility to be decided", status


def is_applicable(feasible, installed):
    return feasible == "Yes" or (feasible == "Legacy" and installed)


def decider(c):
    from .sensor_support import classifier
    return Decider(get_rules(c), overrides(c), classifier(c))


def resolve_os(edr_os, inv_os, scan):
    """(os, source) - CrowdStrike, else the inventory column, else the VA scan."""
    if edr_os:
        return edr_os, "edr"
    if (inv_os or "").strip():
        return inv_os.strip(), "inventory"
    if scan:
        return scan[0], "scan"
    return None, None


# ------------------------------------------------------------------ API
def _summary(c):
    s = db.one(c, """SELECT COUNT(*) nodes, SUM(feasible='Yes') feasible, SUM(feasible='No') not_feasible,
        SUM(feasible='Legacy') legacy, SUM(feasible='Legacy' AND edr_state IN ('Online','Offline')) legacy_installed,
        SUM(feasible='To be decided') to_be_decided,
        SUM(os_support='Supported') os_supported, SUM(os_support='Legacy') os_legacy, SUM(os_support='Not supported') os_unsupported,
        SUM(applicable=1) applicable,
        SUM(feasible='No' AND (feasible_reason LIKE 'OS rule%' OR feasible_reason LIKE 'OS not supported%')) by_os, SUM(feasible_reason LIKE 'Node type rule:%') by_node_type,
        SUM(feasible_reason LIKE 'Domain rule:%') by_domain, SUM(feasible_reason LIKE 'Set manually%') manual,
        SUM(feasible_reason LIKE 'Node type rule (feasible)%') by_node_type_yes, SUM(feasible_reason LIKE 'Domain rule (feasible)%') by_domain_yes,
        SUM(feasible_reason LIKE 'OS rule (feasible)%') by_os_yes, SUM(feasible_reason LIKE '%OS not in the support%') os_not_in_catalog,
        SUM(feasible_reason='EDR installed') by_edr, SUM(feasible_reason LIKE 'Inventory sheet%') by_sheet,
        SUM(COALESCE(os_resolved,'')='') os_unknown, SUM(os_source='edr') os_edr, SUM(os_source='inventory') os_inventory,
        SUM(os_source='scan') os_scan,
        SUM(edr_feasible IN ('Yes','No') AND edr_feasible<>feasible) sheet_differs FROM inventory_current""")
    return {k: v or 0 for k, v in s.items()}


def _facets(c):
    def dist(col):
        return db.rows(c, f"""SELECT {col} value, COUNT(*) nodes, SUM(feasible='No') not_feasible,
            SUM(feasible='To be decided') to_be_decided, SUM(feasible='Yes') feasible,
            SUM(edr_state IN ('Online','Offline')) installed FROM inventory_current
            WHERE COALESCE({col},'')<>'' GROUP BY {col} COLLATE NOCASE ORDER BY nodes DESC LIMIT 400""")
    return {"os": dist("os_resolved"), "node_type": dist("node_type"), "domain": dist("domain")}


@router.get("/api/feasibility")
def feasibility_get():
    with db.get_conn() as c:
        return {"rules": get_rules(c), "summary": _summary(c), "facets": _facets(c),
                "lobs": db.rows(c, "SELECT id, name FROM lobs ORDER BY name COLLATE NOCASE")}


@router.post("/api/feasibility/preview")
def feasibility_preview(data: dict = Body(...)):
    """What the draft rules would change, before saving."""
    rules = {**DEFAULT, **{k: _clean(data.get(k)) for k in RULE_KEYS},
             "use_inventory_column": bool(data.get("use_inventory_column"))}
    with db.get_conn() as c:
        from .sensor_support import classifier
        d = Decider(rules, overrides(c), classifier(c))
        to_no = to_yes = feasible = to_decide = 0
        for r in c.execute("""SELECT lob_id, item_key, os_resolved, node_type, domain, edr_feasible, edr_state, feasible
                              FROM inventory_current"""):
            f, _, _ = d(r["lob_id"], r["item_key"], installed=r["edr_state"] in ("Online", "Offline"), os_=r["os_resolved"],
                     node_type=r["node_type"], domain=r["domain"], inv_feasible=r["edr_feasible"])
            feasible += f == "Yes"
            to_decide += f == TO_DECIDE
            to_no += f != "Yes" and r["feasible"] == "Yes"
            to_yes += f == "Yes" and r["feasible"] != "Yes"
    return {"feasible": feasible, "to_not_feasible": to_no, "to_feasible": to_yes, "to_be_decided": to_decide}
    return {"feasible": feasible, "to_not_feasible": to_no, "to_feasible": to_yes}


@router.put("/api/feasibility/rules")
def feasibility_save(data: dict = Body(...)):
    rules = {k: _clean(data.get(k)) for k in RULE_KEYS}
    rules["use_inventory_column"] = bool(data.get("use_inventory_column"))
    with db.get_conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (KEY, json.dumps(rules)))
        from .inventory import refresh_matches
        refresh_matches(c)
        return {"rules": rules, "summary": _summary(c)}


@router.post("/api/feasibility/override")
def feasibility_override(data: dict = Body(...)):
    """Set (Yes / No / Legacy / To be decided) or clear (null) the decision for inventory nodes: items [{lob_id, item_key}]."""
    val, items = data.get("feasible"), data.get("items") or []
    if val is not None and val not in VALID:
        raise HTTPException(400, "feasible must be one of " + ", ".join(VALID) + " or null")
    with db.get_conn() as c:
        if isinstance(data.get("filter"), dict):  # every node matching the page's current filters
            from .queries import prepare_outdated_temp
            prepare_outdated_temp(c)
            where, params, _ = _query({k: str(v) for k, v in data["filter"].items() if v not in (None, "")})
            items = db.rows(c, f"SELECT ic.lob_id, ic.item_key FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id {where}", params)
        if val:
            c.executemany("""INSERT OR REPLACE INTO feasibility_overrides(lob_id, item_key, feasible, note, set_at)
                             VALUES (?,?,?,?,?)""",
                          [(int(i["lob_id"]), i["item_key"], val, (data.get("note") or "").strip() or None, db.now_iso()) for i in items])
        else:
            c.executemany("DELETE FROM feasibility_overrides WHERE lob_id=? AND item_key=?", [(int(i["lob_id"]), i["item_key"]) for i in items])
        from .inventory import refresh_matches
        refresh_matches(c)
        return {"ok": True, "updated": len(items), "summary": _summary(c)}


SORTS = {"ip": "ic.ip", "node_name": "ic.node_name COLLATE NOCASE", "lob": "l.name", "node_type": "ic.node_type",
         "domain": "ic.domain", "os": "ic.os_resolved COLLATE NOCASE", "feasible": "ic.feasible", "reason": "ic.feasible_reason",
         "edr": "ic.edr_state"}


def _query(p):
    w, params = [], []
    if p.get("lob"):
        w.append("ic.lob_id=?")
        params.append(int(p["lob"]))
    if p.get("feasible") in VALID:
        w.append("ic.feasible=?")
        params.append(p["feasible"])
    reason = p.get("reason")
    if reason == "rule":
        w.append("ic.feasible_reason LIKE '%rule:%'")
    elif reason in ("Legacy OS", "OS not supported", "OS supported", "OS rule", "Node type rule", "Domain rule",
                    "Set manually", "EDR installed", "Inventory sheet",
                    "OS rule (feasible)", "Node type rule (feasible)", "Domain rule (feasible)",
                    "OS not in the support catalog", "OS unknown"):
        w.append("ic.feasible_reason LIKE ?")
        params.append(reason + "%")
    if p.get("os_support") in ("Supported", "Legacy", "Not supported"):
        w.append("ic.os_support=?")
        params.append(p["os_support"])
    elif p.get("os_support") == "unknown":
        w.append("ic.os_support IS NULL")
    if p.get("sensor") in ("N", "N-1", "N-2", "older"):
        from .queries import prepare_outdated_temp
        w.append("""(SELECT s.lvl FROM _sensor_rel s JOIN hosts h ON h.aid=ic.matched_aid
                     WHERE s.platform=COALESCE(h.platform_name,'') AND s.v=h.agent_version) = ?""")
        params.append(p["sensor"])
    if p.get("differs") == "1":
        w.append("ic.edr_feasible IN ('Yes','No') AND ic.edr_feasible<>ic.feasible")
    if p.get("os_source"):
        if p["os_source"] == "none":
            w.append("COALESCE(ic.os_resolved,'')=''")
        else:
            w.append("ic.os_source=?")
            params.append(p["os_source"])
    for f in ("node_type", "domain"):
        if p.get(f):
            w.append(f"ic.{f}=? COLLATE NOCASE")
            params.append(p[f])
    if p.get("os"):
        w.append("ic.os_resolved LIKE ?")
        params.append(f"%{p['os']}%")
    q = (p.get("q") or "").strip()
    if q:
        if db.is_ip(q):
            w.append("ic.ip=?")
            params.append(db.canon_ip(q))
        else:
            like = f"%{q}%"
            w.append("(ic.ip LIKE ? OR ic.node_name LIKE ? OR ic.os_resolved LIKE ? OR ic.node_type LIKE ? OR ic.domain LIKE ?)")
            params += [q + "%", like, like, like, like]
    where = ("WHERE " + " AND ".join(w)) if w else ""
    order = f"ORDER BY {SORTS.get(p.get('sort') or '', 'l.name, ic.ip')} {'DESC' if p.get('dir') == 'desc' else 'ASC'}"
    return where, params, order


COLS = """ic.lob_id, l.name lob, ic.item_key, ic.ip, ic.node_name, ic.msp, ic.node_type, ic.domain, ic.live, ic.os os_inventory,
    ic.cs_os, ic.os_resolved, ic.os_source, ic.os_support, ic.edr_feasible, ic.feasible, ic.feasible_reason, ic.applicable,
    ic.edr_state, ic.cs_agent_version,
    (SELECT s.lvl FROM _sensor_rel s JOIN hosts h ON h.aid=ic.matched_aid
     WHERE s.platform=COALESCE(h.platform_name,'') AND s.v=h.agent_version AND ic.edr_state IN ('Online','Offline')) sensor_level"""


@router.get("/api/feasibility/nodes")
def feasibility_nodes(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params, order = _query(p)
    with db.get_conn() as c:
        from .queries import prepare_outdated_temp
        prepare_outdated_temp(c)
        frm = "inventory_current ic JOIN lobs l ON l.id=ic.lob_id"
        total = c.execute(f"SELECT COUNT(*) FROM {frm} {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT {COLS} FROM {frm} {where} {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    return {"total": total, "rows": rows}


@router.get("/api/feasibility/export")
def feasibility_export(request: Request):
    p = dict(request.query_params)
    where, params, order = _query(p)
    with db.get_conn() as c:
        from .queries import prepare_outdated_temp
        prepare_outdated_temp(c)
        rows = db.rows(c, f"SELECT {COLS} FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id {where} {order}", params)
    cols = [("lob", "LOB"), ("ip", "IP"), ("node_name", "Node Name"), ("msp", "MSP"), ("node_type", "Node Type"), ("domain", "Domain"),
            ("live", "Live / Non Live"), ("os_resolved", "OS"), ("os_source", "OS Source"), ("os_support", "OS Support (N-2 sensors)"),
            ("feasible", "EDR Feasible"), ("cs_agent_version", "Sensor Version"), ("sensor_level", "Sensor Level"),
            ("feasible_reason", "Reason"), ("edr_feasible", "EDR Feasible (inventory sheet)"), ("edr_state", "EDR Status")]
    return xlsx_response([("EDR feasibility", cols, rows)], "edr_feasibility")
