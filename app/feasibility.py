"""EDR feasibility: decided by the console, not taken from the inventory sheet. Live / Non Live does not matter.

Result per inventory node: Yes (feasible) | No (not feasible) | To be decided.
  1. a manual decision on one node (EDR feasibility page, node table) wins
  2. a whole LOB or domain marked not feasible -> No
  3. the feasibility sheet: a Yes / No you set for a Node Type + OS pair (download, edit, upload)
  4. a CrowdStrike agent installed on the node (online or offline) -> Yes; and the same Node Type on the same OS with an
     agent on at least one node (any LOB) -> Yes for every node of that pair
  5. OS: marked on the page (Yes / No); otherwise feasible when any CrowdStrike sensor release ever ran on it - an OS only
     old sensors support is still feasible, the page shows the last sensor version that supported it. Not feasible only
     when no sensor supports it at all (network OS, AIX, Solaris...) and no agent anywhere runs on it.
  6. Node type: marked on the page (Yes / No); otherwise feasible when an agent (online or offline) is installed on at
     least one node of that type - in any LOB. A node type with no agent anywhere is "To be decided" until you mark it.
     A node with a blank node type is decided by its OS alone (unknown OS -> To be decided).
EDR applicable = Yes. "To be decided" is not applicable and is reported separately. Assets in no inventory: feasible when
CrowdStrike has them, otherwise "Unidentified" (VA scan / NIAM only) and left out of the applicable count.

The OS is resolved per node: CrowdStrike (the agent reports it), else the inventory OS column, else the VA scan (Nessus
plugin 11936 "OS Identification", or an Operating System column). OS values are grouped by their catalog entry
("Microsoft Windows Server 2019 Standard" -> "Windows Server 2019") for marks, evidence and the sheet."""
import io
import json

from fastapi import APIRouter, Body, File, HTTPException, Request, UploadFile

from . import db
from .exporter import xlsx_response

router = APIRouter()

KEY = "feasibility_rules"          # legacy rule lists (read once and turned into marks)
MARKS = "feasibility_marks"        # {"lob": {id: "No"}, "domain": {..}, "node_type": {..: "Yes"|"No"}, "os": {..}}
DIMS = ("lob", "domain", "node_type", "os")
TO_DECIDE = "To be decided"
VALID = ("Yes", "No", TO_DECIDE)


def _k(v):
    return " ".join(str(v or "").split()).lower()


def get_marks(c):
    r = c.execute("SELECT value FROM settings WHERE key=?", (MARKS,)).fetchone()
    if r:
        m = db.jloads(r["value"], {})
    else:  # first run after the old rule lists: carry them over
        old = db.jloads((c.execute("SELECT value FROM settings WHERE key=?", (KEY,)).fetchone() or {"value": "{}"})["value"], {})
        m = {d: {} for d in DIMS}
        for d in ("node_type", "domain", "os"):
            for v in old.get(d) or []:
                m[d][_k(v)] = "No"
            for v in old.get(d + "_yes") or []:
                m[d][_k(v)] = "Yes"
    return {d: dict(m.get(d) or {}) for d in DIMS}


def save_marks(c, m):
    c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (MARKS, json.dumps(m)))


def get_rules(c):  # kept for callers of the old API
    return get_marks(c)


def overrides(c):
    return {(r["lob_id"], r["item_key"]): r for r in db.rows(c, "SELECT * FROM feasibility_overrides")}


def sheet_decisions(c):
    """{(lob_id, node type, OS group): decision}; lob_id 0 = a sheet downloaded for every LOB."""
    return {(r["lob_id"], r["node_type"], r["os_key"]): r for r in db.rows(c, "SELECT * FROM feasibility_pairs")}


def os_group(classify, os_):
    """(key, label, catalog entry): OS values grouped by their catalog entry, else by the OS text itself."""
    if not (os_ or "").strip():
        return "", "", None
    e = classify(os_)
    label = e["pattern"] if e else " ".join(os_.split())
    return _k(label), label, e


class Evidence:
    """Where CrowdStrike is actually installed: node types (inventory) and OS groups (inventory + every agent)."""

    def __init__(self):
        self.nt, self.os, self.pair = {}, {}, {}

    def add_node(self, node_type, os_key, installed):
        if installed:
            if _k(node_type):
                self.nt[_k(node_type)] = self.nt.get(_k(node_type), 0) + 1
            if os_key:
                self.os[os_key] = self.os.get(os_key, 0) + 1
            if _k(node_type) and os_key:  # the same node type on the same OS already runs an agent
                self.pair[(_k(node_type), os_key)] = self.pair.get((_k(node_type), os_key), 0) + 1

    def add_agent_os(self, os_key):
        if os_key:
            self.os[os_key] = self.os.get(os_key, 0) + 1


class Decider:
    def __init__(self, marks, ovr, sheet, classify, evidence=None):
        self.m, self.ovr, self.sheet, self.classify = marks, ovr, sheet, classify
        self.ev = evidence or Evidence()

    def os_verdict(self, os_key, label, e):
        """OS on its own: (Yes | No | None = no opinion, reason)."""
        mk = self.m["os"].get(os_key)
        if mk:
            return mk, f"OS marked {'feasible' if mk == 'Yes' else 'not feasible'}: {label}"
        if e and e["status"] == "Not supported":
            if self.ev.os.get(os_key):
                return "Yes", f"OS {label}: no listed sensor, but an agent runs on it"
            return "No", f"OS not supported by any CrowdStrike sensor: {label}"
        if e and e["status"] == "Legacy":
            last = e.get("last_sensor")
            return "Yes", f"OS {label}: old sensors only" + (f" (last sensor {last})" if last else "")
        if e:
            return "Yes", f"OS supported: {label}"
        n = self.ev.os.get(os_key)
        if n:
            return "Yes", f"OS {label}: an agent runs on {n} host{'s' if n > 1 else ''}"
        return None, ""

    def nt_verdict(self, node_type):
        nt = _k(node_type)
        if not nt:
            return None, ""
        mk = self.m["node_type"].get(nt)
        if mk:
            return mk, f"Node type marked {'feasible' if mk == 'Yes' else 'not feasible'}: {node_type}"
        n = self.ev.nt.get(nt)
        if n:
            return "Yes", f"Node type {node_type}: EDR on {n} node{'s' if n > 1 else ''}"
        return TO_DECIDE, f"Node type {node_type}: no agent on any node of this type yet"

    def pair(self, node_type, os_):
        """Verdict for a Node Type + OS pair, ignoring the node-level steps (used by the sheet)."""
        os_key, label, e = os_group(self.classify, os_)
        n = self.ev.pair.get((_k(node_type), os_key)) if os_key else None
        if n and not self.m["os"].get(os_key) == "No" and not self.m["node_type"].get(_k(node_type)) == "No":
            return "Yes", f"{node_type} on {label}: EDR installed on {n} node{'s' if n > 1 else ''}"
        o, why_o = self.os_verdict(os_key, label, e)
        if o == "No":
            return "No", why_o
        n, why_n = self.nt_verdict(node_type)
        if n == "No":
            return "No", why_n
        if n == TO_DECIDE:
            return TO_DECIDE, why_n
        if n is None and o is None:
            return TO_DECIDE, "No node type and OS unknown"
        return "Yes", " · ".join(x for x in (why_n, why_o) if x)

    def __call__(self, lob_id, item_key, *, installed, os_, node_type, domain, inv_feasible=None):
        """-> (Yes | No | To be decided, reason, OS support status or None)"""
        os_key, label, e = os_group(self.classify, os_)
        status = e["status"] if e else None
        o = self.ovr.get((lob_id, item_key))
        if o:
            return o["feasible"], "Set manually" + (f": {o['note']}" if o.get("note") else ""), status
        if self.m["lob"].get(str(lob_id)) == "No":
            return "No", "LOB marked not feasible", status
        d = _k(domain)
        if d and self.m["domain"].get(d) == "No":
            return "No", f"Domain marked not feasible: {domain}", status
        sh = self.sheet.get((int(lob_id or 0), _k(node_type), os_key)) or self.sheet.get((0, _k(node_type), os_key))
        if sh:
            return sh["feasible"], (f"Feasibility sheet{' (this LOB)' if sh['lob_id'] else ''}: "
                                    f"{node_type or '(blank)'} + {label or '(unknown OS)'}"), status
        if installed:
            return "Yes", "EDR installed", status
        f, why = self.pair(node_type, os_)
        return f, why, status


def is_applicable(feasible, installed=False):
    return feasible == "Yes"


def decider(c, evidence=None):
    from .sensor_support import classifier
    return Decider(get_marks(c), overrides(c), sheet_decisions(c), classifier(c), evidence)


def build_evidence(c, classify, items):
    """items: [(node_type, os, installed)] for the inventory nodes being decided; agents in CrowdStrike add OS evidence."""
    ev = Evidence()
    for nt, os_, inst in items:
        ev.add_node(nt, os_group(classify, os_)[0], inst)
    for r in c.execute("""SELECT os_version FROM hosts WHERE COALESCE(os_version,'')<>'' AND
                          (console_state='active' OR (console_state='removed' AND gone_primary=1))"""):
        ev.add_agent_os(os_group(classify, r["os_version"])[0])
    return ev


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
        SUM(feasible='To be decided') to_be_decided, SUM(applicable=1) applicable,
        SUM(os_support='Supported') os_supported, SUM(os_support='Legacy') os_legacy, SUM(os_support='Not supported') os_unsupported,
        SUM(feasible='Yes' AND os_support='Legacy') feasible_legacy_os,
        SUM(feasible='No' AND feasible_reason LIKE '%OS%') by_os, SUM(feasible='No' AND feasible_reason LIKE 'Node type%') by_node_type,
        SUM(feasible='No' AND feasible_reason LIKE 'Domain%') by_domain, SUM(feasible='No' AND feasible_reason LIKE 'LOB%') by_lob,
        SUM(feasible_reason LIKE 'Set manually%') manual, SUM(feasible_reason LIKE 'Feasibility sheet%') by_sheet,
        SUM(feasible_reason='EDR installed') by_edr,
        SUM(COALESCE(os_resolved,'')='') os_unknown, SUM(os_source='edr') os_edr, SUM(os_source='inventory') os_inventory,
        SUM(os_source='scan') os_scan,
        SUM(edr_feasible IN ('Yes','No') AND edr_feasible<>feasible) sheet_differs FROM inventory_current""")
    return {k: v or 0 for k, v in s.items()}


def _agg(rows, key):
    out = {}
    for r in rows:
        k = key(r)
        a = out.setdefault(k[0], {"key": k[0], "value": k[1], "nodes": 0, "installed": 0, "feasible": 0, "not_feasible": 0, "to_be_decided": 0})
        a["nodes"] += 1
        a["installed"] += r["edr_state"] in ("Online", "Offline")
        a["feasible"] += r["feasible"] == "Yes"
        a["not_feasible"] += r["feasible"] == "No"
        a["to_be_decided"] += r["feasible"] == TO_DECIDE
    return sorted(out.values(), key=lambda a: -a["nodes"])


def dimensions(c):
    """Node types, OS groups, LOBs and domains with their node counts, EDR evidence, verdict and your mark."""
    from .sensor_support import classifier, n2_min
    cls = classifier(c)
    d = decider(c)
    rows = db.rows(c, """SELECT ic.lob_id, l.name lob, ic.node_type, ic.domain, ic.os_resolved, ic.edr_state, ic.feasible
                         FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id""")
    ev = build_evidence(c, cls, [(r["node_type"], r["os_resolved"], r["edr_state"] in ("Online", "Offline")) for r in rows])
    d.ev = ev
    m = d.m
    nts = _agg(rows, lambda r: (_k(r["node_type"]), (r["node_type"] or "").strip() or "(blank)"))
    for a in nts:  # auto = what the node type would be without your mark
        a["mark"] = m["node_type"].get(a["key"])
        saved = m["node_type"]
        m["node_type"] = {k: v for k, v in saved.items() if k != a["key"]}
        a["auto"], a["why"] = d.nt_verdict(a["value"]) if a["key"] else (None, "blank node type: decided by the OS")
        m["node_type"] = saved
    oss = _agg(rows, lambda r: os_group(cls, r["os_resolved"])[:2] if (r["os_resolved"] or "").strip() else ("", "(unknown)"))
    for a in oss:
        e = cls(a["value"]) if a["key"] else None
        a["status"], a["last_sensor"], a["platform"] = (e or {}).get("status"), (e or {}).get("last_sensor"), (e or {}).get("platform")
        a["agents"] = ev.os.get(a["key"], 0)
        a["mark"] = m["os"].get(a["key"])
        saved = m["os"]
        m["os"] = {k: v for k, v in saved.items() if k != a["key"]}
        a["auto"], a["why"] = d.os_verdict(a["key"], a["value"], e) if a["key"] else (None, "no OS from the agent, inventory or VA scan")
        m["os"] = saved
    lobs = _agg(rows, lambda r: (str(r["lob_id"]), r["lob"]))
    for a in lobs:
        a["mark"] = m["lob"].get(a["key"])
    doms = _agg(rows, lambda r: (_k(r["domain"]), (r["domain"] or "").strip() or "(blank)"))
    for a in doms:
        a["mark"] = m["domain"].get(a["key"]) if a["key"] else None
    return {"node_type": nts, "os": oss, "lob": lobs, "domain": doms, "n2": {k: ".".join(map(str, v)) for k, v in n2_min(c).items()},
            "sheet": db.one(c, "SELECT COUNT(*) n, MAX(set_at) at FROM feasibility_pairs")}


@router.get("/api/feasibility")
def feasibility_get():
    with db.get_conn() as c:
        return {"summary": _summary(c), "marks": get_marks(c), "dims": dimensions(c),
                "lobs": db.rows(c, "SELECT id, name FROM lobs ORDER BY name COLLATE NOCASE")}


@router.put("/api/feasibility/mark")
def feasibility_mark(data: dict = Body(...)):
    """Mark a whole node type / OS / LOB / domain: {dim, key, feasible: Yes | No | null (automatic)}."""
    dim, key, val = data.get("dim"), data.get("key"), data.get("feasible")
    if dim not in DIMS or not str(key or "").strip():
        raise HTTPException(400, "dim must be lob, domain, node_type or os, with a key")
    if val not in ("Yes", "No", None) or (dim in ("lob", "domain") and val == "Yes"):
        raise HTTPException(400, "feasible must be Yes, No or null (LOB / domain: No or null)")
    with db.get_conn() as c:
        before = _summary(c)
        m = get_marks(c)
        key = str(key) if dim == "lob" else _k(key)
        if val:
            m[dim][key] = val
        else:
            m[dim].pop(key, None)
        save_marks(c, m)
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
        after = _summary(c)
    return {"ok": True, "summary": after, "delta": {k: after[k] - before[k] for k in ("feasible", "not_feasible", "to_be_decided")}}


# ------------------------------------------------------------------ feasibility sheet (download, edit, upload)
# Feasible and Suggested come right after Node Type and OS so the sheet can be worked left to right. The LOB column says
# which LOB a row's decision applies to ("All LOBs" when the sheet was downloaded for every LOB).
SHEET_PAIRS = [("node_type", "Node Type"), ("os", "OS"), ("feasible", "Feasible (Yes/No)"), ("suggested", "Suggested"),
               ("os_support", "OS Support"), ("last_sensor", "Last Sensor Version"), ("why", "Why"), ("lob", "LOB"),
               ("nodes", "Nodes"), ("installed", "With EDR (online or offline)"), ("types", "Inventory Types"), ("remarks", "Remarks")]
SHEET_SCOPE = [("value", "{dim}"), ("feasible", "Feasible (Yes/No)"), ("nodes", "Nodes"), ("installed", "With EDR (online or offline)"),
               ("remarks", "Remarks")]
GUIDE = [("step", "How to use"), ("text", "")]
ALL_LOBS = "All LOBs"


def _scope_rows(c, lob=None, inv_type=None, node_type=None):
    w, params = [], []
    if lob:
        w.append("ic.lob_id=?")
        params.append(int(lob))
    if inv_type == "main":
        w.append("ic.type_id IS NULL")
    elif inv_type:
        w.append("ic.type_id=?")
        params.append(int(inv_type))
    if node_type:
        w.append("LOWER(TRIM(COALESCE(ic.node_type,'')))=?")
        params.append("" if node_type == "(blank)" else _k(node_type))
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return db.rows(c, f"""SELECT ic.lob_id, l.name lob, ic.node_type, ic.domain, ic.os_resolved, ic.edr_state,
        COALESCE(t.name, 'Main') inv_type FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id
        LEFT JOIN lob_types t ON t.id=ic.type_id {where}""", params)


def _decider_with_evidence(c):
    from .sensor_support import classifier
    cls = classifier(c)
    d = decider(c)
    inv = db.rows(c, "SELECT node_type, os_resolved, edr_state FROM inventory_current")
    d.ev = build_evidence(c, cls, [(r["node_type"], r["os_resolved"], r["edr_state"] in ("Online", "Offline")) for r in inv])
    return cls, d


@router.get("/api/feasibility/sheet")
def feasibility_sheet_download(lob: int = 0, type: str = "", node_type: str = ""):
    """The whole estate, or one LOB, one inventory type and / or one node type at a time."""
    with db.get_conn() as c:
        cls, d = _decider_with_evidence(c)
        rows = _scope_rows(c, lob or None, type or None, node_type or None)
        lob_name = db.one(c, "SELECT name FROM lobs WHERE id=?", (lob,))["name"] if lob else None
        type_name = ("Main" if type == "main" else (db.one(c, "SELECT name FROM lob_types WHERE id=?", (int(type),)) or {}).get("name")) if type else None
        pairs = {}
        for r in rows:
            ok, label, e = os_group(cls, r["os_resolved"])
            p = pairs.setdefault((_k(r["node_type"]), ok), {"node_type": (r["node_type"] or "").strip(), "os": label, "e": e,
                                                             "nodes": 0, "installed": 0, "types": set()})
            p["nodes"] += 1
            p["installed"] += r["edr_state"] in ("Online", "Offline")
            p["types"].add(r["inv_type"])
        out = []
        for (ntk, ok), p in sorted(pairs.items(), key=lambda kv: (kv[1]["node_type"].lower(), -kv[1]["nodes"])):
            auto, why = ("Yes", "EDR installed on nodes of this pair") if p["installed"] else d.pair(p["node_type"], p["os"])
            sh = d.sheet.get((lob or 0, ntk, ok))
            out.append({"node_type": p["node_type"] or "(blank)", "os": p["os"] or "(unknown)", "nodes": p["nodes"],
                        "installed": p["installed"], "types": ", ".join(sorted(p["types"])), "lob": lob_name or ALL_LOBS,
                        "os_support": {"Legacy": "Old sensors only", "Not supported": "No sensor", "Supported": "Supported"}.get((p["e"] or {}).get("status"), ""),
                        "last_sensor": (p["e"] or {}).get("last_sensor") or "",
                        "suggested": auto, "why": why, "feasible": sh["feasible"] if sh else ("" if auto == TO_DECIDE else auto),
                        "remarks": (sh or {}).get("remarks") or ""})
        m = get_marks(c)
        lob_rows, dom_rows = {}, {}
        for r in rows:
            a = lob_rows.setdefault(r["lob_id"], {"value": r["lob"], "key": str(r["lob_id"]), "nodes": 0, "installed": 0})
            a["nodes"] += 1
            a["installed"] += r["edr_state"] in ("Online", "Offline")
            if (r["domain"] or "").strip():
                b = dom_rows.setdefault(_k(r["domain"]), {"value": r["domain"].strip(), "key": _k(r["domain"]), "nodes": 0, "installed": 0})
                b["nodes"] += 1
                b["installed"] += r["edr_state"] in ("Online", "Offline")

    def scope(dim, title, items):
        return (title, [(k, l.format(dim=title)) for k, l in SHEET_SCOPE],
                [{**a, "feasible": "No" if m[dim].get(a["key"]) == "No" else "Yes", "remarks": ""}
                 for a in sorted(items.values(), key=lambda a: -a["nodes"])])
    scope_txt = " · ".join(x for x in (f"LOB: {lob_name}" if lob_name else "All LOBs", f"Inventory type: {type_name}" if type_name else "",
                                       f"Node type: {node_type}" if node_type else "") if x)
    guide = [{"step": s, "text": t} for s, t in [
        ("Scope", scope_txt),
        ("1", "Sheet 'Node Type x OS': one row per Node Type + OS pair in this scope. 'Suggested' is what the console decides on its own."),
        ("2", "Set 'Feasible (Yes/No)'. Leave it equal to Suggested (or empty) to keep the automatic decision."),
        ("3", "The LOB column says where the decision applies: a LOB name = that LOB only, 'All LOBs' = every LOB. Keep it as downloaded."),
        ("4", "Sheets 'LOB' and 'Domain': No = every node of that LOB / domain is not feasible, Yes = automatic."),
        ("5", "Upload on the EDR feasibility page. Only the rows in the file are changed, so sheets for other LOBs / types stay as they are."),
        ("", "Automatic: an OS is feasible when any CrowdStrike sensor release ran on it (old sensors included); a node type is feasible "
             "when an agent is installed on at least one node of that type; a node with an agent is always feasible."),
    ]]
    name = "_".join(x for x in ("edr_feasibility", (lob_name or "all_lobs"), type_name or "", node_type or "") if x)
    return xlsx_response([("Node Type x OS", SHEET_PAIRS, out), scope("lob", "LOB", lob_rows), scope("domain", "Domain", dom_rows),
                          ("How to use", GUIDE, guide)], "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in name))


def _yn(v):
    v = _k(v)
    return "Yes" if v in ("yes", "y", "true", "1", "feasible") else "No" if v in ("no", "n", "false", "0", "not feasible", "notfeasible") else None


@router.post("/api/feasibility/sheet")
async def feasibility_sheet_upload(file: UploadFile = File(...)):
    """Apply a filled-in sheet. Only the rows in the file change: other LOBs, types and node types keep their decisions."""
    from .inventory import read_xlsx
    try:
        book = read_xlsx(await file.read(), all_sheets=True)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Not an Excel file: {e}")
    stats = {"pairs": 0, "pairs_stored": 0, "pairs_auto": 0, "lob_no": 0, "domain_no": 0, "skipped": 0}
    with db.get_conn() as c:
        cls, d = _decider_with_evidence(c)
        inv = db.rows(c, "SELECT lob_id, node_type, os_resolved, edr_state FROM inventory_current")
        pair_installed = {}
        for r in inv:
            if r["edr_state"] in ("Online", "Offline"):
                k = (_k(r["node_type"]), os_group(cls, r["os_resolved"])[0])
                for scope_id in (0, r["lob_id"]):
                    pair_installed[(scope_id, *k)] = pair_installed.get((scope_id, *k), 0) + 1
        lob_ids = {_k(r["name"]): r["id"] for r in db.rows(c, "SELECT id, name FROM lobs")}
        m = get_marks(c)
        found, now = False, db.now_iso()
        for rows_ in book.values():
            it = iter(rows_)
            head = [_k(h) for h in (next(it, None) or [])]
            col = lambda *names: next((i for i, h in enumerate(head) if any(h.startswith(n) for n in names)), None)  # noqa: E731
            fcol = col("feasible")
            if fcol is None:
                continue
            ntc, osc, lc, rc = col("node type"), col("os"), col("lob"), col("remarks")
            if ntc is not None and osc is not None:
                found = True
                for row in it:
                    nt = "" if row[ntc] in (None, "(blank)") else str(row[ntc]).strip()
                    os_ = "" if row[osc] in (None, "(unknown)") else str(row[osc]).strip()
                    if not nt and not os_:
                        continue
                    lname = _k(row[lc]) if lc is not None else ""
                    scope_id = 0 if lname in ("", _k(ALL_LOBS)) else lob_ids.get(lname)
                    if scope_id is None:
                        stats["skipped"] += 1
                        continue
                    stats["pairs"] += 1
                    ok = os_group(cls, os_)[0]
                    auto = "Yes" if pair_installed.get((scope_id, _k(nt), ok)) else d.pair(nt, os_)[0]
                    val = _yn(row[fcol])
                    if val is None or val == auto:
                        c.execute("DELETE FROM feasibility_pairs WHERE lob_id=? AND node_type=? AND os_key=?", (scope_id, _k(nt), ok))
                        stats["pairs_auto"] += 1
                        continue
                    c.execute("""INSERT OR REPLACE INTO feasibility_pairs(lob_id, node_type, os_key, node_type_label, os_label, feasible,
                                 remarks, set_at) VALUES (?,?,?,?,?,?,?,?)""",
                              (scope_id, _k(nt), ok, nt, os_, val, str(row[rc] or "") if rc is not None else "", now))
                    stats["pairs_stored"] += 1
                continue
            for dim in ("lob", "domain"):
                vc = col(dim)
                if vc is None:
                    continue
                found = True
                for row in it:
                    name = _k(row[vc])
                    if not name or name == "(blank)":
                        continue
                    key = str(lob_ids[name]) if dim == "lob" and name in lob_ids else (name if dim == "domain" else None)
                    if not key:
                        stats["skipped"] += 1
                        continue
                    if _yn(row[fcol]) == "No":
                        m[dim][key] = "No"
                        stats[f"{dim}_no"] += 1
                    else:
                        m[dim].pop(key, None)
                break
        if not found:
            raise HTTPException(400, "No sheet with a 'Feasible' column and Node Type + OS, LOB or Domain columns")
        save_marks(c, m)
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
        stats["summary"] = _summary(c)
    return stats


@router.delete("/api/feasibility/sheet")
def feasibility_sheet_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM feasibility_pairs")
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
    return {"ok": True}


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
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
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
    elif reason in ("OS not supported", "OS supported", "OS marked", "Node type marked", "Domain marked", "LOB marked",
                    "Set manually", "EDR installed", "Feasibility sheet", "Node type"):
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
            ("live", "Live / Non Live"), ("os_resolved", "OS"), ("os_source", "OS Source"),
            ("feasible", "EDR Feasible"), ("cs_agent_version", "Sensor Version"), ("sensor_level", "Sensor Level"),
            ("feasible_reason", "Reason"), ("edr_feasible", "EDR Feasible (inventory sheet)"), ("edr_state", "EDR Status")]
    return xlsx_response([("EDR feasibility", cols, rows)], "edr_feasibility")
