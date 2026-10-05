"""VA public inventory: the sheet of publicly reachable hosts handed to the VA team (Public IP, Private IP, LOB, MSP …).

Each upload is a full snapshot (it replaces the previous one). Every row is checked against what the console already knows:
  LOB inventory         matched on the private IP (or the public IP when the row has no private IP, also through the
                        inventory's public / NAT IP column); LOB, MSP, Node Type, Domain and NIAM are compared
  communication matrix  the public <-> private NAT pairs of the matrix; a private IP missing on either side, or a different
                        one, is a difference
Every row is publicly exposed: the registry lists the private IP (or the public IP when there is none) on Internet exposed,
taking LOB / MSP / node type from the LOB inventory and, when no inventory lists the host, from this sheet."""
import json
import re

from fastapi import APIRouter, Body, HTTPException, Request

from . import db, inventory
from .addrparse import parse_addresses
from .exporter import xlsx_response

router = APIRouter()

FIELDS = [("lob", "LOB", False), ("node_type", "Node Type", False), ("domain", "Domain", False), ("application", "Application", False),
          ("public_ip", "Public IP", True), ("subnet", "Subnet IP belongs to", False), ("private_ip", "Private IP", False),
          ("p2p", "P2P or Public", False), ("path", "Firewall or ISP", False), ("gateway", "Firewall/Gateway IP", False),
          ("dmz", "DMZ (Yes / No)", False), ("owner", "Bharti Owner Details", False), ("msp", "MS Partner", False),
          ("spoc", "MS Partner SPOC", False), ("niam", "NIAM Integration", False)]
KEYS = [k for k, _, _ in FIELDS]
LABEL = {k: l for k, l, _ in FIELDS}
ALIASES = {
    "lob": ["lob", "lineofbusiness"], "node_type": ["nodetype", "type", "devicetype"], "domain": ["domain"],
    "application": ["application", "app", "applicationname"], "public_ip": ["publicip", "publicips", "natip", "externalip"],
    "subnet": ["subnetipbelongsto", "subnet", "publicsubnet", "subnetip"], "private_ip": ["privateip", "internalip", "privateips", "localip"],
    "p2p": ["p2porpublic", "p2p", "connectivity", "p2ppublic"], "path": ["firewallorisp", "firewallisp", "path", "isporfirewall"],
    "gateway": ["firewallgatewayip", "gatewayip", "firewallip", "gateway"], "dmz": ["dmzyesno", "dmz"],
    "owner": ["bhartiownerdetails", "ownerdetails", "owner", "bhartiowner"], "msp": ["mspartner", "msp", "partner"],
    "spoc": ["mspartnerspoc", "mspspoc", "spoc", "partnerspoc"], "niam": ["niamintigration", "niamintegration", "niam"],
}


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    mapping, used = {}, set()
    for f in KEYS:
        for a in ALIASES[f]:
            hit = next((h for h in headers if h not in used and _norm(h) == a), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def _ips(text):
    """Every single IP in a cell: lists (ip1;ip2, ip1, ip2, new lines), last-octet shorthand (10.2.3.1/2/3/4) and small ranges
    (10.2.3.1-4, up to 64 addresses) are expanded; larger subnets are not hosts and are left out."""
    out = []
    for n in parse_addresses(text or "")[1]:
        if n.num_addresses == 1:
            out.append(str(n.network_address))
        elif n.num_addresses <= 64:
            out += [str(a) for a in n]
    return list(dict.fromkeys(out))


def build(parsed, mapping):
    idx = {h: i for i, h in enumerate(parsed["headers"])}

    def cell(r, k):
        i = idx.get(mapping.get(k))
        return str(r[i] if i is not None and i < len(r) and r[i] is not None else "").strip()
    out, bad = [], 0
    for n, r in enumerate(parsed["rows"], start=1):
        v = {k: cell(r, k) for k in KEYS}
        if not _ips(v["public_ip"]) and not _ips(v["private_ip"]):
            bad += 1
            continue
        v["row_no"] = n
        out.append(v)
    return out, ([f"{bad} rows skipped (no valid Public IP or Private IP)"] if bad else [])


def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    if not mapping.get("public_ip") and not mapping.get("private_ip"):
        raise HTTPException(400, "Map the Public IP column (and Private IP when the sheet has it)")
    rows, warnings = build(parsed, mapping)
    if not rows:
        raise HTTPException(400, "No rows with a valid Public IP or Private IP")
    return parsed, mapping, rows, warnings


@router.post("/api/vapub/parse")
def vapub_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/vapub/preview")
def vapub_preview(data: dict = Body(...)):
    _, _, rows, warnings = _load(data)
    with db.get_conn() as c:
        cur = c.execute("SELECT COUNT(*) FROM va_public").fetchone()[0]
    return {"stats": [["Rows in file", len(rows), ""], ["With a private IP", sum(1 for r in rows if _ips(r["private_ip"])), "info"],
                      ["Public IP only", sum(1 for r in rows if not _ips(r["private_ip"])), "warn"], ["Rows replaced", cur, ""]],
            "warnings": warnings, "note": "The sheet replaces the previous VA public inventory. Every row is checked against the LOB "
                                          "inventory and the communication matrix after loading; differences show under Vulnerabilities › "
                                          "VA public inventory and on Internet exposed.",
            "sample_cols": [["public_ip", "Public IP"], ["private_ip", "Private IP"], ["lob", "LOB"], ["msp", "MS Partner"],
                            ["node_type", "Node Type"], ["application", "Application"]],
            "sample": rows[:50]}


@router.post("/api/vapub/commit")
def vapub_commit(data: dict = Body(...)):
    parsed, mapping, rows, warnings = _load(data)
    with db.get_conn() as c:
        uid = c.execute("""INSERT INTO va_public_uploads(filename, note, uploaded_by, uploaded_at, rows, mapping, warnings)
                           VALUES (?,?,?,?,?,?,?)""", (parsed["filename"], data.get("note", ""), data.get("uploaded_by", ""), db.now_iso(),
                                                     len(rows), json.dumps(mapping), json.dumps(warnings[:50]))).lastrowid
        c.execute("DELETE FROM va_public")
        c.executemany(f"INSERT INTO va_public(upload_id, row_no, {', '.join(KEYS)}) VALUES ({','.join('?' * (len(KEYS) + 2))})",
                      [(uid, r["row_no"], *[r[k] for k in KEYS]) for r in rows])
        inventory.refresh_soon(c, label="Matching the VA public inventory")  # registry: these hosts are publicly exposed
    return {"message": f"{len(rows):,} VA public inventory rows loaded", "rows": len(rows)}


# ------------------------------------------------------------------ differences
def _yn(v):
    v = (v or "").strip().lower()
    return "Yes" if v in ("yes", "y", "integrated", "true", "1") else "No" if v in ("no", "n", "not integrated", "false", "0") else (v or "")


def _same(a, b):
    return _norm(a) == _norm(b)


def compare(c):
    """Every VA row with its differences, kept until the sheet, the matrix or the asset registry (inventory, NAT columns) change."""
    from .registry import VERSION
    key = (VERSION[0], *db.sig(c, "SELECT COUNT(*), MAX(id), MAX(upload_id) FROM va_public",
                               "SELECT COUNT(*), COALESCE(MAX(id),0), COALESCE(SUM(inbound_internet),0) FROM comm_rules",
                               "SELECT COUNT(*), MAX(rowid) FROM inventory_current"))
    return db.memo("vapub_compare", key, lambda: _compare(c))


def _compare(c):
    """Every VA row with its differences: [{field, va, other, source}] against the LOB inventory and the communication matrix."""
    from .commatrix import load_rules, matrix_pairs
    from .registry import is_public
    rows = db.rows(c, "SELECT * FROM va_public ORDER BY row_no")
    if not rows:
        return []
    pub_of, priv_of = matrix_pairs(load_rules(c))
    inv = {}
    for r in db.rows(c, """SELECT ic.ip, l.name lob, ic.msp, ic.node_type, ic.domain, ic.niam_integrated, ic.node_name, ic.os_resolved
                          FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id WHERE COALESCE(ic.ip,'')<>''"""):
        inv.setdefault(r["ip"], r)
    from .registry import inventory_exposure
    nat_inv = {}  # public IP -> private IPs, from the LOB inventories' own public / NAT IP columns (not the registry, which this sheet feeds)
    for r in c.execute("SELECT ip, extra FROM inventory_current WHERE COALESCE(ip,'')<>'' AND extra IS NOT NULL"):
        for p in inventory_exposure(r["extra"])[1]:
            if p != r["ip"]:
                nat_inv.setdefault(p, set()).add(r["ip"])
    niam_ips = {r[0] for r in c.execute("SELECT ip FROM niam_nodes WHERE present=1 AND ip<>''")}
    out = []
    for v in rows:
        pubs = [p for p in _ips(v["public_ip"]) if is_public(p)] or _ips(v["public_ip"])
        privs = [p for p in _ips(v["private_ip"]) if not is_public(p)]
        diffs = []
        # private IP: what the matrix / inventory NAT columns pair with the public IP(s)
        m_priv = set().union(*[priv_of.get(p, set()) for p in pubs]) if pubs else set()
        n_priv = set().union(*[nat_inv.get(p, set()) for p in pubs]) if pubs else set()
        for src, known in (("Communication matrix", m_priv), ("LOB inventory (NAT column)", n_priv)):
            if known and not privs:
                diffs.append({"field": "Private IP", "va": "", "other": ", ".join(sorted(known)), "source": src})
            elif known and privs and not (known & set(privs)):
                diffs.append({"field": "Private IP", "va": ", ".join(privs), "other": ", ".join(sorted(known)), "source": src})
        # public IP: what the matrix pairs with the private IP(s)
        m_pub = set().union(*[pub_of.get(p, set()) for p in privs]) if privs else set()
        if m_pub and pubs and not (m_pub & set(pubs)):
            diffs.append({"field": "Public IP", "va": ", ".join(pubs), "other": ", ".join(sorted(m_pub)), "source": "Communication matrix"})
        elif m_pub and not pubs:
            diffs.append({"field": "Public IP", "va": "", "other": ", ".join(sorted(m_pub)), "source": "Communication matrix"})
        in_matrix = bool(m_priv or m_pub or any(p in priv_of for p in pubs))
        # LOB inventory fields: matched on the private IP, else the public IP (directly or through the inventory NAT column)
        key = next((p for p in privs if p in inv), None) or next((p for p in pubs if p in inv), None) or next(
            (x for p in pubs for x in sorted(nat_inv.get(p, ())) if x in inv), None)
        row = inv.get(key) if key else None
        if row:
            for f, col in (("lob", "lob"), ("msp", "msp"), ("node_type", "node_type"), ("domain", "domain")):
                if v[f] and row[col] and not _same(v[f], row[col]):
                    diffs.append({"field": LABEL[f], "va": v[f], "other": row[col], "source": "LOB inventory"})
                elif row[col] and not v[f]:
                    diffs.append({"field": LABEL[f], "va": "", "other": row[col], "source": "LOB inventory"})
            inv_niam = row["niam_integrated"] or ("Yes" if key in niam_ips else "")
            if v["niam"] and inv_niam and _yn(v["niam"]) != _yn(inv_niam):
                diffs.append({"field": LABEL["niam"], "va": v["niam"], "other": inv_niam, "source": "LOB inventory / NIAM"})
        out.append({**v, "public_ips": ", ".join(pubs), "private_ips": ", ".join(privs), "asset_ip": privs[0] if privs else (pubs[0] if pubs else ""),
                    "in_inventory": bool(row), "inventory_ip": key or "", "inv_lob": row["lob"] if row else "", "inv_msp": row["msp"] if row else "",
                    "inv_node_name": row["node_name"] if row else "", "os": row["os_resolved"] if row else "", "in_matrix": in_matrix,
                    "diffs": diffs, "diff_fields": sorted({d["field"] for d in diffs}),
                    "diff_text": "; ".join(f"{d['field']}: VA '{d['va'] or '–'}' vs {d['source']} '{d['other']}'" for d in diffs),
                    "status": "differs" if diffs else ("not_known" if not row and not in_matrix else "match")})
    return out


STATUS = {"match": "Matches", "differs": "Differs", "not_known": "Not in inventory or matrix"}


def _filter(p, rows):
    if p.get("status"):
        rows = [r for r in rows if r["status"] in db.multi(p, "status")]
    if p.get("diff"):
        want = set(db.multi(p, "diff"))
        rows = [r for r in rows if want & set(r["diff_fields"])]
    if p.get("in_inventory") in ("0", "1"):
        rows = [r for r in rows if r["in_inventory"] == (p["in_inventory"] == "1")]
    if p.get("in_matrix") in ("0", "1"):
        rows = [r for r in rows if r["in_matrix"] == (p["in_matrix"] == "1")]
    if p.get("has_private") in ("0", "1"):
        rows = [r for r in rows if bool(r["private_ips"]) == (p["has_private"] == "1")]
    q = (p.get("q") or "").strip().lower()
    if q:
        rows = [r for r in rows if q in " ".join(str(r.get(k) or "") for k in (*KEYS, "inv_node_name", "diff_text")).lower()]
    return rows


@router.get("/api/vapub/rows")
def vapub_rows(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    with db.get_conn() as c:
        allr = compare(c)
        up = db.one(c, "SELECT filename, uploaded_at, uploaded_by, rows FROM va_public_uploads ORDER BY id DESC LIMIT 1")
    rows = _filter(p, allr)
    fields = sorted({f for r in allr for f in r["diff_fields"]})
    counts = {"all": len(allr), **{s: sum(1 for r in allr if r["status"] == s) for s in STATUS},
              "no_private": sum(1 for r in allr if not r["private_ips"]), "not_in_inventory": sum(1 for r in allr if not r["in_inventory"]),
              "fields": {f: sum(1 for r in allr if f in r["diff_fields"]) for f in fields}}
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size], "counts": counts, "upload": up}


EXPORT = [("public_ip", "Public IP"), ("private_ip", "Private IP (VA sheet)"), ("status_text", "Check"), ("diff_text", "Differences"),
          ("inventory_ip", "Matched inventory IP"), ("inv_node_name", "Inventory node name"), ("inv_lob", "Inventory LOB"),
          ("inv_msp", "Inventory MSP"), ("os", "OS (inventory)"), ("in_matrix_text", "In communication matrix"),
          *[(k, LABEL[k]) for k in KEYS if k not in ("public_ip", "private_ip")]]


@router.get("/api/vapub/rows/export")
def vapub_export(request: Request):
    with db.get_conn() as c:
        rows = _filter(dict(request.query_params), compare(c))
    for r in rows:
        r["status_text"] = STATUS.get(r["status"], r["status"])
        r["in_matrix_text"] = "Yes" if r["in_matrix"] else "No"
    return xlsx_response([("VA public inventory", EXPORT, rows)], "va_public_inventory_check")


@router.delete("/api/vapub")
def vapub_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM va_public")
        inventory.refresh_soon(c, label="Removing the VA public inventory")
    return {"ok": True}
