"""Communication matrix (firewall / NAT flows, telecom environment).

The uploaded sheet is the complete matrix; each upload replaces the previous one (history in comm_uploads). How it is used:
  - internet exposure: an active Allow rule whose source is the internet (direction Inbound, source zone Internet / ISP /
    Untrust / Outside / External, source Any / 0.0.0.0/0 / a public IP, or an ISP link) makes every known asset inside its
    destination (IP, CIDR or list) internet-exposed on the rule's ports; the destination NAT (public) IP is linked to it
  - flows: Asset 360 lists every rule where the asset is a source or destination
Rules whose Valid Till has passed are kept but ignored."""
import ipaddress
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Request

from . import db, inventory
from .exporter import xlsx_response

router = APIRouter()

FIELDS = [("rule_id", "Rule ID", True), ("direction", "Direction", False), ("src_zone", "Source Zone", False),
          ("src", "Source IP / Subnet", True), ("src_nat", "Source NAT IP", False), ("isp", "ISP / Link", False),
          ("firewall", "Firewall", False), ("fw_rule", "Firewall Rule Name", False), ("dst_zone", "Destination Zone", False),
          ("dst_nat", "Destination NAT IP (Public)", False), ("dst", "Destination IP / Subnet", True), ("protocol", "Protocol", False),
          ("ports", "Port(s)", False), ("service", "Application / Service", False), ("action", "Action", False),
          ("cr", "Change / CR No.", False), ("valid_till", "Valid Till", False), ("remarks", "Remarks", False)]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "rule_id": ["ruleid", "rule", "flowid", "id", "ruleno", "sno"], "direction": ["direction", "flowdirection", "traffictype"],
    "src_zone": ["sourcezone", "srczone", "fromzone"], "src": ["sourceipsubnet", "sourceip", "srcip", "source", "sourcesubnet", "src"],
    "src_nat": ["sourcenatip", "srcnat", "snat", "sourcenat"], "isp": ["isplink", "isp", "link", "carrier"],
    "firewall": ["firewall", "fw", "firewallname", "device"], "fw_rule": ["firewallrulename", "rulename", "policyname", "policy"],
    "dst_zone": ["destinationzone", "dstzone", "tozone"], "dst_nat": ["destinationnatippublic", "destinationnatip", "dstnat", "dnat", "publicip", "vip", "natip"],
    "dst": ["destinationipsubnet", "destinationip", "dstip", "destination", "destinationsubnet", "dst"],
    "protocol": ["protocol", "proto"], "ports": ["ports", "port", "dstport", "destinationport", "service port"],
    "service": ["applicationservice", "application", "service"], "action": ["action", "permit"],
    "cr": ["changecrno", "crno", "cr", "change", "approval"], "valid_till": ["validtill", "validuntil", "expiry", "expirydate"],
    "remarks": ["remarks", "comments", "notes"],
}
INTERNET_ZONE = re.compile(r"internet|isp|untrust|outside|external|public|wan", re.I)
ANY = re.compile(r"^(any|all|\*|0\.0\.0\.0/0|::/0|internet)$", re.I)


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers):
    from .filetemplates import custom_aliases
    custom = custom_aliases("comm_matrix")
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    for f in KEYS:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == _norm(alias)), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def endpoints(text):
    """'10.1.1.1, 10.2.0.0/16, Any' -> (is_any, [ip_network...])"""
    nets, anyv = [], False
    for tok in re.split(r"[\s,;|]+", str(text or "").strip()):
        if not tok:
            continue
        if ANY.match(tok):
            anyv = True
            continue
        if "-" in tok and not tok.startswith("-"):  # range 10.1.1.10-10.1.1.20 (or -20) -> covering networks
            a, _, b = tok.partition("-")
            if db.is_ip(a):
                a = db.canon_ip(a)
                b = db.canon_ip(b) if db.is_ip(b) else (a.rsplit(".", 1)[0] + "." + b if "." in a and b.isdigit() else "")
                try:
                    nets += list(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
                    continue
                except (ValueError, TypeError):
                    pass
        n = db.parse_net(tok) if "/" in tok else (ipaddress.ip_network(db.canon_ip(tok)) if db.is_ip(tok) else None)
        if n:
            nets.append(n)
    return anyv, nets


def is_inbound_internet(r):
    from .registry import is_public
    if (r["action"] or "allow").strip().lower() not in ("allow", "permit", "accept", "yes", ""):
        return False
    if re.match(r"^\s*in", r["direction"] or "", re.I) and (INTERNET_ZONE.search(r["src_zone"] or "") or r["isp"]):
        return True
    if INTERNET_ZONE.search(r["src_zone"] or "") or r["isp"]:
        return True
    anyv, nets = endpoints(r["src"])
    if anyv:
        return True
    return any(n.num_addresses == 1 and is_public(str(n.network_address)) for n in nets)


def active(r, now):
    return not r["valid_till"] or r["valid_till"] >= now


def build(parsed, mapping):
    for k in ("rule_id", "src", "dst"):
        if not mapping.get(k):
            raise ValueError("Map Rule ID, Source IP / Subnet and Destination IP / Subnet")
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    out, warnings, bad, seen = [], [], 0, set()
    for n, r in enumerate(parsed["rows"], start=1):
        v = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        if not v["src"] and not v["dst"]:
            continue
        if not endpoints(v["dst"])[1] and not v["dst_nat"]:
            bad += 1
            continue
        v["rule_id"] = v["rule_id"] or f"row-{n}"
        if v["rule_id"] in seen:
            v["rule_id"] = f"{v['rule_id']}#{n}"
        seen.add(v["rule_id"])
        v["dst_nat"] = ", ".join(db.all_ips(v["dst_nat"])) or v["dst_nat"]
        v["valid_till"] = (db.parse_ts(v["valid_till"]) or v["valid_till"])[:10]
        v["protocol"] = v["protocol"].lower()
        v["inbound_internet"] = 1 if is_inbound_internet(v) else 0
        out.append(v)
    if bad:
        warnings.append(f"{bad} rows skipped: destination is not an IP, CIDR or range")
    return out, warnings


def load_rules(c, only_active=True):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rows = db.rows(c, "SELECT * FROM comm_rules")
    return [r for r in rows if not only_active or active(r, now)]


def flows_for(c, ips):
    """Rules where any of the IPs is a source or destination (Asset 360)."""
    addrs = []
    for ip in ips:
        try:
            addrs.append(ipaddress.ip_address(ip))
        except ValueError:
            pass
    out = []
    for r in load_rules(c, only_active=False):
        s_any, s_nets = endpoints(r["src"])
        _, d_nets = endpoints(r["dst"])
        d_nat = set(db.all_ips(r["dst_nat"]))
        as_dst = any(a in n for a in addrs for n in d_nets if a.version == n.version) or bool(d_nat & set(ips))
        as_src = any(a in n for a in addrs for n in s_nets if a.version == n.version)
        if as_dst or as_src:
            out.append({**r, "role": "Destination" if as_dst else "Source"})
    return out[:500]


# ------------------------------------------------------------------ routes
def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    rows, warnings = build(parsed, mapping)
    if not rows:
        raise ValueError("No usable rules found with this mapping")
    return parsed, mapping, rows, warnings


@router.post("/api/comm/parse")
def comm_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:6], "mapping": suggest_mapping(parsed["headers"]),
            "fields": [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]}


@router.post("/api/comm/preview")
def comm_preview(data: dict = Body(...)):
    _, _, rows, warnings = _load(data)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        cur = c.execute("SELECT COUNT(*) FROM comm_rules").fetchone()[0]
    inbound = [r for r in rows if r["inbound_internet"] and active(r, now)]
    return {"stats": [["Rules in file", len(rows), ""], ["Inbound from internet", len(inbound), "crit"],
                      ["With a public / NAT IP", sum(1 for r in rows if r["dst_nat"]), "info"],
                      ["Expired (ignored)", sum(1 for r in rows if not active(r, now)), "warn"], ["Current rules replaced", cur, ""]],
            "warnings": warnings, "note": "The file replaces the current communication matrix.",
            "sample_cols": [["rule_id", "Rule"], ["direction", "Direction"], ["src", "Source"], ["dst_nat", "Public / NAT IP"],
                            ["dst", "Destination"], ["ports", "Ports"], ["firewall", "Firewall"]],
            "sample": (inbound + [r for r in rows if not r["inbound_internet"]])[:50]}


@router.post("/api/comm/commit")
def comm_commit(data: dict = Body(...)):
    parsed, mapping, rows, warnings = _load(data)
    cols = KEYS + ["inbound_internet"]
    with db.get_conn() as c:
        cur = c.execute("SELECT COUNT(*) FROM comm_rules").fetchone()[0]
        uid = c.execute("""INSERT INTO comm_uploads(filename, note, uploaded_by, uploaded_at, rows, replaced, mapping, warnings)
                           VALUES (?,?,?,?,?,?,?,?)""", (parsed["filename"], data.get("note", ""), data.get("uploaded_by", ""), db.now_iso(),
                                                        len(rows), cur, json.dumps(mapping), json.dumps(warnings))).lastrowid
        c.execute("DELETE FROM comm_rules")
        c.executemany(f"INSERT INTO comm_rules({', '.join(cols)}, upload_id) VALUES ({','.join('?' * (len(cols) + 1))})",
                      [(*[r[k] for k in cols], uid) for r in rows])
        inventory.refresh_matches(c)  # re-join: exposure from inbound rules
        exposed = c.execute("SELECT COUNT(*) FROM asset_registry WHERE exposure_src LIKE '%,matrix,%'").fetchone()[0]
    return {"message": f"{len(rows)} rules loaded · {exposed} assets internet-exposed through the matrix", "rows": len(rows)}


def _query(p):
    w, params = [], []
    if p.get("inbound") == "1":
        w.append("inbound_internet=1")
    if p.get("firewall"):
        w.append("firewall=?")
        params.append(p["firewall"])
    if p.get("direction"):
        w.append("direction LIKE ?")
        params.append(p["direction"] + "%")
    q = (p.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        w.append("(rule_id LIKE ? OR src LIKE ? OR dst LIKE ? OR dst_nat LIKE ? OR src_nat LIKE ? OR firewall LIKE ? OR fw_rule LIKE ? OR service LIKE ? OR ports LIKE ? OR cr LIKE ?)")
        params += [like] * 10
    return ("WHERE " + " AND ".join(w)) if w else "", params


@router.get("/api/comm/rules")
def comm_rules(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params = _query(p)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM comm_rules {where}", params).fetchone()[0]
        rows = db.rows(c, f"SELECT * FROM comm_rules {where} ORDER BY inbound_internet DESC, rule_id LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    for r in rows:
        r["active"] = active(r, now)
    return {"total": total, "rows": rows}


@router.get("/api/comm/rules/export")
def comm_export(request: Request):
    where, params = _query(dict(request.query_params))
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT * FROM comm_rules {where} ORDER BY inbound_internet DESC, rule_id", params)
    for r in rows:
        r["inbound_text"] = "Yes" if r["inbound_internet"] else "No"
    return xlsx_response([("Communication matrix", [(k, l) for k, l, _ in FIELDS] + [("inbound_text", "Inbound From Internet")], rows)],
                         "communication_matrix")


@router.get("/api/comm/summary")
def comm_summary():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with db.get_conn() as c:
        rows = load_rules(c, only_active=False)
        exposed = c.execute("SELECT COUNT(*) FROM asset_registry WHERE exposure_src LIKE '%,matrix,%'").fetchone()[0]
        last = db.one(c, "SELECT * FROM comm_uploads ORDER BY id DESC LIMIT 1")
    act = [r for r in rows if active(r, now)]
    return {"rules": len(rows), "active": len(act), "expired": len(rows) - len(act),
            "inbound": sum(1 for r in act if r["inbound_internet"]), "exposed_assets": exposed,
            "firewalls": sorted({r["firewall"] for r in rows if r["firewall"]}), "last_upload": last}


@router.delete("/api/comm")
def comm_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM comm_rules")
        inventory.refresh_matches(c)
    return {"ok": True}


@router.get("/api/comm/uploads")
def comm_uploads():
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT id, filename, note, uploaded_by, uploaded_at, rows, replaced FROM comm_uploads ORDER BY id DESC")}
