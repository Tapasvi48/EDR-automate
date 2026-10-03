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

from fastapi import APIRouter, Body, HTTPException, Request

from . import db, inventory
from .addrparse import parse_addresses, ports_allow
from .exporter import xlsx_response

router = APIRouter()

FIELDS = [("rule_id", "Rule ID / S.No", False), ("name", "Name / Service name", False), ("direction", "Direction", False),
          ("src_zone", "Source Zone", False), ("src", "Source IP / Address", False), ("src_nat", "Source NAT IP", False),
          ("isp", "ISP / Link", False), ("firewall", "Firewall", False), ("fw_rule", "Firewall Rule Name", False),
          ("dst_zone", "Destination Zone", False), ("dst_nat", "Public / Destination NAT IP", False), ("dst", "Destination / Private IP", False),
          ("protocol", "Protocol", False), ("ports", "Port(s) / Service", False), ("service", "Service details / Use", False),
          ("application", "Application", False), ("app_owner", "Application owner", False), ("action", "Action", False),
          ("cr", "Change / CR / SOD No.", False), ("valid_till", "Valid Till", False), ("lob", "LOB", False), ("domain", "Domain", False),
          ("msp", "MS Partner", False), ("location", "Location", False), ("remarks", "Remarks", False)]
KEYS = [k for k, _, _ in FIELDS]
ALIASES = {
    "rule_id": ["ruleid", "rule", "flowid", "id", "ruleno", "sno", "slno", "srno", "serialno"],
    "name": ["name", "servicename", "rulename2", "objectname", "flowname"],
    "direction": ["direction", "flowdirection", "traffictype"],
    "src_zone": ["sourcezone", "srczone", "fromzone"],
    "src": ["sourceipsubnet", "sourceip", "sourceaddress", "srcip", "srcaddress", "source", "sourcesubnet", "src"],
    "src_nat": ["sourcenatip", "srcnat", "snat", "sourcenat", "natip"],
    "isp": ["isplink", "isp", "link", "carrier"],
    "firewall": ["firewall", "fw", "fwl", "firewallname", "device", "whichfirewalldetailsexposedtothisip", "firewalldetails", "whichfirewall"],
    "fw_rule": ["firewallrulename", "rulename", "policyname", "policy"],
    "dst_zone": ["destinationzone", "dstzone", "tozone"],
    "dst_nat": ["destinationnatippublic", "destinationnatip", "destnatip", "dstnat", "dnat", "publicip", "publicippool", "publicips", "vip", "natpublicip"],
    "dst": ["destinationipsubnet", "destinationip", "destinationaddress", "dstip", "dstaddress", "destination", "destinationsubnet", "dst",
            "privateip", "internalip", "private", "internal"],
    "protocol": ["protocol", "proto"],
    "ports": ["ports", "port", "dstport", "destinationport", "serviceport", "service"],
    "service": ["servicedetails", "use", "usage", "purpose", "applicationservice"],
    "application": ["application", "applicaiton", "applicaton", "app", "appname", "applicationname"],
    "app_owner": ["applicationowner", "applicatonowner", "applicaitonowner", "appowner", "serviceowner", "owner", "sourcecontactdetails", "contact"],
    "action": ["action", "permit"],
    "cr": ["changecrno", "crno", "cr", "change", "approval", "soddetails", "sod", "sodno"],
    "valid_till": ["validtill", "validuntil", "expiry", "expirydate"],
    "lob": ["lob", "lineofbusiness"], "domain": ["domain"], "msp": ["mspartner", "msp", "partner", "mspname"],
    "location": ["location", "site", "dc"],
    "remarks": ["remarks", "remark", "comments", "notes", "hoststatus", "planner"],
}
# Sheet types: what one sheet of a matrix workbook holds, which fields it needs, and whether its rows mean internet exposure
SHEET_TYPES = {
    "rules": {"label": "Firewall rules (source → destination)", "need": [["src", "dst", "dst_nat"]],
              "hint": "Name · Source Zone · Source Address · Destination Zone · Destination Address · Service / Port · Application owner"},
    "public_pool": {"label": "Public IP pool", "need": [["dst_nat"]],
                    "hint": "S.No · Public IP pool · Use · Application · Application owner"},
    "nat_map": {"label": "Public ↔ private IP (NAT)", "need": [["dst_nat"], ["dst"]],
                "hint": "S.No · Public IP · Private IP · Application · Application owner · Which firewall exposes it"},
    "sod_nat": {"label": "SOD / NAT rules", "need": [["dst", "dst_nat"]],
                "hint": "SOD details · dest_nat_ip · destination_ip · fwl · location · nat_ip · port · protocol · rule · source_ip"},
    "exposure": {"label": "Internet exposure register", "need": [["dst_nat", "dst"]],
                 "hint": "Public IP · Internal IP · Port · Service details · Destination IP · LOB · Domain · MS Partner · Service owner · Firewall"},
}
# per sheet type, aliases that win over the generic ones (e.g. "Destination IP" on a register is a second internal address)
TYPE_ALIASES = {
    "nat_map": {"dst_nat": ["publicip", "publicippool", "public"], "dst": ["privateip", "private", "internalip"]},
    "exposure": {"dst_nat": ["publicip"], "dst": ["internalip", "privateip"], "src": ["destinationip"]},
    "sod_nat": {"dst_nat": ["destnatip"], "src_nat": ["natip"], "dst": ["destinationip"], "src": ["sourceip"]},
    "public_pool": {"dst_nat": ["publicippool", "publicip", "publicips", "pool"]},
}


def guess_type(headers):
    n = {_norm(h) for h in headers}
    if n & {"soddetails", "destnatip", "fwl"}:
        return "sod_nat"
    if "publicippool" in n or ("pool" in " ".join(n) and not n & {"privateip", "internalip"}):
        return "public_pool"
    if n & {"internalip"} and n & {"publicip"} and n & {"hoststatus", "servicedetails", "lob", "mspartner", "planner"}:
        return "exposure"
    if n & {"publicip"} and n & {"privateip", "internalip"}:
        return "nat_map"
    return "rules"


INTERNET_ZONE = re.compile(r"internet|isp|untrust|outside|external|public|wan", re.I)
ANY = re.compile(r"^(any|all|\*|0\.0\.0\.0/0|::/0|internet)$", re.I)


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def suggest_mapping(headers, stype="rules"):
    from .filetemplates import custom_aliases
    custom = custom_aliases("comm_matrix")
    mapping, used = {}, set()
    norm = {h: _norm(h) for h in headers}
    over = TYPE_ALIASES.get(stype, {})
    order = [k for k in over] + [k for k in KEYS if k not in over]
    for f in order:
        for alias in [*(_norm(n) for n in custom.get(f, [])), *over.get(f, []), *ALIASES[f]]:
            hit = next((h for h in headers if h not in used and norm[h] == _norm(alias)), None)
            if hit:
                mapping[f] = hit
                used.add(hit)
                break
    return mapping


def endpoints(text):
    """'10.1.1.1, 10.2.0.0/16, Any' -> (is_any, [ip_network]). Every notation of addrparse.parse_addresses."""
    anyv, nets, _ = parse_addresses(text)
    return anyv, list(nets)


def endpoint_names(text):
    return list(parse_addresses(text)[2])


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


def build(parsed, mapping, stype="rules", workbook="", sheet=""):
    st = SHEET_TYPES.get(stype) or SHEET_TYPES["rules"]
    for group in st["need"]:
        if not any(mapping.get(k) for k in group):
            raise ValueError(f"{st['label']}: map " + " or ".join(dict((a, b) for a, b, _ in FIELDS)[k] for k in group))
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    out, warnings, bad, seen = [], [], 0, set()
    tag = (sheet or "")[:12]
    for n, r in enumerate(parsed["rows"], start=1):
        v = {k: (r[idx[mapping[k]]] if mapping.get(k) in idx else "").strip() for k in KEYS}
        d_any, d_nets, d_names = parse_addresses(v["dst"])
        p_any, p_nets, _ = parse_addresses(v["dst_nat"])
        s_any, s_nets, s_names = parse_addresses(v["src"])
        if not (d_any or d_nets or d_names or p_nets or s_nets or s_names or s_any):
            bad += 1
            continue
        rid = v["rule_id"] or f"row-{n}"
        if stype != "rules" or rid in seen:
            rid = f"{tag}:{rid}" if stype != "rules" and tag else rid
        if rid in seen:
            rid = f"{rid}#{n}"
        seen.add(rid)
        v["rule_id"] = rid
        v["dst_nat"] = ", ".join(str(x.network_address) if x.num_addresses == 1 else str(x) for x in p_nets) or v["dst_nat"]
        v["valid_till"] = (db.parse_ts(v["valid_till"]) or v["valid_till"])[:10]
        v["protocol"] = v["protocol"].lower()
        if stype == "rules":
            v["inbound_internet"] = 1 if is_inbound_internet(v) else 0
        else:  # NAT / pool / register sheets: a public IP (or a public internal address) means reachable from the internet
            from .registry import is_public
            pub = any(is_public(str(x.network_address)) for x in p_nets) or any(is_public(str(x.network_address)) for x in d_nets)
            v["inbound_internet"] = 1 if pub else 0
            v["direction"] = v["direction"] or ("Inbound" if pub else "")
            v["src_zone"] = v["src_zone"] or ("Internet" if pub and not v["src"] else v["src_zone"])
        v["workbook"], v["sheet"], v["sheet_type"] = workbook, sheet, stype
        out.append(v)
    if bad:
        warnings.append(f"{sheet or 'sheet'}: {bad} rows skipped (no IP, subnet or host name in the address columns)")
    return out, warnings


def load_rules(c, only_active=True):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rows = db.rows(c, "SELECT * FROM comm_rules")
    return [r for r in rows if not only_active or active(r, now)]


class RuleIndex:
    """Every matrix rule's source / destination networks, indexed by (IP version, prefix length, network), so finding the
    rules of an IP costs a few dictionary look-ups instead of parsing and scanning every rule (Asset 360, shadow exposure
    over thousands of public IPs)."""

    def __init__(self, rules):
        self.rules = rules
        self.nets = {"src": {}, "dst": {}}
        self.nat = {}
        for i, r in enumerate(rules):
            for side, text in (("src", r["src"]), ("dst", r["dst"])):
                for n in endpoints(text)[1]:
                    self.nets[side].setdefault((n.version, n.prefixlen), {}).setdefault(int(n.network_address), set()).add(i)
            for ip in db.all_ips(r["dst_nat"]):
                self.nat.setdefault(ip, set()).add(i)

    def _hits(self, side, addrs):
        out = set()
        for (v, plen), m in self.nets[side].items():
            bits = 32 if v == 4 else 128
            for a in addrs:
                if a.version == v:
                    out |= m.get((int(a) >> (bits - plen)) << (bits - plen), set())
        return out

    def match(self, ips):
        addrs = []
        for ip in ips:
            try:
                addrs.append(ipaddress.ip_address(ip))
            except ValueError:
                pass
        dst = self._hits("dst", addrs)
        for ip in ips:
            dst |= self.nat.get(ip, set())
        src = self._hits("src", addrs)
        return [{**self.rules[i], "role": "Destination" if i in dst else "Source"} for i in sorted(dst | src)]


_RIDX = {"gen": None, "idx": None}


def rule_index(c):
    """The RuleIndex of the current matrix, rebuilt only after the data changed."""
    g = db.GEN[0]
    if _RIDX["gen"] != g:
        _RIDX["idx"], _RIDX["gen"] = RuleIndex(load_rules(c, only_active=False)), g
    return _RIDX["idx"]


def flows_for(c, ips):
    """Rules where any of the IPs is a source or destination (Asset 360)."""
    return rule_index(c).match(list(ips))[:500]


def rule_allows(rule, port, proto):
    """Does this rule allow port / protocol (tcp / udp)? Ports as in addrparse.parse_ports (443, tcp/443, dns_tcp, https, any…)."""
    rp = str(rule.get("protocol") or "").strip().lower()
    if rp not in ("", "any", "ip", "all", "tcp/udp") and proto and rp != proto.lower():
        return False
    return ports_allow(rule.get("ports"), port, proto)


def shadow_ports(c, public_ip, extra_ips=()):
    """Ports the VA scan found open on a public IP, each with the inbound Internet / ISP rules that allow it.
    A port no rule allows is shadow exposure: reachable from the internet with no documented firewall rule."""
    rules = [r for r in flows_for(c, [public_ip, *extra_ips]) if r.get("inbound_internet")]
    ports = {}
    for f in c.execute("""SELECT port, protocol, sev_rank, status, name FROM vuln_findings WHERE ip=? AND COALESCE(port,'') NOT IN ('', '0')""",
                       (public_ip,)):
        k = (str(f["port"]), (f["protocol"] or "").lower())
        p = ports.setdefault(k, {"ip": public_ip, "port": k[0], "protocol": k[1], "findings": 0, "open": 0, "max_rank": -1, "names": []})
        p["findings"] += 1
        if f["status"] == "open":
            p["open"] += 1
            p["max_rank"] = max(p["max_rank"], f["sev_rank"] or 0)
            if len(p["names"]) < 3 and (f["sev_rank"] or 0) >= 1:
                p["names"].append(f["name"])
    out = []
    for p in sorted(ports.values(), key=lambda x: int(x["port"]) if x["port"].isdigit() else 0):
        p["rules"] = [r["rule_id"] for r in rules if rule_allows(r, p["port"], p["protocol"])]
        p["shadow"] = not p["rules"]
        out.append(p)
    return out, [r["rule_id"] for r in rules]


# ------------------------------------------------------------------ routes
ROW_COLS = KEYS + ["inbound_internet", "workbook", "sheet", "sheet_type", "inbound_auto"]


def apply_overrides(c):
    """Manual internet-facing marks win over the computed value (they survive re-uploads of the same workbook / sheet / row)."""
    c.execute("UPDATE comm_rules SET inbound_auto=inbound_internet WHERE inbound_auto IS NULL")
    c.execute("""UPDATE comm_rules SET inbound_internet=COALESCE((SELECT o.inbound FROM comm_overrides o WHERE o.workbook=COALESCE(comm_rules.workbook,'')
                 AND o.sheet=COALESCE(comm_rules.sheet,'') AND o.rule_id=comm_rules.rule_id), inbound_auto)""")


def _load(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    mapping = {k: v for k, v in (data.get("mapping") or {}).items() if v}
    rows, warnings = build(parsed, mapping, data.get("type") or "rules", parsed["filename"], parsed["sheet"])
    if not rows:
        raise ValueError("No usable rows found with this mapping")
    return parsed, mapping, rows, warnings


def _sheet_info(token, sheet=None, header_row=None, stype=None):
    parsed = inventory.parse_upload(token, sheet, header_row)
    t = stype or guess_type(parsed["headers"])
    return {"sheet": parsed["sheet"], "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:5], "type": t, "mapping": suggest_mapping(parsed["headers"], t), "filename": parsed["filename"],
            "sheets": parsed["sheets"]}


def _fields():
    return [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]


def _types():
    return [{"id": k, "label": v["label"], "hint": v["hint"], "need": v["need"]} for k, v in SHEET_TYPES.items()]


@router.post("/api/comm/parse")
def comm_parse(data: dict = Body(...)):
    info = _sheet_info(data["token"], data.get("sheet"), data.get("header_row"), data.get("type"))
    return {"token": data["token"], **info, "fields": _fields(), "types": _types()}


@router.post("/api/comm/workbook")
def comm_workbook(data: dict = Body(...)):
    """Every sheet of an uploaded workbook: its guessed type, header row and column mapping (all editable)."""
    first = inventory.parse_upload(data["token"])
    sheets = []
    for name in first["sheets"]:
        try:
            info = _sheet_info(data["token"], name)
        except Exception as e:  # noqa: BLE001 - an empty or odd sheet should not stop the others
            sheets.append({"sheet": name, "error": str(e), "include": False})
            continue
        info.pop("sheets", None)
        info["include"] = info["row_count"] > 0
        sheets.append(info)
    return {"token": data["token"], "filename": first["filename"], "sheets": sheets, "fields": _fields(), "types": _types()}


@router.post("/api/comm/workbook/sheet")
def comm_workbook_sheet(data: dict = Body(...)):
    """Re-read one sheet after a header row or type change."""
    info = _sheet_info(data["token"], data["sheet"], data.get("header_row"), data.get("type"))
    info.pop("sheets", None)
    info["include"] = True
    if data.get("keep_mapping") and data.get("mapping"):
        info["mapping"] = data["mapping"]
    return info


def _workbook_rows(data):
    rows, warnings, per = [], [], []
    for sh in data.get("sheets") or []:
        if not sh.get("include"):
            continue
        parsed = inventory.parse_upload(data["token"], sh["sheet"], sh.get("header_row"))
        mapping = {k: v for k, v in (sh.get("mapping") or {}).items() if v}
        try:
            got, w = build(parsed, mapping, sh.get("type") or "rules", parsed["filename"], parsed["sheet"])
        except ValueError as e:
            raise HTTPException(400, f"Sheet '{sh['sheet']}': {e}")
        rows += got
        warnings += w
        per.append({"sheet": sh["sheet"], "type": sh.get("type") or "rules", "rows": len(got), "inbound": sum(1 for r in got if r["inbound_internet"])})
    if not rows:
        raise HTTPException(400, "No usable rows in the selected sheets")
    return rows, warnings, per


@router.post("/api/comm/workbook/preview")
def comm_workbook_preview(data: dict = Body(...)):
    rows, warnings, per = _workbook_rows(data)
    fname = inventory.parse_upload(data["token"])["filename"]
    with db.get_conn() as c:
        same = c.execute("SELECT COUNT(*) FROM comm_rules WHERE workbook=?", (fname,)).fetchone()[0]
        cur = c.execute("SELECT COUNT(*) FROM comm_rules").fetchone()[0]
    ips = sum(len(parse_addresses(r[k])[1]) for r in rows for k in ("src", "dst", "dst_nat", "src_nat"))
    return {"per_sheet": per, "warnings": warnings[:30], "rows": len(rows), "inbound": sum(1 for r in rows if r["inbound_internet"]),
            "addresses": ips, "replaces_workbook": same, "current": cur,
            "sample": [{k: r[k] for k in ("sheet", "rule_id", "name", "src", "dst_nat", "dst", "ports", "application", "app_owner", "inbound_internet")} for r in rows[:40]]}


@router.post("/api/comm/workbook/commit")
def comm_workbook_commit(data: dict = Body(...)):
    rows, warnings, per = _workbook_rows(data)
    fname = inventory.parse_upload(data["token"])["filename"]
    return _store(rows, fname, data, warnings, per, replace_all=data.get("mode") == "all")


def _store(rows, fname, data, warnings, per, replace_all):
    with db.get_conn() as c:
        cur = c.execute("SELECT COUNT(*) FROM comm_rules" + ("" if replace_all else " WHERE workbook=? OR workbook IS NULL"),
                        () if replace_all else (fname,)).fetchone()[0]
        uid = c.execute("""INSERT INTO comm_uploads(filename, note, uploaded_by, uploaded_at, rows, replaced, mapping, warnings, sheets)
                           VALUES (?,?,?,?,?,?,?,?,?)""", (fname, data.get("note", ""), data.get("uploaded_by", ""), db.now_iso(), len(rows), cur,
                                                          json.dumps({s.get("sheet"): s.get("mapping") for s in data.get("sheets") or []} or data.get("mapping") or {}),
                                                          json.dumps(warnings[:50]), json.dumps(per))).lastrowid
        if replace_all:
            c.execute("DELETE FROM comm_rules")
        else:  # replace this workbook's rows (and rows of uploads made before workbooks were tracked)
            c.execute("DELETE FROM comm_rules WHERE workbook=? OR workbook IS NULL", (fname,))
        c.executemany(f"INSERT INTO comm_rules({', '.join(ROW_COLS)}, upload_id) VALUES ({','.join('?' * (len(ROW_COLS) + 1))})",
                      [(*[r.get(k) if k != "inbound_auto" else r["inbound_internet"] for k in ROW_COLS], uid) for r in rows])
        apply_overrides(c)
        if inventory.refresh_soon(c, label="Recalculating internet exposure from the matrix"):  # re-join: exposure from the matrix
            exposed = c.execute("SELECT COUNT(*) FROM asset_registry WHERE exposure_src LIKE '%,matrix,%'").fetchone()[0]
            done = f"{exposed:,} assets internet-exposed through the matrix"
        else:
            done = "internet exposure is being recalculated in the background"
    return {"message": f"{len(rows):,} rows from {len(per) or 1} sheet(s) loaded · {done}",
            "rows": len(rows), "per_sheet": per}


@router.post("/api/comm/preview")
def comm_preview(data: dict = Body(...)):
    try:
        _, _, rows, warnings = _load(data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    inbound = [r for r in rows if r["inbound_internet"] and active(r, now)]
    return {"stats": [["Rows in sheet", len(rows), ""], ["Internet-facing", len(inbound), "crit"],
                      ["With a public / NAT IP", sum(1 for r in rows if r["dst_nat"]), "info"],
                      ["Expired (ignored)", sum(1 for r in rows if not active(r, now)), "warn"]],
            "warnings": warnings, "note": "The rows replace earlier rows of the same workbook.",
            "sample_cols": [["rule_id", "Rule"], ["src", "Source"], ["dst_nat", "Public / NAT IP"], ["dst", "Destination"], ["ports", "Ports"], ["app_owner", "Owner"]],
            "sample": (inbound + [r for r in rows if not r["inbound_internet"]])[:50]}


@router.post("/api/comm/commit")
def comm_commit(data: dict = Body(...)):
    try:
        parsed, _, rows, warnings = _load(data)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _store(rows, parsed["filename"], data, warnings, [{"sheet": parsed["sheet"], "type": data.get("type") or "rules", "rows": len(rows)}], False)


def _query(p):
    w, params = [], []
    if p.get("inbound") in ("0", "1"):
        w.append("inbound_internet=?")
        params.append(int(p["inbound"]))
    if p.get("sheet"):
        w.append("sheet=?")
        params.append(p["sheet"])
    if p.get("manual") == "1":
        w.append("inbound_auto IS NOT NULL AND inbound_internet<>inbound_auto")
    if p.get("firewall"):
        w.append("firewall=?")
        params.append(p["firewall"])
    if p.get("direction"):
        w.append("direction LIKE ?")
        params.append(p["direction"] + "%")
    q = (p.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        w.append("""(rule_id LIKE ? OR src LIKE ? OR dst LIKE ? OR dst_nat LIKE ? OR src_nat LIKE ? OR firewall LIKE ? OR fw_rule LIKE ? OR service LIKE ?
                  OR ports LIKE ? OR cr LIKE ? OR name LIKE ? OR application LIKE ? OR app_owner LIKE ?)""")
        params += [like] * 13
    if p.get("sheet_type"):
        w.append("sheet_type=?")
        params.append(p["sheet_type"])
    if p.get("workbook"):
        w.append("workbook=?")
        params.append(p["workbook"])
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
        for col in ("src", "dst", "dst_nat", "src_nat"):
            r[col + "_list"] = split_display(r[col])
        r["port_list"] = port_display(r["ports"], r["protocol"])
        r["manual"] = r.get("inbound_auto") is not None and r["inbound_internet"] != r["inbound_auto"]
    return {"total": total, "rows": rows}


def split_display(text, cap=40):
    """One cell -> the separate addresses for display: IPs (small ranges / shorthand expanded), subnets, names, Any."""
    anyv, nets, names = parse_addresses(text)
    out = ["Any"] if anyv else []
    for n in nets:
        if n.num_addresses == 1:
            out.append(str(n.network_address))
        elif n.version == 4 and n.num_addresses <= 16 and str(n) not in str(text):  # a range / shorthand: one chip per IP
            out += [str(a) for a in n]
        else:
            out.append(str(n))
    out += list(names)
    if len(out) > cap:
        out = out[:cap] + [f"+{len(out) - cap} more"]
    return out


def port_display(ports, protocol=""):
    from .addrparse import parse_ports
    t = parse_ports(ports)
    if t is None:
        return ["any"]
    proto = (protocol or "").lower()
    out = []
    for lo, hi, p in t:
        pp = p or (proto if proto in ("tcp", "udp", "sctp") else "")
        out.append(f"{pp + '/' if pp else ''}{lo}{'-' + str(hi) if hi != lo else ''}")
    return list(dict.fromkeys(out)) or ([ports] if ports else ["any"])


@router.get("/api/comm/rules/export")
def comm_export(request: Request):
    where, params = _query(dict(request.query_params))
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT * FROM comm_rules {where} ORDER BY inbound_internet DESC, rule_id", params)
    for r in rows:
        r["inbound_text"] = "Yes" if r["inbound_internet"] else "No"
    return xlsx_response([("Communication matrix", [("workbook", "Workbook"), ("sheet", "Sheet"), ("sheet_type", "Sheet type")] + [(k, l) for k, l, _ in FIELDS]
                           + [("inbound_text", "Inbound From Internet")], rows)],
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
            "firewalls": sorted({r["firewall"] for r in rows if r["firewall"]}), "last_upload": last,
            "workbooks": sorted({(r.get("workbook") or "", r.get("sheet") or "", r.get("sheet_type") or "rules") for r in rows}),
            "sheet_types": {k: v["label"] for k, v in SHEET_TYPES.items()},
            "manual": sum(1 for r in rows if r.get("inbound_auto") is not None and r["inbound_internet"] != r["inbound_auto"])}


@router.delete("/api/comm")
def comm_clear():
    with db.get_conn() as c:
        c.execute("DELETE FROM comm_rules")
        inventory.refresh_soon(c)
    return {"ok": True}


@router.get("/api/comm/uploads")
def comm_uploads():
    with db.get_conn() as c:
        return {"rows": db.rows(c, "SELECT id, filename, note, uploaded_by, uploaded_at, rows, replaced FROM comm_uploads ORDER BY id DESC")}


# ------------------------------------------------------------------ matrix IP register: every address in the matrix
"""How each address in the matrix is classified (shown on the page too):
  ours      private / CGNAT / IPv6 ULA address; or a public IP the matrix lists as a public / NAT / pool IP, or as the
            destination of an inbound rule (we only allow traffic in to our own addresses); or a public IP
            in an inventory, VA scan or NIAM; or a host name that matches an inventory / CrowdStrike host
  roles     exposed      destination (or public / NAT IP) of an internet-facing row: inbound rule from Internet / ISP /
                         untrust / any, a NAT / pool / exposure-register sheet
            public       listed as a public / destination-NAT / pool IP
            public_src   source NAT IP (the public address our traffic leaves from)
            snat         source of a row with a source NAT IP: leaves through that public IP -> internet exposed
            outbound     source of a rule whose destination is the internet (any / internet zone / a public IP not ours)
            internet_src source of an inbound internet rule (a partner or 'any'; ours only if it is one of our public IPs)
            internal     only in internal flows"""
_IPS_CACHE = {}


def _is_private(net):
    from .registry import is_public
    return not is_public(str(net.network_address))


def matrix_ips(c):
    key = (c.execute("SELECT COUNT(*), MAX(id) FROM comm_rules").fetchone()[:], c.execute("SELECT COUNT(*) FROM asset_registry").fetchone()[0])
    if _IPS_CACHE.get("key") == key:
        return _IPS_CACHE["rows"]
    from .registry import is_public
    import bisect
    reg = {r["ip"]: r for r in db.rows(c, """SELECT ip, name, lobs, in_inventory, in_edr, in_scan, in_niam, edr_status, exposed, nat_of
                                              FROM asset_registry WHERE ip IS NOT NULL""")}
    names = {}
    for ip, r in reg.items():
        for n in (r["name"] or "").split(", "):
            if n:
                names.setdefault(db.norm_hostname(n), []).append(ip)
    v4 = sorted((int(ipaddress.ip_address(ip)), ip) for ip in reg if ":" not in ip)
    v4n = [n for n, _ in v4]
    rules = load_rules(c)
    our_public = set()
    for r in rules:
        for col in ("dst_nat", "src_nat"):
            our_public |= {str(n.network_address) for n in parse_addresses(r[col])[1] if n.num_addresses == 1}
    ent = {}

    def add(addr_key, kind, role, r, net=None):
        e = ent.setdefault(addr_key, {"address": addr_key, "kind": kind, "net": net, "roles": set(), "rules": set(), "sheets": set(),
                                      "apps": set(), "owners": set(), "ports": set()})
        e["roles"].add(role)
        e["rules"].add(r["rule_id"])
        if r.get("sheet"):
            e["sheets"].add(f"{r.get('workbook') or ''} › {r['sheet']}".strip(" ›"))
        for fld, tgt in (("application", "apps"), ("app_owner", "owners"), ("ports", "ports")):
            if r.get(fld):
                e[tgt].add(str(r[fld])[:60])

    for r in rules:
        d_any, d_nets, _ = parse_addresses(r["dst"])
        to_internet = d_any or bool(INTERNET_ZONE.search(r["dst_zone"] or "")) or any(
            not _is_private(n) and str(n.network_address) not in our_public for n in d_nets)
        for col in ("src", "dst", "dst_nat", "src_nat"):
            anyv, nets, nms = parse_addresses(r[col])
            if col == "dst":
                role = "exposed" if r["inbound_internet"] else "internal"
            elif col == "dst_nat":
                role = "public"
            elif col == "src_nat":
                role = "public_src"
            else:
                role = ("internet_src" if r["inbound_internet"] else "snat" if parse_addresses(r["src_nat"])[1]
                        else "outbound" if to_internet else "internal")
            for n0 in nets:
                # small ranges / subnets (up to 64 addresses) are listed IP by IP, so each can be matched to inventory
                parts = [ipaddress.ip_network(a) for a in n0] if n0.version == 4 and 1 < n0.num_addresses <= 64 else [n0]
                for n in parts:
                    k = str(n.network_address) if n.num_addresses == 1 else str(n)
                    add(k, "ip" if n.num_addresses == 1 else "subnet", role, r, n)
                    if col == "dst_nat" and r["inbound_internet"]:
                        ent[k]["roles"].add("exposed")
            for nm in nms:
                add("name:" + nm, "name", role, r)
    out = []
    for k, e in ent.items():
        n = e["net"]
        why, ours = "", False
        m = {"lobs": None, "name": None, "in_inventory": 0, "in_edr": 0, "edr_status": None, "assets": 0}
        if e["kind"] == "name":
            ips = names.get(db.norm_hostname(k[5:]), [])
            if ips:
                rr = reg[ips[0]]
                ours, why = True, "host name matches an inventory / CrowdStrike host"
                m.update(lobs=rr["lobs"], name=rr["name"], in_inventory=rr["in_inventory"], in_edr=rr["in_edr"], edr_status=rr["edr_status"], assets=len(ips),
                         ip=ips[0])
        else:
            if _is_private(n):
                ours, why = True, "private address"
            elif e["address"] in our_public or "public" in e["roles"] or "public_src" in e["roles"]:
                ours, why = True, "listed as a public / NAT / pool IP in the matrix"
            elif "exposed" in e["roles"]:
                ours, why = True, "destination of an inbound rule in our matrix"
            if n.num_addresses == 1:
                rr = reg.get(e["address"])
                if rr:
                    if not ours and is_public(e["address"]) and (rr["in_inventory"] or rr["in_scan"] or rr["in_niam"]):
                        ours, why = True, "public IP in an inventory / VA scan / NIAM"
                    m.update(lobs=rr["lobs"], name=rr["name"], in_inventory=rr["in_inventory"], in_edr=rr["in_edr"], edr_status=rr["edr_status"], assets=1)
            elif n.version == 4 and n.num_addresses <= 1 << 20:
                lo, hi = int(n.network_address), int(n.broadcast_address)
                inside = [v4[i][1] for i in range(bisect.bisect_left(v4n, lo), bisect.bisect_right(v4n, hi))]
                m.update(assets=len(inside), in_inventory=sum(1 for ip in inside if reg[ip]["in_inventory"]),
                         in_edr=sum(1 for ip in inside if reg[ip]["in_edr"]),
                         lobs=", ".join(sorted({x for ip in inside for x in (reg[ip]["lobs"] or "").split(", ") if x}))[:120] or None)
        roles = e["roles"]
        cat = ("exposed" if ours and roles & {"exposed", "public", "snat", "public_src"} else "outbound" if ours and "outbound" in roles
               else "external" if not ours and e["kind"] != "name" else "unknown" if not ours else "internal")
        out.append({"address": e["address"][5:] if e["kind"] == "name" else e["address"], "kind": e["kind"], "ours": ours, "why": why,
                    "category": cat, "roles": sorted(roles), "rules": len(e["rules"]), "rule_ids": ", ".join(sorted(e["rules"])[:6]),
                    "sheets": ", ".join(sorted(e["sheets"])), "applications": ", ".join(sorted(e["apps"]))[:200],
                    "owners": ", ".join(sorted(e["owners"]))[:200], "ports": ", ".join(sorted(e["ports"]))[:120], **m,
                    "num": int(n.network_address) if n is not None and n.version == 4 else 0})
    out.sort(key=lambda x: ({"exposed": 0, "outbound": 1, "unknown": 2, "internal": 3, "external": 4}[x["category"]], x["kind"] != "ip", x["num"]))
    _IPS_CACHE.update(key=key, rows=out)
    return out


def _ips_filter(p, rows):
    v = p.get("view") or "exposed"
    if v == "exposed":
        rows = [r for r in rows if r["category"] == "exposed"]
    elif v == "outbound":
        rows = [r for r in rows if r["category"] == "outbound" or ("outbound" in r["roles"] and r["ours"])]
    elif v == "public":
        rows = [r for r in rows if {"public", "public_src"} & set(r["roles"])]
    elif v == "not_inventory":
        rows = [r for r in rows if r["ours"] and r["category"] in ("exposed", "outbound") and not r["in_inventory"]]
    elif v == "external":
        rows = [r for r in rows if r["category"] == "external"]
    elif v == "unknown":
        rows = [r for r in rows if r["category"] == "unknown"]
    q = (p.get("q") or "").strip().lower()
    if q:
        rows = [r for r in rows if q in f"{r['address']} {r['name'] or ''} {r['applications']} {r['owners']} {r['sheets']} {r['rule_ids']} {r['lobs'] or ''}".lower()]
    if p.get("kind"):
        rows = [r for r in rows if r["kind"] == p["kind"]]
    return rows


@router.get("/api/comm/ips")
def comm_ips(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    with db.get_conn() as c:
        allr = matrix_ips(c)
    rows = _ips_filter(p, allr)
    cnt = lambda f: sum(1 for r in allr if f(r))  # noqa: E731
    counts = {"exposed": cnt(lambda r: r["category"] == "exposed"), "outbound": cnt(lambda r: r["category"] == "outbound" or ("outbound" in r["roles"] and r["ours"])),
              "public": cnt(lambda r: {"public", "public_src"} & set(r["roles"])),
              "not_inventory": cnt(lambda r: r["ours"] and r["category"] in ("exposed", "outbound") and not r["in_inventory"]),
              "external": cnt(lambda r: r["category"] == "external"), "unknown": cnt(lambda r: r["category"] == "unknown"), "all": len(allr)}
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size], "counts": counts}


IPS_EXPORT = [("address", "Address"), ("kind", "Kind"), ("category", "Category"), ("ours_text", "Ours"), ("why", "Why ours"), ("roles_text", "Roles"),
              ("name", "Matched asset"), ("lobs", "LOB"), ("inv_text", "In inventory"), ("edr_text", "EDR"), ("assets", "Known assets inside"),
              ("applications", "Application"), ("owners", "Owner"), ("ports", "Ports"), ("rules", "Rows"), ("rule_ids", "Rule / row IDs"), ("sheets", "Workbook › sheet")]


@router.get("/api/comm/ips/export")
def comm_ips_export(request: Request):
    with db.get_conn() as c:
        rows = _ips_filter(dict(request.query_params), matrix_ips(c))
    for r in rows:
        r["ours_text"] = "Yes" if r["ours"] else "No"
        r["roles_text"] = ", ".join(r["roles"])
        r["inv_text"] = ("Yes" if r["in_inventory"] else "No") if r["kind"] != "subnet" else f"{r['in_inventory']} of {r['assets']} known"
        r["edr_text"] = r["edr_status"] or (f"{r['in_edr']} with EDR" if r["kind"] == "subnet" else "")
    return xlsx_response([("Matrix IPs", IPS_EXPORT, rows)], "matrix_ip_register")



# ------------------------------------------------------------------ manage: sheets, delete, manual internet-facing marks
@router.get("/api/comm/sheets")
def comm_sheets():
    """Every workbook / sheet loaded, with its type, rows, internet-facing rows, manual marks and upload time."""
    with db.get_conn() as c:
        rows = db.rows(c, """SELECT COALESCE(r.workbook,'') workbook, COALESCE(r.sheet,'') sheet, COALESCE(r.sheet_type,'rules') sheet_type,
            COUNT(*) rows, SUM(r.inbound_internet) inbound, SUM(r.inbound_auto IS NOT NULL AND r.inbound_internet<>r.inbound_auto) manual,
            MAX(u.uploaded_at) uploaded_at, MAX(u.uploaded_by) uploaded_by
            FROM comm_rules r LEFT JOIN comm_uploads u ON u.id=r.upload_id GROUP BY 1, 2, 3 ORDER BY 1, 2""")
    for r in rows:
        r["type_label"] = SHEET_TYPES.get(r["sheet_type"], {}).get("label", r["sheet_type"])
    return {"rows": rows}


@router.delete("/api/comm/sheet")
def comm_delete_sheet(workbook: str = "", sheet: str = ""):
    """Delete one sheet (workbook + sheet) or, with sheet empty, the whole workbook. Exposure is recomputed."""
    with db.get_conn() as c:
        if sheet:
            n = c.execute("DELETE FROM comm_rules WHERE COALESCE(workbook,'')=? AND COALESCE(sheet,'')=?", (workbook, sheet)).rowcount
        else:
            n = c.execute("DELETE FROM comm_rules WHERE COALESCE(workbook,'')=?", (workbook,)).rowcount
        inventory.refresh_soon(c)
    _IPS_CACHE.clear()
    return {"ok": True, "deleted": n, "message": f"{n:,} rows deleted" + (f" (sheet {sheet})" if sheet else f" (workbook {workbook or 'without name'})")}


@router.patch("/api/comm/rules/{rule_pk}")
def comm_mark(rule_pk: int, data: dict = Body(...)):
    """Mark a matrix row internet-facing (1) or not (0), or back to automatic (null). Kept across re-uploads."""
    v = data.get("inbound")
    with db.get_conn() as c:
        r = db.one(c, "SELECT * FROM comm_rules WHERE id=?", (rule_pk,))
        if not r:
            raise HTTPException(404, "Row not found")
        key = (r["workbook"] or "", r["sheet"] or "", r["rule_id"])
        if v is None or v == "" or (r["inbound_auto"] is not None and int(v) == r["inbound_auto"]):
            c.execute("DELETE FROM comm_overrides WHERE workbook=? AND sheet=? AND rule_id=?", key)
        else:
            c.execute("INSERT OR REPLACE INTO comm_overrides VALUES (?,?,?,?,?,?)", (*key, 1 if int(v) else 0, data.get("note") or "", db.now_iso()))
        apply_overrides(c)
        inventory.refresh_soon(c, label="Recalculating internet exposure", registry_only=True)
        r = db.one(c, "SELECT inbound_internet, inbound_auto FROM comm_rules WHERE id=?", (rule_pk,))
    _IPS_CACHE.clear()
    return {"ok": True, "inbound_internet": r["inbound_internet"], "manual": r["inbound_internet"] != r["inbound_auto"]}



# ------------------------------------------------------------------ template workbook: one sheet per sheet type
TEMPLATE_SHEETS = [
    ("Firewall rules", "rules", ["Rule ID", "Name", "Direction", "Source Zone", "Source Address", "Source NAT IP", "ISP / Link", "Firewall",
                                 "Destination Zone", "Destination NAT IP (Public)", "Destination Address", "Protocol", "Service / Port",
                                 "Application", "APPLICATION OWNER", "Action", "Change / CR No.", "Valid Till", "Remarks"],
     [["FW-DMZ-0142", "web-in", "Inbound", "OUTSIDE", "any", "", "ISP-A", "DMZ-FW-01", "DMZ", "198.51.100.21", "h-10.10.4.21; h-10.10.4.22",
       "tcp", "tcp_443;tcp_8443", "Internet banking", "Digital Channels", "Allow", "CR-2026-0931", "", ""],
      ["FW-CORE-0077", "dns-out", "Outbound", "DNS BIND", "10.1.55.194/195/200/201", "203.0.113.200", "", "CORE-FW-02", "OUTSIDE", "",
       "any", "udp", "dns_udp, dns_tcp", "DNS resolvers", "NetOps", "Allow", "CR-2026-1102", "2026-12-31", ""],
      ["FW-APP-0003", "web-to-app", "Internal", "DMZ", "10.10.4.0/24", "", "", "CORE-FW-01", "APP", "", "10.20.0.10-20, APP-SRV-01",
       "tcp", "8080", "App tier", "App team", "Allow", "CR-2026-1200", "", ""]]),
    ("Public IP pool", "public_pool", ["S.NO", "PUBLIC IP POOL", "USE", "APPLICATION", "APPLICATION OWNER"],
     [["1", "198.51.100.0/28", "Internet banking VIPs", "NetBanking", "Digital Channels"],
      ["2", "203.0.113.10/11/12", "Mail gateways", "Email", "IT Messaging"]]),
    ("NAT list", "nat_map", ["S.NO", "PUBLIC IP", "PRIVATE-IP", "APPLICATION", "APPLICATION OWNER", "Which firewall details exposed to this IP"],
     [["1", "198.51.100.21", "10.10.4.21", "Internet banking", "Digital Channels", "DMZ-FW-01"],
      ["2", "198.51.100.30", "10.1.55.194/195", "Partner API", "API team", "EDGE-FW-02"]]),
    ("SOD NAT", "sod_nat", ["SODdetails", "dest_nat_ip", "destination_ip", "fwl", "location", "nat_ip", "port", "protocol", "rule", "source_ip"],
     [["SOD-2026-041", "198.51.100.40", "10.30.0.10", "EDGE-FW-02", "DC-Mumbai", "", "22", "tcp", "NAT-12", "203.0.113.5"]]),
    ("Exposure register", "exposure", ["S.NO", "Public IP", "Internal IP", "Port", "Service Details", "Destination IP", "REMARK",
                                       "Source Contact Details", "Planner", "Host Status", "LOB", "Domain", "MS Partner", "Subnet", "Service Owner",
                                       "Which firewall details exposed to this IP"],
     [["1", "198.51.100.50", "10.40.0.5", "443/tcp, 8443", "Partner API", "", "", "noc@example.com", "Q4", "Live", "Payments", "Core", "Wipro",
       "10.40.0.0/24", "Payments API owner", "DMZ-FW-01"]]),
]
TEMPLATE_GUIDE = [
    ("Sheets", "Keep one sheet per kind of list, or delete the ones you do not use. On upload you pick each sheet's type and match its columns; "
               "the types are guessed from these headers. Extra columns are fine."),
    ("Firewall rules", "Source / destination addresses and ports. A row is internet-facing when its source is Internet / ISP / untrust / "
                       "outside / any, or a public IP."),
    ("Public IP pool", "Our public IPs. Every row counts as internet-facing."),
    ("NAT list", "Public IP → private IP. The private IP (and the asset behind it) is internet exposed."),
    ("SOD NAT", "Approved NAT rules: dest_nat_ip (public) → destination_ip (internal)."),
    ("Exposure register", "Public IP → internal IP with owner, LOB and firewall."),
    ("Address cells", "One IP; lists split by , ; | / space or new line; ranges 10.1.1.10-10.1.1.20 or 10.1.1.10-20; subnets 10.1.0.0/24; "
                      "last-octet shorthand 10.1.55.194/195/200; h-10.1.1.5, n-10.1.0.0/24, 10.1.1.5_nat, 10.1.1.5_vm; IPv6 2101:3900:3d5a::/48; "
                      "host / object names (matched to inventory hostnames); Any."),
    ("Port cells", "443 · 80,443 · 8000-8100 · tcp/443 · 443/tcp · tcp_8443 · udp-53 · dns_tcp · https · any."),
    ("Mark by hand", "After upload, any row can be marked internet-facing or not on the Communication matrix page; the mark is kept when "
                     "the same workbook / sheet / row is uploaded again."),
]


@router.get("/api/comm/template")
def comm_template():
    sheets = [(name, [(f"c{i}", h) for i, h in enumerate(hd)], [{f"c{i}": v for i, v in enumerate(r)} for r in rows]) for name, _, hd, rows in TEMPLATE_SHEETS]
    sheets.append(("How to fill", [("k", "Topic"), ("v", "How")], [{"k": k, "v": v} for k, v in TEMPLATE_GUIDE]))
    return xlsx_response(sheets, "template_communication_matrix")



def nat_map(c):
    """Public / NAT IP -> the private IPs behind it, from every NAT source: matrix rows (destination NAT: dst_nat -> dst on
    internet-facing rows; source NAT: src_nat <- src on any row) and inventory Public / NAT IP columns. Used to match
    inventory rows that list the public IP to the CrowdStrike agent that reports the private one, and the other way round."""
    from .registry import inventory_exposure, is_public
    out = {}

    def add(pub, priv_text):
        for n in parse_addresses(priv_text)[1]:
            if n.num_addresses <= 1024:
                for a in (n if n.num_addresses > 1 else [n.network_address]):
                    a = str(a)
                    if a != pub:
                        out.setdefault(pub, set()).add(a)

    for r in load_rules(c):
        for col, src in (("dst_nat", "dst"), ("src_nat", "src")):
            if col == "dst_nat" and not r["inbound_internet"]:
                continue
            for n in parse_addresses(r[col])[1]:
                if n.num_addresses == 1 and is_public(str(n.network_address)):
                    add(str(n.network_address), r[src])
    for r in c.execute("SELECT ip, extra FROM inventory_current WHERE COALESCE(ip,'')<>'' AND extra IS NOT NULL"):
        for p in inventory_exposure(r["extra"])[1]:
            if p != r["ip"]:
                out.setdefault(p, set()).add(r["ip"])
    return out
