"""Asset registry: every IP the console knows about, from every source, joined on one canonical IP.

Sources: LOB inventories (current version), CrowdStrike (agents in the console, plus devices in EDR history; hidden hosts
are ignored), vulnerability scans and the NIAM dump. Each row says which sources have the IP and what each one says about
it, plus internet-exposure evidence. The table is rebuilt at the end of inventory.refresh_matches(), which runs after every
sync and every upload (inventory, scan, old EDR, NIAM, agent tags), so files can be uploaded in any order: each upload
re-joins everything from scratch.

Internet exposure (any one is enough; every reason is kept so the page can explain it):
  inventory   - a column such as "Internet Facing" / "Exposure" / "Zone" says yes / DMZ / internet, or a
                "Public IP" / "NAT IP" column maps the node to a public address
  crowdstrike - the agent reports a public (globally routable) address on its own interface
  scan        - the VA scan covered a public IP: the IP itself, or the public / NAT IP of an inventory node
  public ip   - the asset's own IP is globally routable (inventory, NIAM or scan)
Egress IPs (CrowdStrike external / connection IP) are listed separately as the organisation's public IPs; sharing a NAT
egress address does not make a host reachable from the internet, so it is not counted as exposure."""
import ipaddress
import json
import re

from fastapi import APIRouter, Request

from . import db
from .exporter import xlsx_response

router = APIRouter()

FACING_COLS = {"internetfacing", "internetexposed", "exposure", "exposedtointernet", "publicfacing", "externalfacing",
               "internetexposure", "dmz", "zone", "networkzone", "securityzone", "segment", "exposuretype"}
FACING_YES = re.compile(r"^(y|yes|true|1|internet|external|public|dmz|exposed|internet[- ]?facing|public[- ]?facing)\b", re.I)
NAT_COLS = {"publicip", "natip", "externalip", "internetip", "wanip", "vip", "publicaddress", "natedip", "publicnatip",
            "internetfacingip", "globalip"}
SOURCES = ("inventory", "edr", "scan", "niam")


# IPv4 documentation ranges never appear on real networks; the sample data uses them as public addresses
_DOC_V4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global or (a.version == 4 and any(a in n for n in _DOC_V4))


def _norm(h):
    return re.sub(r"[^a-z0-9]", "", str(h or "").lower())


def inventory_exposure(extra):
    """(facing reason or None, [public / NAT IPs]) from an inventory row's extra columns."""
    facing, nat = None, []
    for k, v in (extra or {}).items():
        nk, sv = _norm(k), str(v or "").strip()
        if not sv:
            continue
        if nk in FACING_COLS and FACING_YES.search(sv):
            facing = f"{k} = {sv}"
        if nk in NAT_COLS:
            for ip in db.all_ips(sv):
                if is_public(ip):
                    nat.append(ip)
    return facing, nat


EDR_RANK = {"Online": 0, "Offline": 1, "Not Installed": 2}


def refresh(c):
    reg = {}

    def slot(key, ip):
        return reg.setdefault(key, {
            "asset_key": key, "ip": ip, "names": [], "lobs": {}, "msps": {}, "node_type": None, "live": None, "edr_applicable": 0,
            "in_inventory": 0, "in_edr": 0, "in_scan": 0, "in_niam": 0, "edr_status": None, "aid": None, "cs_hostname": None,
            "edr_last_seen": None, "edr_detail": None, "last_scan": None, "crit": 0, "high": 0, "med": 0, "low": 0,
            "ne_ids": set(), "reasons": [], "exp_src": set(), "public_ips": set(), "nat_of": set(),
            "os": None, "os_source": None, "feasible": None, "feasible_reason": None})

    def add_name(s, n):
        if n and n not in s["names"]:
            s["names"].append(n)

    def reason(s, src, text):
        if text not in [r["text"] for r in s["reasons"]]:
            s["reasons"].append({"src": src, "text": text})
            s["exp_src"].add(src)

    nat_pairs = []
    # --- LOB inventories
    for r in db.rows(c, """SELECT ic.lob_id, l.name lob, ic.msp_id, ic.msp, ic.ip, ic.node_name, ic.node_type, ic.live, ic.applicable,
                          ic.edr_state, ic.matched_aid, ic.cs_hostname, ic.cs_last_seen, ic.extra, ic.item_key,
                          ic.os_resolved, ic.os_source, ic.feasible, ic.feasible_reason
                          FROM inventory_current ic JOIN lobs l ON l.id=ic.lob_id ORDER BY ic.feasible='Yes' DESC"""):
        key = r["ip"] or "name:" + (db.norm_hostname(r["node_name"]) or r["item_key"])
        s = slot(key, r["ip"] or None)
        s["in_inventory"] = 1
        s["lobs"][r["lob_id"]] = r["lob"]
        if r["msp"]:
            s["msps"][r["msp_id"] or 0] = r["msp"]
        add_name(s, r["node_name"])
        s["node_type"] = s["node_type"] or r["node_type"]
        s["live"] = s["live"] or r["live"]
        s["edr_applicable"] |= r["applicable"] or 0
        if s["feasible"] is None:  # feasible rows first: one feasible inventory row is enough
            s["feasible"], s["feasible_reason"] = r["feasible"], r["feasible_reason"]
        if not s["os"] and r["os_resolved"]:
            s["os"], s["os_source"] = r["os_resolved"], r["os_source"]
        st = r["edr_state"] or "Not Installed"
        if s["edr_status"] is None or EDR_RANK.get(st, 9) < EDR_RANK.get(s["edr_status"], 9):
            s["edr_status"] = st
            if st != "Not Installed":
                s.update(aid=r["matched_aid"], cs_hostname=r["cs_hostname"], edr_last_seen=r["cs_last_seen"], in_edr=1)
        facing, nat = inventory_exposure(db.jloads(r["extra"], {}))
        if facing:
            reason(s, "inventory", f"Inventory ({r['lob']}): {facing}")
        for p in nat:
            if r["ip"] and p != r["ip"]:
                nat_pairs.append((key, p, "inventory", f"Inventory ({r['lob']})"))
    # --- CrowdStrike: agents in the console and devices in EDR history (hidden hosts ignored)
    for h in db.rows(c, """SELECT aid, hostname, local_ip, console_state, online_state, last_seen, removal_type, os_version FROM hosts
                          WHERE local_ip<>'' AND (console_state='active' OR (console_state='removed' AND gone_primary=1))
                          ORDER BY console_state='active' DESC, online_state='online' DESC, last_seen DESC"""):
        s = slot(h["local_ip"], h["local_ip"])
        s["in_edr"] = 1
        st = "Online" if h["console_state"] == "active" and h["online_state"] == "online" else "Offline"
        if s["edr_status"] is None or EDR_RANK.get(st, 9) < EDR_RANK.get(s["edr_status"], 9):
            s.update(edr_status=st, aid=h["aid"], cs_hostname=h["hostname"], edr_last_seen=h["last_seen"])
        if s["edr_detail"] is None:
            s["edr_detail"] = "in console" if h["console_state"] == "active" else (
                "old EDR import" if h["removal_type"] == "imported" else "removed from console")
        add_name(s, h["hostname"])
        if not s["os"] and h["os_version"]:
            s["os"], s["os_source"] = h["os_version"], "edr"
        if is_public(h["local_ip"]):
            reason(s, "crowdstrike", f"CrowdStrike: {h['hostname'] or h['aid']} has a public IP on its interface")
    # --- vulnerability scans
    from .vulns import scan_os
    va_os = scan_os(c)
    for v in db.rows(c, """SELECT a.lob_id, l.name lob, a.ip, a.crit, a.high, a.med, a.low, a.last_scanned_at FROM vuln_assets a
                          JOIN lobs l ON l.id=a.lob_id"""):
        s = slot(v["ip"], v["ip"])
        s["in_scan"] = 1
        for k in ("crit", "high", "med", "low"):
            s[k] += v[k] or 0
        s["last_scan"] = max(s["last_scan"] or "", v["last_scanned_at"] or "") or None
        if not s["os"] and v["ip"] in va_os:
            s["os"], s["os_source"] = va_os[v["ip"]][0], "scan"
    # --- NIAM
    for n in db.rows(c, "SELECT ip, ne_id, extra FROM niam_nodes WHERE present=1 AND ip<>''"):
        s = slot(n["ip"], n["ip"])
        s["in_niam"] = 1
        if n["ne_id"]:
            s["ne_ids"].add(n["ne_id"])
        add_name(s, (db.jloads(n["extra"], {}) or {}).get("NE Name"))
    # --- communication matrix: inbound Allow rules from the internet / ISP
    from .commatrix import endpoints, load_rules
    import bisect
    v4 = sorted((db.ip_to_num(s["ip"]), k) for k, s in reg.items() if s["ip"] and ":" not in s["ip"])
    v4n = [n for n, _ in v4]
    v6 = [(ipaddress.ip_address(s["ip"]), k) for k, s in reg.items() if s["ip"] and ":" in s["ip"]]
    for rule in load_rules(c):
        if not rule["inbound_internet"]:
            continue
        _, nets = endpoints(rule["dst"])
        hits = []
        for n in nets:
            if n.version == 4:
                lo, hi = int(n.network_address), int(n.broadcast_address)
                hits += [v4[i][1] for i in range(bisect.bisect_left(v4n, lo), bisect.bisect_right(v4n, hi))]
            else:
                hits += [k for a, k in v6 if a in n]
        svc = f"{(rule['protocol'] or 'any').upper()} {rule['ports'] or 'any port'}"
        text = (f"Communication matrix rule {rule['rule_id']}: {rule['src_zone'] or rule['src'] or 'internet'} → {svc}"
                + (f" via {rule['firewall']}" if rule["firewall"] else "") + (f" ({rule['isp']})" if rule["isp"] else ""))
        for k in hits:
            reason(reg[k], "matrix", text)
            for p in db.all_ips(rule["dst_nat"]):
                if p != reg[k]["ip"]:
                    nat_pairs.append((k, p, "matrix", f"Communication matrix rule {rule['rule_id']}"))
    # --- public / NAT IPs (inventory columns and matrix destination NAT)
    for key, p, src, label in nat_pairs:
        s = reg[key]
        if p in s["public_ips"]:  # same public IP from the inventory and the matrix: one reason is enough
            continue
        s["public_ips"].add(p)
        reason(s, src, f"{label}: public / NAT IP {p}")
        ps = reg.get(p)
        if ps:
            ps["nat_of"].add(s["ip"])
            if ps["in_scan"]:
                n_open = ps["crit"] + ps["high"] + ps["med"] + ps["low"]
                reason(s, "scan", f"VA scan of its public IP {p}: {n_open} open findings")
    # --- the asset's own IP is public
    for s in reg.values():
        if s["ip"] and is_public(s["ip"]):
            src = "scan" if s["in_scan"] else "ip"
            reason(s, src, "Public IP, covered by a VA scan (external scan)" if s["in_scan"] else "Public IP address")
    # --- EDR feasibility of assets in no inventory: CrowdStrike has it -> feasible (and applicable); anything else found only
    # by a VA scan / NIAM (or a future source) is unidentified and stays out of the applicable count
    for s in reg.values():
        if s["in_inventory"]:
            continue
        if s["in_edr"]:
            s.update(feasible="Yes", feasible_reason="EDR installed (not in any inventory)", edr_applicable=1)
        elif s["nat_of"]:
            s.update(feasible=None, feasible_reason="Public / NAT IP of an inventory node")
        else:
            s.update(feasible="Unidentified", feasible_reason="Not in any inventory and no EDR: feasibility unknown")
    rows = []
    for s in reg.values():
        srcs = [x for x, f in (("inventory", s["in_inventory"]), ("edr", s["in_edr"]), ("scan", s["in_scan"]), ("niam", s["in_niam"])) if f]
        rows.append((s["asset_key"], s["ip"], db.ip_to_num(s["ip"]), ", ".join(s["names"][:3]) or None,
                     ", ".join(sorted(set(s["lobs"].values()))) or None, "," + ",".join(str(i) for i in s["lobs"]) + ",",
                     ", ".join(sorted(set(s["msps"].values()))) or None, "," + ",".join(str(i) for i in s["msps"]) + ",",
                     s["node_type"], s["live"], s["edr_applicable"], s["in_inventory"], s["in_edr"], s["in_scan"], s["in_niam"],
                     s["edr_status"] or "Not Installed", s["edr_detail"], s["aid"], s["cs_hostname"], s["edr_last_seen"],
                     s["last_scan"], s["crit"], s["high"], s["med"], s["low"], ", ".join(sorted(s["ne_ids"])) or None,
                     1 if s["reasons"] else 0, json.dumps(s["reasons"]), "," + ",".join(sorted(s["exp_src"])) + ",",
                     ", ".join(sorted(s["public_ips"])) or None, ", ".join(sorted(x for x in s["nat_of"] if x)) or None,
                     1 if is_public(s["ip"]) else 0, ",".join(srcs), s["os"], s["os_source"], s["feasible"], s["feasible_reason"]))
    c.execute("DELETE FROM asset_registry")
    c.executemany(f"INSERT INTO asset_registry VALUES ({','.join('?' * 37)})", rows)


# ------------------------------------------------------------------ queries
SORTS = {"ip": "r.ip_num", "name": "r.name COLLATE NOCASE", "lobs": "r.lobs", "msps": "r.msps", "edr_status": "r.edr_status",
         "last_scan": "r.last_scan", "os": "r.os COLLATE NOCASE", "feasibility": "r.feasibility", "crit": "(r.crit*1000 + r.high)", "exposed": "r.exposed", "sources": "LENGTH(r.sources)"}


def query(p):
    w, params = [], []
    for src in (p.get("has") or "").split("|"):
        if src in SOURCES:
            w.append(f"r.in_{src}=1")
    for src in (p.get("missing") or "").split("|"):
        if src in SOURCES:
            w.append(f"r.in_{src}=0")
            if src == "inventory":  # a public IP that is the NAT address of an inventory node is not a gap
                w.append("r.nat_of IS NULL")
    if p.get("lob"):
        w.append("r.lob_ids LIKE ?")
        params.append(f"%,{int(p['lob'])},%")
    if p.get("msp"):
        if p["msp"] == "none":
            w.append("r.in_inventory=1 AND r.msps IS NULL")
        else:
            w.append("r.msp_ids LIKE ?")
            params.append(f"%,{int(p['msp'])},%")
    if p.get("node_type"):
        w.append("r.node_type=?")
        params.append(p["node_type"])
    if p.get("edr_status"):
        vals = p["edr_status"].split("|")
        w.append(f"r.edr_status IN ({','.join('?' * len(vals))})")
        params += vals
    if p.get("exposed") in ("0", "1"):
        w.append("r.exposed=?")
        params.append(int(p["exposed"]))
    if p.get("exposure_src"):
        w.append("r.exposure_src LIKE ?")
        params.append(f"%,{p['exposure_src']},%")
    v = p.get("vulns")
    if v == "crit_high":
        w.append("(r.crit + r.high) > 0")
    elif v == "any":
        w.append("(r.crit + r.high + r.med + r.low) > 0")
    elif v == "none":
        w.append("r.in_scan=1 AND (r.crit + r.high + r.med + r.low) = 0")
    # links kept from the inventory-only list (Overview / LOB pages / coverage gaps)
    live = "COALESCE(r.live,'')<>'Non Live'"
    gap = p.get("gap")
    if gap == "edr" or p.get("pending") == "1":
        w.append("r.in_inventory=1 AND r.edr_applicable=1 AND r.edr_status='Not Installed'")
    elif gap == "niam":
        w.append("r.in_niam=0")
    elif gap == "scan":
        w.append(f"r.in_scan=0 AND {live}")
    if p.get("coverage_status") in ("Online", "Offline"):
        w.append("r.in_inventory=1 AND r.edr_applicable=1 AND r.edr_status=?")
        params.append(p["coverage_status"])
    ok = p.get("offline_kind")
    if ok in ("console", "removed", "import"):
        w.append("r.in_inventory=1 AND r.edr_status='Offline'")
        w.append({"console": "r.edr_detail='in console'",
                  "removed": "r.edr_detail='removed from console'",
                  "import": "r.edr_detail='old EDR import'"}[ok])
    if p.get("applicable") == "1":
        w.append("r.in_inventory=1 AND r.edr_applicable=1")
    if p.get("edr_applicable") == "1":  # inventory nodes that are applicable + assets in no inventory that have EDR
        w.append("r.edr_applicable=1")
    if p.get("feasibility") in ("Yes", "No", "Legacy", "To be decided", "Unidentified"):
        w.append("r.feasibility=?")
        params.append(p["feasibility"])
    if p.get("os_source"):
        if p["os_source"] == "none":
            w.append("COALESCE(r.os,'')=''")
        else:
            w.append("r.os_source=?")
            params.append(p["os_source"])
    if p.get("os"):
        w.append("r.os LIKE ?")
        params.append(f"%{p['os']}%")
    if p.get("installed") == "1":
        w.append("r.in_inventory=1 AND r.edr_applicable=1 AND r.edr_status IN ('Online','Offline')")
    if p.get("niam") in ("0", "1"):
        w.append(f"r.in_niam={int(p['niam'])}")
    if p.get("scanned") in ("0", "1"):
        w.append(f"r.in_scan={int(p['scanned'])}" + (f" AND {live}" if p["scanned"] == "0" else ""))
    q = (p.get("q") or "").strip()
    if q:
        terms = [t for t in re.split(r"[\s,;]+", q) if t]
        if len(terms) > 1:
            ph = ",".join("?" * len(terms))
            w.append(f"(r.ip IN ({ph}) OR LOWER(r.name) IN ({ph}))")
            params += [db.canon_ip(t) for t in terms] + [t.lower() for t in terms]
        elif db.is_range_query(q):
            w.append("ip_in(r.ip, ?)")
            params.append(q)
        elif db.is_ip(q):
            ip = db.canon_ip(q)
            w.append("(r.ip=? OR r.public_ips LIKE ? OR r.nat_of LIKE ?)")
            params += [ip, f"%{ip}%", f"%{ip}%"]
        else:
            like = f"%{q}%"
            w.append("(r.ip LIKE ? OR r.name LIKE ? OR r.cs_hostname LIKE ? OR r.ne_ids LIKE ? OR r.lobs LIKE ? OR r.msps LIKE ? OR r.os LIKE ?)")
            params += [q + "%", like, like, like, like, like, like]
    sort = SORTS.get(p.get("sort") or "", "r.ip_num")
    direction = "DESC" if (p.get("dir") or "asc") == "desc" else "ASC"
    where = ("WHERE " + " AND ".join(w)) if w else ""
    return where, params, f"ORDER BY {sort} {direction}, r.asset_key"


def _rows(c, p, limit=None, offset=0):
    where, params, order = query(p)
    lim = f"LIMIT {int(limit)} OFFSET {int(offset)}" if limit else ""
    rows = db.rows(c, f"SELECT r.* FROM asset_registry r {where} {order} {lim}", params)
    for r in rows:
        r["exposure"] = json.loads(r["exposure"] or "[]")
    return rows


@router.get("/api/registry")
def registry_list(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params, _ = query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM asset_registry r {where}", params).fetchone()[0]
        rows = _rows(c, p, size, (page - 1) * size)
    return {"total": total, "rows": rows}


EXPORT = [("ip", "IP"), ("name", "Name"), ("sources_text", "Found In"), ("lobs", "LOB"), ("msps", "MSP"), ("node_type", "Node Type"),
          ("os", "OS"), ("os_source", "OS Source"), ("feasibility", "EDR Feasible"), ("feasibility_reason", "Feasibility Reason"),
          ("live", "Live / Non Live"), ("edr_status", "EDR Status"), ("edr_detail", "EDR Detail"), ("cs_hostname", "CrowdStrike Hostname"),
          ("aid", "Agent ID"), ("edr_last_seen", "EDR Last Seen"), ("last_scan", "Last VA Scan"), ("crit", "Critical"), ("high", "High"),
          ("med", "Medium"), ("low", "Low"), ("ne_ids", "NIAM NE ID"), ("exposed_text", "Internet Exposed"),
          ("exposure_text", "Exposure Evidence"), ("public_ips", "Public / NAT IP"), ("nat_of", "Public IP Of")]
SRC_LABEL = {"inventory": "Inventory", "edr": "CrowdStrike", "scan": "VA scan", "niam": "NIAM"}


@router.get("/api/registry/export")
def registry_export(request: Request):
    p = dict(request.query_params)
    with db.get_conn() as c:
        rows = _rows(c, p)
    for r in rows:
        r["sources_text"] = ", ".join(SRC_LABEL[s] for s in (r["sources"] or "").split(",") if s)
        r["exposed_text"] = "Yes" if r["exposed"] else "No"
        r["exposure_text"] = "; ".join(e["text"] for e in r["exposure"])
    return xlsx_response([("All assets", EXPORT, rows)], "internet_exposed" if p.get("exposed") == "1" else "all_assets")


@router.get("/api/registry/summary")
def registry_summary():
    with db.get_conn() as c:
        s = db.one(c, """SELECT COUNT(*) total, SUM(in_inventory) inventory, SUM(in_edr) edr, SUM(in_scan) scan, SUM(in_niam) niam,
            SUM(exposed) exposed, SUM(in_inventory=0 AND nat_of IS NULL) not_in_inventory,
            SUM(in_inventory=0 AND nat_of IS NULL AND in_edr=1) not_inv_edr, SUM(in_inventory=0 AND nat_of IS NULL AND in_scan=1) not_inv_scan,
            SUM(in_inventory=0 AND nat_of IS NULL AND in_niam=1) not_inv_niam,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Online') not_inv_online,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Offline') not_inv_offline,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Offline' AND COALESCE(edr_detail,'in console')='in console') not_inv_offline_console,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Offline' AND edr_detail='removed from console') not_inv_removed_console,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Offline' AND edr_detail='old EDR import') not_inv_removed_import,
            SUM(in_inventory=0 AND nat_of IS NULL AND edr_status='Not Installed') not_inv_no_edr, SUM(in_inventory=0 AND nat_of IS NULL AND in_niam=0) not_inv_not_niam,
            SUM(in_niam=0) not_in_niam, SUM(edr_applicable=1) applicable,
            SUM(edr_applicable=1 AND edr_status IN ('Online','Offline')) installed,
            SUM(edr_applicable=1 AND in_inventory=0) applicable_not_inv, SUM(feasibility='Unidentified') unidentified,
            SUM(feasibility='To be decided') to_be_decided,
            SUM(feasibility='No') not_feasible, SUM(feasibility='Legacy') legacy, SUM(COALESCE(os,'')<>'') os_known FROM asset_registry""")
        lob_opts = db.rows(c, "SELECT id, name FROM lobs ORDER BY name COLLATE NOCASE")
    return {k: (v or 0) for k, v in s.items()} | {"lobs": lob_opts}


@router.get("/api/exposure/summary")
def exposure_summary():
    with db.get_conn() as c:
        s = db.one(c, """SELECT SUM(exposed) exposed, SUM(exposed AND exposure_src LIKE '%,inventory,%') by_inventory,
            SUM(exposed AND exposure_src LIKE '%,crowdstrike,%') by_crowdstrike, SUM(exposed AND exposure_src LIKE '%,scan,%') by_scan,
            SUM(exposed AND exposure_src LIKE '%,ip,%') by_ip, SUM(exposed AND exposure_src LIKE '%,matrix,%') by_matrix, SUM(exposed AND edr_status='Not Installed') no_edr,
            SUM(exposed AND (crit + high) > 0) crit_high, SUM(exposed AND in_inventory=0) not_in_inventory,
            SUM(exposed AND in_inventory=1) in_inventory,
            SUM(exposed AND edr_status='Offline') edr_offline,
            SUM(exposed AND edr_status IN ('Online','Offline')) edr_installed,
            SUM(exposed AND edr_status='Online') edr_online,
            SUM(exposed AND edr_status='Not Installed') edr_missing,
            SUM(exposed AND edr_detail='removed from console') edr_removed,
            SUM(exposed AND edr_detail='old EDR import') edr_import,
            SUM(exposed AND (crit + high) = 0) no_crit_high FROM asset_registry""")
        # "how we know": only the four evidence sources the page explains (CrowdStrike, inventory, VA scan, matrix)
        know = db.one(c, """SELECT
            SUM(exposed AND (exposure_src LIKE '%,scan,%' OR exposure_src LIKE '%,ip,%')) by_scan,
            SUM(exposed AND exposure_src LIKE '%,inventory,%') by_inventory,
            SUM(exposed AND exposure_src LIKE '%,crowdstrike,%') by_crowdstrike,
            SUM(exposed AND exposure_src LIKE '%,matrix,%') by_matrix FROM asset_registry""")
        # the organisation's public egress IPs as CrowdStrike sees them (NAT / proxy addresses the agents connect from)
        egress = {}
        for h in db.rows(c, """SELECT hostname, external_ip, connection_ip, online_state FROM hosts WHERE console_state='active'"""):
            for ip in {h["external_ip"], h["connection_ip"]}:
                if ip and is_public(ip):
                    e = egress.setdefault(ip, {"ip": ip, "hosts": 0, "online": 0, "sample": []})
                    e["hosts"] += 1
                    e["online"] += 1 if h["online_state"] == "online" else 0
                    if len(e["sample"]) < 3 and h["hostname"]:
                        e["sample"].append(h["hostname"])
    return {**{k: (v or 0) for k, v in s.items()},
            "know": {k: (v or 0) for k, v in know.items()},
            "egress_ips": sorted(egress.values(), key=lambda e: -e["hosts"])}
