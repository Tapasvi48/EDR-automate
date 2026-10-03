"""Subnets & VLANs: every known asset (inventory, CrowdStrike, VA scans, NIAM — the asset registry) grouped by where it sits on
the network, so gaps show up per segment ("this /24 has 40 servers and 6 have no EDR", "this VLAN mixes two LOBs").

Three ways to group:
  subnet   IPv4 prefix of your choice (/16 … /30), from the asset IP
  gateway  CrowdStrike's default gateway of each agent: agents behind the same gateway share a layer-2 segment, which is
           as close to a VLAN as an agent can tell. Assets without an agent take the gateway most agents in their /24 use
           (marked "inferred").
  vlan     a VLAN column in an LOB inventory (any column whose name contains "VLAN")
"""
import ipaddress
import re

from fastapi import APIRouter, HTTPException, Request

from . import db
from .exporter import xlsx_response

router = APIRouter()
HAS_EDR = ("Online", "Offline")
VLAN_KEY = re.compile(r"vlan", re.I)
COLS = """r.ip, r.ip_num, r.name, r.lobs, r.msps, r.node_type, r.edr_status, r.edr_applicable, r.in_inventory, r.exposed,
          COALESCE(r.crit,0) crit, COALESCE(r.high,0) high, r.aid, r.os"""


def _gateways(c):
    """{aid: default gateway} of active agents."""
    return {r[0]: r[1] for r in c.execute("""SELECT aid, default_gateway_ip FROM hosts
                                             WHERE console_state='active' AND COALESCE(default_gateway_ip,'')<>''""")}


def _vlans(c):
    """{ip: VLAN} from inventory columns named like VLAN (extra columns of the LOB inventories)."""
    out = {}
    for r in c.execute("SELECT ip, extra FROM inventory_current WHERE COALESCE(ip,'')<>'' AND extra LIKE '%vlan%' COLLATE NOCASE"):
        for k, v in (db.jloads(r[1], {}) or {}).items():
            if VLAN_KEY.search(k) and str(v or "").strip():
                out[r[0]] = str(v).strip()
                break
    return out


def _prefix(p):
    try:
        n = int(p or 24)
    except ValueError:
        n = 24
    return min(30, max(8, n))


def _assets(c):
    return db.rows(c, f"SELECT {COLS} FROM asset_registry r WHERE r.ip_num IS NOT NULL AND r.ip NOT LIKE '%:%'")


def _keyer(c, mode, prefix, rows):
    """Function asset -> (group key, label, inferred?)."""
    if mode == "gateway":
        gw = _gateways(c)
        by24 = {}
        for r in rows:
            g = gw.get(r["aid"]) if r["aid"] else None
            if g:
                by24.setdefault(r["ip_num"] >> 8, {}).setdefault(g, 0)
                by24[r["ip_num"] >> 8][g] += 1
        major = {k: max(v, key=v.get) for k, v in by24.items()}

        def key(r):
            g = gw.get(r["aid"]) if r["aid"] else None
            if g:
                return g, g, False
            g = major.get(r["ip_num"] >> 8)
            return (g, g, True) if g else (None, "(no CrowdStrike agent nearby)", True)
        return key
    if mode == "vlan":
        vl = _vlans(c)

        def key(r):
            v = vl.get(r["ip"])
            return (v, f"VLAN {v}", False) if v else (None, "(no VLAN in inventory)", False)
        return key
    shift = 32 - prefix

    def key(r):
        k = r["ip_num"] >> shift
        return k, f"{ipaddress.IPv4Address(k << shift)}/{prefix}", False
    return key


def _groups(c, mode, prefix):
    rows = _assets(c)
    key = _keyer(c, mode, prefix, rows)
    gw = _gateways(c) if mode != "gateway" else {}
    vl = _vlans(c) if mode != "vlan" else {}
    groups = {}
    for r in rows:
        k, label, inferred = key(r)
        g = groups.get(k)
        if g is None:
            g = groups[k] = {"key": str(k) if k is not None else "", "label": label, "assets": 0, "edr": 0, "online": 0, "offline": 0,
                             "gap": 0, "exposed": 0, "exposed_no_edr": 0, "crit": 0, "high": 0, "inferred": 0,
                             "_lobs": {}, "_msps": set(), "_types": {}, "_gw": set(), "_vl": set(), "_min": r["ip_num"], "_max": r["ip_num"]}
        g["assets"] += 1
        st = r["edr_status"]
        has = st in HAS_EDR
        g["edr"] += has
        g["online"] += st == "Online"
        g["offline"] += st == "Offline"
        g["gap"] += bool(r["in_inventory"] and r["edr_applicable"] and st == "Not Installed")
        g["exposed"] += bool(r["exposed"])
        g["exposed_no_edr"] += bool(r["exposed"] and not has)
        g["crit"] += r["crit"]
        g["high"] += r["high"]
        g["inferred"] += inferred
        for l in (r["lobs"] or "").split(", "):
            if l:
                g["_lobs"][l] = g["_lobs"].get(l, 0) + 1
        g["_msps"].update(x for x in (r["msps"] or "").split(", ") if x)
        if r["node_type"]:
            g["_types"][r["node_type"]] = g["_types"].get(r["node_type"], 0) + 1
        if gw.get(r["aid"]):
            g["_gw"].add(gw[r["aid"]])
        if vl.get(r["ip"]):
            g["_vl"].add(vl[r["ip"]])
        g["_min"], g["_max"] = min(g["_min"], r["ip_num"]), max(g["_max"], r["ip_num"])
    out = []
    for g in groups.values():
        lobs = sorted(g.pop("_lobs").items(), key=lambda x: -x[1])
        types = sorted(g.pop("_types").items(), key=lambda x: -x[1])
        g["lobs"] = ", ".join(l for l, _ in lobs)
        g["lob_count"] = len(lobs)
        g["msps"] = ", ".join(sorted(g.pop("_msps")))
        g["node_types"] = ", ".join(f"{t} ({n})" for t, n in types[:4])
        g["gateways"] = ", ".join(sorted(g.pop("_gw"))[:5])
        g["vlans"] = ", ".join(sorted(g.pop("_vl"))[:5])
        lo, hi = g.pop("_min"), g.pop("_max")
        g["range"] = f"{ipaddress.IPv4Address(lo)} – {ipaddress.IPv4Address(hi)}"
        need = g["edr"] + g["gap"]
        g["coverage"] = round(100 * g["edr"] / need) if need else None
        out.append(g)
    return out


SORTS = {"assets": lambda g: -g["assets"], "gap": lambda g: (-g["gap"], -g["assets"]), "exposed": lambda g: (-g["exposed_no_edr"], -g["exposed"]),
         "risk": lambda g: (-g["crit"], -g["high"]), "coverage": lambda g: (g["coverage"] if g["coverage"] is not None else 101, -g["assets"]),
         "label": lambda g: g["label"], "lobs": lambda g: (-g["lob_count"], -g["assets"])}


def _filtered(c, p):
    mode = p.get("group") if p.get("group") in ("subnet", "gateway", "vlan") else "subnet"
    out = _groups(c, mode, _prefix(p.get("prefix")))
    q = (p.get("q") or "").strip().lower()
    if q:
        out = [g for g in out if q in g["label"].lower() or q in g["lobs"].lower() or q in g["msps"].lower()
               or q in g["gateways"].lower() or q in g["vlans"].lower() or _contains(g, q, mode, p)]
    if p.get("lob"):
        out = [g for g in out if p["lob"] in g["lobs"].split(", ")]
    if p.get("gap") == "1":
        out = [g for g in out if g["gap"]]
    if p.get("exposed") == "1":
        out = [g for g in out if g["exposed"]]
    if p.get("mixed") == "1":
        out = [g for g in out if g["lob_count"] > 1]
    out.sort(key=SORTS.get(p.get("sort") or "", SORTS["gap"]))
    if (p.get("dir") or "") == "asc" and p.get("sort") in SORTS:
        out.reverse()
    return mode, out


def _contains(g, q, mode, p):
    """A typed IP finds its own subnet."""
    if mode != "subnet" or not db.is_ip(q) or ":" in q:
        return False
    prefix = _prefix(p.get("prefix"))
    return str(ipaddress.ip_network(f"{q}/{prefix}", strict=False)) == g["label"]


@router.get("/api/subnets")
def subnets(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    with db.get_conn() as c:
        mode, out = _filtered(c, p)
        has_vlan = bool(_vlans(c)) if mode != "vlan" else True
        has_gw = bool(_gateways(c))
    tot = {k: sum(g[k] for g in out) for k in ("assets", "edr", "gap", "exposed", "exposed_no_edr")}
    return {"total": len(out), "rows": out[(page - 1) * size: page * size], "mode": mode, "prefix": _prefix(p.get("prefix")),
            "summary": {**tot, "groups": len(out), "with_gap": sum(1 for g in out if g["gap"]), "mixed_lob": sum(1 for g in out if g["lob_count"] > 1),
                        "exposed_groups": sum(1 for g in out if g["exposed"])},
            "has_vlan": has_vlan, "has_gateway": has_gw}


def _members(c, p):
    mode = p.get("group") if p.get("group") in ("subnet", "gateway", "vlan") else "subnet"
    key = p.get("key") or ""
    if mode == "subnet":
        try:
            net = ipaddress.ip_network(key if "/" in key else f"{key}/{_prefix(p.get('prefix'))}", strict=False)
        except ValueError:
            raise HTTPException(400, "Not a subnet")
        sel = db.rows(c, f"SELECT {COLS} FROM asset_registry r WHERE r.ip_num BETWEEN ? AND ? AND r.ip NOT LIKE '%:%'",
                      (int(net.network_address), int(net.broadcast_address)))
    else:
        rows = _assets(c)
        keyer = _keyer(c, mode, 24, rows)
        sel = [r for r in rows if str(keyer(r)[0] if keyer(r)[0] is not None else "") == key]
    gw, vl = _gateways(c), _vlans(c)
    for r in sel:
        r["gateway"] = gw.get(r["aid"]) or ""
        r["vlan"] = vl.get(r["ip"]) or ""
        r["gap"] = bool(r["in_inventory"] and r["edr_applicable"] and r["edr_status"] == "Not Installed")
    sel.sort(key=lambda r: r["ip_num"])
    return sel


@router.get("/api/subnets/members")
def subnet_members(request: Request):
    with db.get_conn() as c:
        rows = _members(c, dict(request.query_params))
    return {"total": len(rows), "rows": rows[:5000]}


EXPORT = [("label", "Subnet / segment"), ("range", "IPs seen"), ("assets", "Assets"), ("edr", "With EDR"), ("online", "Online"),
          ("offline", "Offline"), ("gap", "Feasible without EDR"), ("coverage", "EDR coverage %"), ("exposed", "Internet exposed"),
          ("exposed_no_edr", "Exposed without EDR"), ("crit", "Critical vulns"), ("high", "High vulns"), ("lobs", "LOBs"), ("msps", "MSPs"),
          ("node_types", "Node types"), ("gateways", "CrowdStrike gateways"), ("vlans", "VLANs (inventory)"), ("inferred", "Grouped by inferred gateway")]
MEMBER_EXPORT = [("ip", "IP"), ("name", "Name"), ("lobs", "LOB"), ("msps", "MSP"), ("node_type", "Node type"), ("os", "OS"),
                 ("edr_status", "EDR"), ("gap_text", "Feasible without EDR"), ("exposed_text", "Internet exposed"), ("crit", "Critical"),
                 ("high", "High"), ("gateway", "Gateway (CrowdStrike)"), ("vlan", "VLAN (inventory)")]


@router.get("/api/subnets/export")
def subnets_export(request: Request):
    p = dict(request.query_params)
    with db.get_conn() as c:
        mode, out = _filtered(c, p)
        members = _members(c, p) if p.get("key") else None
    sheets = [("Segments", EXPORT, out)]
    if members is not None:
        for r in members:
            r["gap_text"] = "Yes" if r["gap"] else ""
            r["exposed_text"] = "Yes" if r["exposed"] else ""
        sheets.append(("Assets in " + (p.get("key") or "")[:20].replace("/", "_"), MEMBER_EXPORT, members))
    return xlsx_response(sheets, f"segments_by_{mode}")


def neighbours(c, ip, prefix=24):
    """Summary of the asset's own subnet for Asset 360: how many assets, EDR coverage, gateway(s)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    rows = db.rows(c, f"SELECT {COLS} FROM asset_registry r WHERE r.ip_num BETWEEN ? AND ?",
                   (int(net.network_address), int(net.broadcast_address)))
    gw = _gateways(c)
    return {"subnet": str(net), "assets": len(rows), "edr": sum(r["edr_status"] in HAS_EDR for r in rows),
            "gap": sum(bool(r["in_inventory"] and r["edr_applicable"] and r["edr_status"] == "Not Installed") for r in rows),
            "exposed": sum(bool(r["exposed"]) for r in rows), "gateways": sorted({gw[r["aid"]] for r in rows if gw.get(r["aid"])})[:5],
            "lobs": sorted({l for r in rows for l in (r["lobs"] or "").split(", ") if l})}

