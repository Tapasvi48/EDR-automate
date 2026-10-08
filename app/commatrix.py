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
from functools import lru_cache

from .addrparse import parse_addresses as _parse_addresses, ports_allow


@lru_cache(maxsize=200_000)
def parse_addresses(text):
    """addrparse.parse_addresses, cached per cell text: the same rule cells are parsed by the exposure rebuild, the matrix
    asset list, ownership and NAT pairing. Returns tuples (read-only)."""
    anyv, nets, names = _parse_addresses(text)
    return anyv, tuple(nets), tuple(names)
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
    "src": ["sourceipsubnetinside", "sourceinsideip", "insideip", "inside", "insidelocal", "insideaddress", "localip", "privatesourceip",
            "sourceipsubnet", "sourceip", "sourceaddress", "srcip", "srcaddress", "source", "sourcesubnet", "src"],
    "src_nat": ["sourcenatoutsideippublic", "outsideippublic", "outsideip", "outside", "outsideglobal", "outsideaddress", "translatedip",
                "sourcenattedip", "sourcenatedip", "nattedip", "natedip", "nattedpublicip", "natpublicipsource", "sourcepublicip", "publicsourceip", "sourcenatip", "srcnat", "snat",
                "sourcenat", "natip"],
    "isp": ["isplink", "isp", "link", "carrier"],
    "firewall": ["firewall", "fw", "fwl", "firewallname", "device", "whichfirewalldetailsexposedtothisip", "firewalldetails", "whichfirewall"],
    "fw_rule": ["firewallrulename", "rulename", "policyname", "policy"],
    "dst_zone": ["destinationzone", "dstzone", "tozone"],
    "dst_nat": ["destinationpublicnatip", "destinationpublicip", "destinationnatippublic", "destinationnatip", "destnatip", "dstnat", "dnat", "publicip", "publicippool", "publicips", "vip", "natpublicip"],
    "dst": ["destinationipsubnetinside", "destinationinsideip", "destinationipsubnet", "destinationip", "destinationaddress", "dstip", "dstaddress", "destination", "destinationsubnet", "dst",
            "privateip", "internalip", "private", "internal"],
    "protocol": ["protocol", "proto"],
    "ports": ["ports", "port", "portprotocol", "protocolport", "portsprotocol", "dstport", "destinationport", "serviceport", "service"],
    "service": ["serviceuse", "servicedetails", "use", "usage", "purpose", "applicationservice"],
    "application": ["application", "applicaiton", "applicaton", "app", "appname", "applicationname"],
    "app_owner": ["applicationowner", "applicatonowner", "applicaitonowner", "appowner", "serviceowner", "owner", "sourcecontactdetails", "contact"],
    "action": ["action", "permit"],
    "cr": ["changesodno", "changecrsodno", "changecrno", "crno", "cr", "change", "approval", "soddetails", "sod", "sodno"],
    "valid_till": ["validtill", "validuntil", "expiry", "expirydate"],
    "lob": ["lob", "lineofbusiness"], "domain": ["domain"], "msp": ["mspartner", "msp", "partner", "mspname"],
    "location": ["locationdc", "location", "site", "dc", "circle"],
    "remarks": ["remarks", "remark", "comments", "notes", "hoststatus", "planner"],
}
# Sheet types offered on upload: one per pattern of the template (MX-0001 … MX-0014). A pattern decides how EVERY row of the sheet is
# read: inbound = rows are internet-facing (1) or not (0); clear = fields emptied so they cannot expose anything; defaults = values
# filled when the cell is empty (for display). need = groups of fields, one of each group must be mapped.
_ANY_ADDR = [["src", "dst", "dst_nat"]]
PATTERNS = {
    # the three sheet types offered on upload (inbound None = decided per row from the zones / ISP / source)
    "zones": ("Firewall rules (Source Zone / ISP / Destination Zone)",
              "Each row is checked: Source Zone Internet / ISP / Untrust / Outside, a filled ISP link, or a source of Any / a public IP "
              "= exposed. Deny rows and internal zones are not.", _ANY_ADDR, None, (), {}),
    "pubpriv": ("Public IP + private IP", "Each row's public IP is NATed to its private IP: both are exposed and linked.",
                [["dst_nat"], ["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Internet", "src": "Any"}),
    "pubonly": ("Only public IP", "Each row is a public IP with no private IP behind it (ISP direct): the public IP is exposed.",
                [["dst_nat"]], 1, ("dst",), {"direction": "Inbound", "src_zone": "Internet", "src": "Any"}),
    "register": ("Public IP · Internal IP · Port · Service · Destination IP",
                 "Each Public IP leads to its Internal IP (and the Destination IP when filled): all are exposed and linked.",
                 [["dst_nat"], ["dst", "src"]], 1, (), {"direction": "Inbound", "src_zone": "Internet"}),
    "snat": ("Source IP · Destination IP · Port / Protocol · Source Natted IP",
             "Each source IP goes out to the internet through its Source Natted (public) IP: the source is exposed and linked to it.",
             [["src"], ["src_nat"]], 0, ("dst_nat",), {"direction": "Outbound"}),
    "fwpolicy": ("Firewall policy (Rule Name · Zones · IP/Object · NAT Translated IP …)",
                 "Each rule checked by its zones: from Internet / Untrust / Outside or a source of Any = exposed; NAT Translated IP is the "
                 "inside server of an inbound rule or the public IP an outbound rule leaves as. Deny rules are never exposed.",
                 [["src", "dst"]], None, (), {}),
    "sod": ("SOD NAT (SODdetails · dest_nat_ip · destination_ip · nat_ip · source_ip …)",
            "Each row checked: a public dest_nat_ip exposes destination_ip (linked); a public nat_ip exposes source_ip (linked).",
            [["dst", "dst_nat", "src"]], None, (), {}),
    # earlier sheet types: kept so rows uploaded with them still read and show correctly
    "mx01": ("MX-0001 · Public + private (destination NAT)", "Public IP NATed to an inside server: both IPs exposed and linked.",
             [["dst_nat"], ["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Internet", "src": "Any"}),
    "mx02": ("MX-0002 · Outbound via source NAT", "Inside host goes out through a public IP: the inside host is exposed and linked.",
             [["src"], ["src_nat"]], 0, (), {"direction": "Outbound"}),
    "mx03": ("MX-0003 · Public IP only (ISP direct)", "Host with only a public IP on the ISP link, no NAT: the public IP is exposed.",
             [["dst_nat"]], 1, ("dst",), {"direction": "Inbound", "src_zone": "Internet", "src": "Any"}),
    "mx04": ("MX-0004 · Static NAT, all ports", "One-to-one public ↔ private NAT on every port: both exposed and linked.",
             [["dst_nat"], ["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Internet", "src": "Any", "ports": "any", "protocol": "any"}),
    "mx05": ("MX-0005 · Partner / NNI link", "Partner / NNI / roaming flow: not directly exposed (add the range under Indirect ranges).",
             [["src", "dst"]], 0, ("src_nat",), {"direction": "Inbound", "src_zone": "NNI-Partner"}),
    "mx06": ("MX-0006 · Internal (east–west)", "Inside to inside flow: not exposed.",
             [["src", "dst"]], 0, ("src_nat",), {"direction": "Internal"}),
    "mx07": ("MX-0007 · Own public IP (no NAT)", "Server that owns a public IP (in the destination column): the public IP is exposed.",
             [["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Internet", "src": "Any"}),
    "mx08": ("MX-0008 · Internet → private IP", "Inbound from the internet to a private IP, public IP unknown: the private IP is exposed.",
             [["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Untrust", "src": "Any"}),
    "mx09": ("MX-0009 · Partner public IP → internal", "One partner public IP allowed in to an internal server: the server is exposed.",
             [["src"], ["dst"]], 1, (), {"direction": "Inbound", "src_zone": "Partner"}),
    "mx10": ("MX-0010 · Partner public range → internal", "A partner public subnet / range allowed in to an internal server: the server is exposed.",
             [["src"], ["dst"]], 1, (), {"direction": "Inbound", "src_zone": "External"}),
    "mx11": ("MX-0011 · Public IP in source column", "A list of public IPs in the source column only: each public IP is exposed (ISP direct).",
             [["src"]], 0, ("dst", "dst_nat", "src_nat"), {}),
    "mx12": ("MX-0012 · Outbound, no NAT", "Outbound to the internet without a NAT IP: not exposed.",
             [["src"]], 0, ("src_nat",), {"direction": "Outbound"}),
    "mx13": ("MX-0013 · Denied rule", "Deny / drop rules: kept for reference, never exposed.",
             _ANY_ADDR, 0, ("src_nat",), {"action": "Deny"}),
    "mx14": ("MX-0014 · Expired rule", "Expired rules: kept for reference, ignored.",
             _ANY_ADDR, 0, ("src_nat",), {}),
}
# Fields offered for mapping per pattern: the pattern's own address fields first (with what they mean in THAT pattern), then
# the flow and descriptive fields. Fields a pattern does not list are not read from its sheets.
FIELD_DESC = {
    "rule_id": "Unique ID of the row (blank = row number)", "protocol": "tcp / udp / icmp / any", "ports": "Port, list or range (443, 80,443, 8000-8100)",
    "service": "What the flow is for", "application": "Application name; also names assets only the matrix knows",
    "app_owner": "Team / person who owns the application", "lob": "Owning LOB, used when no inventory lists the IP",
    "msp": "Managed service partner", "domain": "Domain / tower", "location": "DC, circle or POP", "firewall": "Firewall that enforces the rule",
    "fw_rule": "Rule name on the firewall", "cr": "Change / CR / SOD approval number", "valid_till": "Last day the rule is valid (blank = permanent)",
    "remarks": "Free notes", "isp": "ISP / ILL link the traffic comes in on", "src_zone": "Zone of the source", "dst_zone": "Zone of the destination",
    "direction": "Inbound / Outbound / Internal", "action": "Allow / Deny", "name": "Rule or service name",
}
_FLOW = ["protocol", "ports", "service"]
_INFO = ["rule_id", "application", "app_owner", "lob", "msp", "domain", "location", "firewall", "fw_rule", "cr", "valid_till", "remarks"]
PATTERN_FIELDS = {
    "zones": [("src_zone", "Zone the traffic comes from; Internet / ISP / Untrust / Outside = from the internet"),
              ("isp", "ISP / ILL link; filled = from the internet"), ("dst_zone", "Zone of the destination, e.g. DMZ"),
              ("src", "Source IP / subnet, or Any"), ("dst", "Destination server IP / subnet"),
              ("dst_nat", "Destination public / NAT IP (optional)"), ("src_nat", "Source NAT public IP (optional; exposes the source)"),
              ("direction", None), ("action", "Allow / Deny; Deny rows are never exposed"), *_FLOW],
    "pubpriv": [("dst_nat", "The public IP"), ("dst", "The private IP behind the public IP"), ("isp", None), *_FLOW],
    "pubonly": [("dst_nat", "The public IP"), ("isp", "ISP / ILL link the public IP sits on"), *_FLOW],
    # (key, description, label shown for this type): the register's own column names
    "register": [("dst_nat", "Public IP the internet reaches", "Public IP"), ("dst", "Internal IP behind the public IP", "Internal IP"),
                 ("ports", "Port(s) open on the public IP", "Port"), ("service", "What the service is", "Service Details"),
                 ("src", "Another internal address the public IP leads to (also exposed and linked)", "Destination IP"),
                 ("remarks", "Free notes", "REMARK")],
    "snat": [("src", "Inside host that goes out", "source_ip"), ("dst", "Where it connects to (internet IP; not listed as ours)", "destination_ip"),
             ("ports", "Port and protocol, e.g. 443/tcp", "Port / Protocol"),
             ("src_nat", "Public IP the source leaves through; a public IP here makes the source exposed", "Source Natted IP")],
    "fwpolicy": [("fw_rule", "Rule name on the firewall", "Rule Name"),
                 ("src_zone", "Zone the traffic comes from; Internet / Untrust / Outside = from the internet", "Source Zone"),
                 ("src", "Source IP / object, or Any", "Source IP/Object"), ("dst_zone", "Zone of the destination, e.g. DMZ", "Destination Zone"),
                 ("dst", "Destination IP / object (public IP of an inbound NAT rule)", "Destination IP/Object"),
                 ("protocol", None, "Protocol"), ("ports", None, "Port"), ("action", "Allow / Deny; Deny is never exposed", "Action"),
                 ("x_logging", "Kept in the remarks", "Logging"), ("name", "NAT rule name", "NAT Rule"),
                 ("src_nat", "Inbound rule: the inside server behind the destination. Outbound rule: the public IP the source leaves as",
                  "NAT Translated IP"),
                 ("x_vpn", "VPN peer; kept in the remarks, not listed as ours", "VPN Peer"), ("x_nexthop", "Kept in the remarks", "Route Next Hop"),
                 ("remarks", None, "Remarks")],
    "sod": [("cr", "SOD / approval reference", "SODdetails"),
            ("dst_nat", "Public IP the traffic comes in on (destination NAT); public = destination_ip exposed", "dest_nat_ip"),
            ("dst", "Inside server behind dest_nat_ip", "destination_ip"), ("firewall", "Firewall that enforces it", "fwl"),
            ("location", "DC / site", "location"),
            ("src_nat", "Public IP the source leaves through (source NAT); public = source_ip exposed", "nat_ip"),
            ("ports", "Port(s)", "port"), ("protocol", "tcp / udp / any", "protocol"), ("rule_id", "Rule number / name", "rule"),
            ("src", "Source IP, or Any", "source_ip")],
    "mx01": [("dst_nat", "Public / VIP IP the internet connects to"), ("dst", "Inside server IP behind that public IP"),
             ("src", "Allowed internet source (blank = Any)"), ("isp", None), *_FLOW],
    "mx02": [("src", "Inside host(s) that go out to the internet"), ("src_nat", "Public IP they leave through (source NAT / outside IP)"),
             ("dst", "Where they connect to (optional)"), ("isp", None), *_FLOW],
    "mx03": [("dst_nat", "The host's public IP (no private IP behind it)"), ("isp", "ISP / ILL link the public IP sits on"), *_FLOW],
    "mx04": [("dst_nat", "Public IP of the one-to-one NAT"), ("dst", "Inside IP it is translated to (all ports)"), ("isp", None)],
    "mx05": [("src", "Partner / NNI / roaming range"), ("dst", "Our inside IP the partner reaches"), ("src_zone", "Partner zone (e.g. NNI-Partner)"), *_FLOW],
    "mx06": [("src", "Inside source IP / subnet"), ("dst", "Inside destination IP / subnet"), ("src_zone", None), ("dst_zone", None), *_FLOW],
    "mx07": [("dst", "The server's own public IP"), ("isp", None), *_FLOW],
    "mx08": [("dst", "Inside IP reachable from the internet"), ("src", "Allowed source (blank = Any)"), ("src_zone", None), *_FLOW],
    "mx09": [("src", "The partner's public IP"), ("dst", "Our inside server it reaches"), *_FLOW],
    "mx10": [("src", "The partner's public subnet / range"), ("dst", "Our inside server it reaches"), *_FLOW],
    "mx11": [("src", "The public IP (one per row)"), ("isp", "ISP / ILL link it sits on")],
    "mx12": [("src", "Inside host going out"), ("dst", "Internet destination (not ours, never listed)"), *_FLOW],
    "mx13": [("src", "Source of the denied flow"), ("dst", "Inside destination of the denied flow"), ("dst_nat", "Public IP of the denied flow"),
             ("action", "Deny / Drop (blank = Deny)"), *_FLOW],
    "mx14": [("src", "Source of the expired flow"), ("dst", "Inside destination of the expired flow"), ("dst_nat", "Public IP of the expired flow"),
             *_FLOW],
}
_LABEL = {"src": "Source IP / Subnet", "src_nat": "Source NAT / Outside IP (public)", "dst_nat": "Destination Public / NAT IP",
          "dst": "Destination IP / Subnet"}


def pattern_fields(stype):
    """[(key, label, description)] for a pattern sheet, or None for the older sheet types (every field)."""
    spec = PATTERN_FIELDS.get(stype)
    if not spec:
        return None
    labels = {k: l for k, l, _ in FIELDS}
    out, seen = [], set()
    for item in [*spec, *_INFO]:
        k, d, lab = (tuple(item) + (None, None))[:3] if isinstance(item, tuple) else (item, None, None)
        if k not in seen:
            seen.add(k)
            out.append((k, lab or _LABEL.get(k) or labels[k], d or FIELD_DESC.get(k, "")))
    return out


# Older sheet types: rows uploaded before the patterns keep these (and the demo data uses them)
SHEET_TYPES = {
    "rules": {"label": "Firewall rules (mixed)", "need": _ANY_ADDR, "hint": ""},
    "public_pool": {"label": "Public IP pool", "need": [["dst_nat"]], "hint": ""},
    "nat_map": {"label": "NAT list (public ↔ private)", "need": [["dst_nat"], ["dst"]], "hint": ""},
    "sod_nat": {"label": "SOD NAT", "need": [["dst", "dst_nat"]], "hint": ""},
    "exposure": {"label": "Exposure register", "need": [["dst_nat", "dst"]], "hint": ""},
    **{k: {"label": p[0], "need": p[2], "hint": p[1]} for k, p in PATTERNS.items()},
}
LIST_TYPES = ("public_pool", "nat_map", "sod_nat", "exposure")  # older list sheets: any public IP on them is internet-facing
# per sheet type, aliases that win over the generic ones (e.g. "Destination IP" on a register is a second internal address)
TYPE_ALIASES = {
    "nat_map": {"dst_nat": ["publicip", "publicippool", "public"], "dst": ["privateip", "private", "internalip"]},
    "exposure": {"dst_nat": ["publicip"], "dst": ["internalip", "privateip"], "src": ["destinationip"]},
    "sod_nat": {"dst_nat": ["destnatip"], "src_nat": ["natip"], "dst": ["destinationip"], "src": ["sourceip"]},
    "public_pool": {"dst_nat": ["publicippool", "publicip", "publicips", "pool"]},
    "register": {"dst_nat": ["publicip"], "dst": ["internalip", "privateip"], "src": ["destinationip"], "ports": ["port"],
                 "service": ["servicedetails"], "remarks": ["remark"]},
    "snat": {"src": ["sourceip"], "dst": ["destinationip"], "ports": ["portprotocol", "protocolport", "port"],
             "src_nat": ["sourcenattedip", "sourcenatedip", "sourcenatip", "nattedip", "natip"]},
    "fwpolicy": {"fw_rule": ["rulename"], "src": ["sourceipobject", "sourceip", "sourceobject"],
                 "dst": ["destinationipobject", "destinationip", "destinationobject"], "ports": ["port"], "name": ["natrule"],
                 "src_nat": ["nattranslatedip", "translatedip"], "x_logging": ["logging", "log"], "x_vpn": ["vpnpeer", "vpn"],
                 "x_nexthop": ["routenexthop", "nexthop"]},
    "sod": {"cr": ["soddetails"], "dst_nat": ["destnatip"], "dst": ["destinationip"], "firewall": ["fwl"], "location": ["location"],
            "src_nat": ["natip"], "ports": ["port"], "protocol": ["protocol"], "rule_id": ["rule"], "src": ["sourceip"]},
}


OFFERED = ("zones", "pubpriv", "pubonly", "register", "snat", "sod", "fwpolicy")  # sheet types in the upload dropdown
NOTE_LABELS = {"x_logging": "Logging", "x_vpn": "VPN peer", "x_nexthop": "Next hop"}  # columns kept in the remarks


def guess_type(headers, sheet=""):
    """Sheet type from the columns: only a public IP -> Only public IP; public + private IP and no source / zone / ISP -> Public IP +
    private IP; anything else (source, zones, ISP) -> Firewall rules. Public IP + Internal IP columns -> the register."""
    n = {_norm(h) for h in headers}
    if "publicip" in n and "internalip" in n:
        return "register"
    if "nattranslatedip" in n or "sourceipobject" in n or "destinationipobject" in n:
        return "fwpolicy"
    if "soddetails" in n or ("destnatip" in n and "natip" in n):
        return "sod"
    if "sourcenattedip" in n or "sourcenatedip" in n:
        return "snat"
    has = set(suggest_mapping(headers, "rules"))
    rulish = has & {"src", "src_nat", "direction", "action"}
    if "dst_nat" in has and "dst" not in has and not rulish:
        return "pubonly"
    if "dst_nat" in has and "dst" in has and not rulish:
        return "pubpriv"
    return "zones"


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
        for alias in [*(_norm(n) for n in custom.get(f, [])), *over.get(f, []), *ALIASES.get(f, [])]:  # x_ keys: notes of one type
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
    # traffic going OUT to the internet is never inbound, whatever the source zone / ISP column says
    if re.match(r"^\s*out", r["direction"] or "", re.I) or INTERNET_ZONE.search(r.get("dst_zone") or ""):
        return False
    d_any, d_nets = endpoints(r["dst"])
    if d_any and not parse_addresses(r.get("dst_nat") or "")[1]:  # destination Any: not one of our hosts
        return False
    s_any, s_nets = endpoints(r["src"])
    if (any(is_public(str(n.network_address)) for n in parse_addresses(r.get("dst_nat") or "")[1])
            and any(_is_private(n) for n in d_nets) and not any(_is_private(n) for n in s_nets)):
        return True  # a public NAT IP in front of our private destination, reached from outside: a published service
    if re.match(r"^\s*in", r["direction"] or "", re.I) and (INTERNET_ZONE.search(r["src_zone"] or "") or r["isp"]):
        return True
    if INTERNET_ZONE.search(r["src_zone"] or "") or r["isp"]:
        return True
    anyv, nets = endpoints(r["src"])
    if anyv:
        return True
    return any(n.num_addresses == 1 and is_public(str(n.network_address)) for n in nets)


RULE_TYPES = ("rules", "zones", "fwpolicy")  # sheet types whose rows are judged one by one (zones / ISP / source)


def fix_nat_side(r):
    """A NAT IP in the source-NAT column on a row whose source is NOT ours (a public IP / Any) and whose destination is our
    private IP is the destination's public NAT (inbound DNAT), not a source NAT: a real source NAT always has a private
    source. Moves it to dst_nat in place; True when moved."""
    from .registry import is_public
    s_any, s_nets, _ = parse_addresses(r.get("src") or "")
    if r.get("dst_nat") or any(_is_private(n) for n in s_nets):
        return False
    nat = [n for n in parse_addresses(r.get("src_nat") or "")[1] if n.num_addresses == 1 and is_public(str(n.network_address))]
    if not nat or not any(_is_private(n) for n in parse_addresses(r.get("dst") or "")[1]):
        return False
    r["dst_nat"], r["src_nat"] = r["src_nat"], ""
    return True


def reclassify(c):
    """Re-judge stored firewall-rule rows with the current is_inbound_internet (rows uploaded under older logic), keeping
    manual marks. Every consumer (exposure, data fabric, ontology, threats, Asset 360) reads inbound_internet."""
    moved = []
    for r in db.rows(c, """SELECT id, src, src_nat, dst, dst_nat, direction, sheet_type FROM comm_rules
                          WHERE COALESCE(src_nat,'')<>'' AND COALESCE(dst_nat,'')=''"""):
        if fix_nat_side(r):
            pat = PATTERNS.get(r["sheet_type"] or "")
            d = "Inbound" if pat and r["direction"] == pat[5].get("direction") == "Outbound" else r["direction"]  # sheet default only
            moved.append((r["dst_nat"], d, r["id"]))
    if moved:
        c.executemany("UPDATE comm_rules SET dst_nat=?, src_nat='', direction=? WHERE id=?", moved)
    upd = []
    ids = {m[-1] for m in moved}
    for r in db.rows(c, f"""SELECT * FROM comm_rules WHERE COALESCE(sheet_type,'rules') IN ({','.join('?' * len(RULE_TYPES))})""", RULE_TYPES):
        v = 1 if is_inbound_internet(r) else 0
        if v != r["inbound_auto"]:
            upd.append((v, r["id"]))
    if ids:  # rows whose NAT moved to the destination are published services, whatever their sheet type
        for r in db.rows(c, f"SELECT * FROM comm_rules WHERE id IN ({','.join('?' * len(ids))})", list(ids)):
            if (r["sheet_type"] or "rules") not in RULE_TYPES:
                upd.append((1 if is_inbound_internet(r) else 0, r["id"]))
    if upd or moved:
        c.executemany("UPDATE comm_rules SET inbound_auto=? WHERE id=?", upd)
        apply_overrides(c)
    return len(upd) + len(moved)


def matrix_owned(rules):
    """Which public IPs of the matrix are OURS.
    natted: a public IP translated to / from one of our private IPs in the same row (destination NAT / source NAT). It belongs
            to that private asset (shown as its public IP), it is not an asset of its own.
    direct: a public IP an internet-facing row reaches with no private IP behind it (directly on the ISP link). An asset.
    Any other public IP in the matrix (internet destinations, partner sources, VPN peers) is not ours."""
    from .registry import is_public

    def singles(text):
        return [str(n.network_address) for n in parse_addresses(text)[1] if n.num_addresses == 1]
    natted, direct = set(), set()
    for r in rules:
        for a, b in (("dst", "dst_nat"), ("src", "src_nat")):
            na, nb = parse_addresses(r[a])[1], parse_addresses(r[b])[1]
            if na and nb:
                if any(_is_private(n) for n in na):
                    natted |= {str(n.network_address) for n in nb if n.num_addresses == 1 and not _is_private(n)}
                if any(_is_private(n) for n in nb):
                    natted |= {str(n.network_address) for n in na if n.num_addresses == 1 and not _is_private(n)}
        if r["inbound_internet"] and not any(_is_private(n) for n in parse_addresses(r["dst"])[1]):
            direct |= {ip for ip in singles(r["dst"]) + singles(r["dst_nat"]) if is_public(ip)}
        if r.get("sheet_type") == "mx11" and not r["dst"] and not r["dst_nat"]:  # public IPs listed in the source column
            direct |= {ip for ip in singles(r["src"]) if is_public(ip)}
    return natted, direct - natted


def internet_without_nat(r, our_public=frozenset()):
    """A private source let out to the internet by the firewall with no public NAT IP in the row: allowed, not inbound, no
    public source NAT, and the destination is the internet (an internet zone, a public IP that is not ours, or Any with no
    internal destination zone)."""
    from .registry import is_public
    if r["inbound_internet"] or (r["action"] or "allow").strip().lower() not in ("allow", "permit", "accept", "yes", ""):
        return False
    if any(is_public(str(n.network_address)) for n in parse_addresses(r["src_nat"])[1]):
        return False
    d_any, d_nets, _ = parse_addresses(r["dst"])
    zone = r.get("dst_zone") or ""
    if INTERNET_ZONE.search(zone):
        return True
    if any(not _is_private(n) and str(n.network_address) not in our_public for n in d_nets):
        return True
    return bool(d_any and not zone)


def active(r, now):
    return not r["valid_till"] or r["valid_till"] >= now


def build(parsed, mapping, stype="rules", workbook="", sheet=""):
    st = SHEET_TYPES.get(stype) or SHEET_TYPES["rules"]
    pf = pattern_fields(stype)
    if pf:  # a pattern sheet reads only its own fields
        mapping = {k: v for k, v in mapping.items() if k in {f for f, _, _ in pf}}
    for group in st["need"]:
        if not any(mapping.get(k) for k in group):
            raise ValueError(f"{st['label']}: map " + " or ".join(dict((a, b) for a, b, _ in FIELDS)[k] for k in group))
    idx = {h: i for i, h in enumerate(parsed["headers"])}
    out, warnings, bad, seen = [], [], 0, set()
    tag = (sheet or "")[:12]
    pat = PATTERNS.get(stype)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    def cell(r, h):  # rows can be shorter than the header row (trailing empty cells)
        i = idx.get(h)
        return str(r[i] if i is not None and i < len(r) and r[i] is not None else "").strip()
    for n, r in enumerate(parsed["rows"], start=1):
        v = {k: cell(r, mapping.get(k)) for k in KEYS}
        notes = [f"{NOTE_LABELS.get(k, k)}: {cell(r, h)}" for k, h in mapping.items() if k.startswith("x_") and cell(r, h)]
        if notes:  # columns with no field of their own (Logging, VPN Peer, Route Next Hop) are kept in the remarks
            v["remarks"] = " · ".join([v["remarks"], *notes] if v["remarks"] else notes)
        if stype == "fwpolicy" and v["src_nat"]:  # NAT Translated IP: which side it belongs to depends on the rule's direction
            from .registry import is_public
            t = v["src_nat"]
            if is_inbound_internet(v):  # inbound: public destination -> translated inside server (or the translated IP is the public one)
                if any(is_public(str(x.network_address)) for x in parse_addresses(t)[1]):
                    v["dst_nat"] = t
                else:
                    v["dst_nat"], v["dst"] = v["dst"], t
                v["src_nat"] = ""
            # outbound: the translated IP is the public address the source leaves as (stays in src_nat)
        if pat:  # the sheet's pattern decides for every row
            for k in pat[4]:
                v[k] = ""
            for k, d in pat[5].items():
                v[k] = v[k] or d
            if stype == "register" and v["src"]:  # Destination IP: a second internal address behind the public IP
                v["dst"] = ", ".join(x for x in (v["dst"], v["src"]) if x)
            if stype == "register":
                v["src"] = "Any"
            if stype == "mx14" and not (v["valid_till"] and (db.parse_ts(v["valid_till"]) or v["valid_till"])[:10] < today):
                v["valid_till"] = "1970-01-01"
        nat_moved = fix_nat_side(v)
        if nat_moved and pat and v["direction"] == pat[5].get("direction") == "Outbound":  # the sheet's default, not the row's
            v["direction"] = "Inbound"
        d_any, d_nets, d_names = parse_addresses(v["dst"])
        p_any, p_nets, _ = parse_addresses(v["dst_nat"])
        s_any, s_nets, s_names = parse_addresses(v["src"])
        if not (d_any or d_nets or d_names or p_nets or s_nets or s_names or s_any):
            bad += 1
            continue
        rid = v["rule_id"] or f"row-{n}"
        if stype in LIST_TYPES or rid in seen:
            rid = f"{tag}:{rid}" if stype in LIST_TYPES and tag else rid
        if rid in seen:
            rid = f"{rid}#{n}"
        seen.add(rid)
        v["rule_id"] = rid
        v["dst_nat"] = ", ".join(str(x.network_address) if x.num_addresses == 1 else str(x) for x in p_nets) or v["dst_nat"]
        v["valid_till"] = (db.parse_ts(v["valid_till"]) or v["valid_till"])[:10]
        v["protocol"] = v["protocol"].lower()
        if pat:
            v["inbound_internet"] = pat[3] if pat[3] is not None and not nat_moved else (1 if is_inbound_internet(v) else 0)
            if stype == "sod":  # a public dest_nat_ip (or a public destination_ip on a row without nat_ip): published to the internet;
                from .registry import is_public  # on a source-NAT row the destination is the far end, not ours
                pub = lambda nets: any(is_public(str(x.network_address)) for x in nets)
                if pub(p_nets) or (pub(d_nets) and not v["src_nat"]):
                    v["inbound_internet"] = 1
        elif stype == "rules":
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
        self.nat, self.snat = {}, {}
        for i, r in enumerate(rules):
            for side, text in (("src", r["src"]), ("dst", r["dst"])):
                for n in endpoints(text)[1]:
                    self.nets[side].setdefault((n.version, n.prefixlen), {}).setdefault(int(n.network_address), set()).add(i)
            for ip in db.all_ips(r["dst_nat"]):
                self.nat.setdefault(ip, set()).add(i)
            for ip in db.all_ips(r["src_nat"]):  # the public IP a source leaves as: its rows belong to that IP too
                self.snat.setdefault(ip, set()).add(i)

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
        for ip in ips:
            src |= self.snat.get(ip, set())
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
    t = stype or guess_type(parsed["headers"], parsed["sheet"])
    mapping = suggest_mapping(parsed["headers"], t)
    pf = pattern_fields(t)
    if pf:  # only the fields this pattern reads
        mapping = {k: v for k, v in mapping.items() if k in {f for f, _, _ in pf}}
    return {"sheet": parsed["sheet"], "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:5], "type": t, "mapping": mapping, "filename": parsed["filename"],
            "sheets": parsed["sheets"]}


def _fields():
    return [{"key": k, "label": l, "required": r} for k, l, r in FIELDS]


def _types():
    return [{"id": k, "label": SHEET_TYPES[k]["label"], "hint": SHEET_TYPES[k]["hint"], "need": SHEET_TYPES[k]["need"],
             "fields": [{"key": f, "label": l, "desc": d} for f, l, d in pattern_fields(k)]} for k in OFFERED]


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
        need = (SHEET_TYPES.get(info["type"]) or SHEET_TYPES["rules"])["need"]
        # guide sheets (Which sheet to use, How to fill) have no address column: left out unless picked by hand
        info["include"] = info["row_count"] > 0 and all(any(info["mapping"].get(k) for k in g) for g in need)
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
    if db.multi(p, "sheet"):
        s, v = db.in_clause("sheet", db.multi(p, "sheet"))
        w.append(s)
        params += v
    if p.get("manual") == "1":
        w.append("inbound_auto IS NOT NULL AND inbound_internet<>inbound_auto")
    if db.multi(p, "firewall"):
        s, v = db.in_clause("firewall", db.multi(p, "firewall"))
        w.append(s)
        params += v
    if p.get("direction"):
        w.append("direction LIKE ?")
        params.append(p["direction"] + "%")
    q = (p.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        w.append("""(rule_id LIKE ? OR src LIKE ? OR dst LIKE ? OR dst_nat LIKE ? OR src_nat LIKE ? OR firewall LIKE ? OR fw_rule LIKE ? OR service LIKE ?
                  OR ports LIKE ? OR cr LIKE ? OR name LIKE ? OR application LIKE ? OR app_owner LIKE ?)""")
        params += [like] * 13
    if db.multi(p, "sheet_type"):
        s, v = db.in_clause("sheet_type", db.multi(p, "sheet_type"))
        w.append(s)
        params += v
    if db.multi(p, "workbook"):
        s, v = db.in_clause("workbook", db.multi(p, "workbook"))
        w.append(s)
        params += v
    return ("WHERE " + " AND ".join(w)) if w else "", params


@router.get("/api/comm/rules")
def comm_rules(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
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


def vip_map(rules):
    """{private NAT / VIP IP: {backend private IPs}}. A private IP in the destination-NAT column of a row that also names a
    private backend destination is a translation layer (load-balancer VIP, firewall NAT), not a host: public 202.x -> VIP
    10.4.x -> server 10.1.x. Rows can chain (202.x -> VIP in one row, VIP -> server in another)."""
    out = {}
    for r in rules:
        nat_priv = [str(n.network_address) for n in parse_addresses(r["dst_nat"])[1] if n.num_addresses == 1 and _is_private(n)]
        if not nat_priv:
            continue
        backs = [str(n.network_address) for n in parse_addresses(r["dst"])[1] if n.num_addresses == 1 and _is_private(n)]
        for v in nat_priv:
            for b in backs:
                if b != v:
                    out.setdefault(v, set()).add(b)
    return out


def resolve_vips(ips, vmap):
    """The real hosts behind addresses: a VIP is replaced by its backends (following chains), any other IP stays."""
    out, seen, todo = [], set(), list(ips)
    while todo:
        ip = todo.pop(0)
        if ip in seen:
            continue
        seen.add(ip)
        if ip in vmap:
            todo += sorted(vmap[ip])
        else:
            out.append(ip)
    return out


def matrix_pairs(rules):
    """(pub_of, priv_of): private IP -> its public / NAT IPs and back, from every NAT pair of the matrix rows (destination <->
    destination NAT, source <-> source NAT, same row)."""
    pub_of, priv_of = {}, {}
    for r in rules:
        for a, b in (("dst", "dst_nat"), ("src", "src_nat")):
            na = [n for n in parse_addresses(r[a])[1] if n.num_addresses == 1]
            nb = [n for n in parse_addresses(r[b])[1] if n.num_addresses == 1]
            for x in na:
                for y in nb:
                    if _is_private(x) and not _is_private(y):
                        priv, pub = str(x.network_address), str(y.network_address)
                    elif _is_private(y) and not _is_private(x):
                        priv, pub = str(y.network_address), str(x.network_address)
                    else:
                        continue
                    pub_of.setdefault(priv, set()).add(pub)
                    priv_of.setdefault(pub, set()).add(priv)
    vmap = vip_map(rules)
    for vip in [v for v in pub_of if v in vmap]:  # public -> VIP -> server: the public IP is the server's
        pubs = pub_of.pop(vip)
        for b in resolve_vips([vip], vmap):
            pub_of.setdefault(b, set()).update(pubs)
        for p in pubs:
            priv_of[p] = (priv_of.get(p, set()) - {vip}) | set(resolve_vips([vip], vmap))
    return pub_of, priv_of


def matrix_ips(c):
    # rebuilt only when what it is made of changes (the matrix rows, the asset registry, enterprise marks, your ranges / ASNs),
    # not on every write anywhere: at 1 lakh assets it takes seconds, and syncs / background jobs write all the time
    from .registry import VERSION as REG_VERSION
    from .surface import ASNS_KEY, RANGES_KEY
    key = (REG_VERSION[0],
           tuple(c.execute("""SELECT COUNT(*), COALESCE(MAX(id),0), COALESCE(SUM(inbound_internet),0),
                              COALESCE(SUM(LENGTH(rule_id)),0) FROM comm_rules""").fetchone()),
           tuple(c.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(ip) + LENGTH(class)),0) FROM ip_class").fetchone()),
           c.execute("SELECT GROUP_CONCAT(value, '|') FROM settings WHERE key IN (?, ?)", (RANGES_KEY, ASNS_KEY)).fetchone()[0],
           tuple(c.execute("SELECT COUNT(*), MAX(fetched_at) FROM asn_prefixes").fetchone()))
    if _IPS_CACHE.get("key") == key:
        return _IPS_CACHE["rows"]
    from .registry import is_public
    import bisect
    reg = {r["ip"]: r for r in db.rows(c, """SELECT ip, name, lobs, in_inventory, in_edr, in_scan, in_niam, edr_status, exposed, nat_of,
                                              public_ips FROM asset_registry WHERE ip IS NOT NULL""")}
    names = {}
    for ip, r in reg.items():
        for n in (r["name"] or "").split(", "):
            if n:
                names.setdefault(db.norm_hostname(n), []).append(ip)
    def _num(ip):  # inventory IP cells can hold typos / text ("NOT IN USE", #REF!): those cannot sit in a subnet
        try:
            return db.ip_to_num(ip)
        except ValueError:
            return None
    v4 = sorted((n, ip) for ip in reg if ":" not in ip for n in [_num(ip)] if n is not None)
    v4n = [n for n, _ in v4]
    rules = load_rules(c)
    # Our assets are private (10.x, 172.16-31.x, 192.168.x …). A public IP is ours when the matrix translates it to / from one of
    # those private IPs in the same rule (destination ↔ translated destination, source ↔ translated source), when it is in your
    # public ranges or your ASNs' advertised prefixes, when you marked it enterprise, or when inventory / VA / NIAM has it.
    natted, direct = matrix_owned(rules)
    our_public = natted | direct
    vmap = vip_map(rules)
    # private IP <-> its public / NAT IPs: the matrix NAT pairs, plus inventory NAT columns
    pub_of, priv_of = matrix_pairs(rules)
    for ip, rr in reg.items():
        for p in (rr.get("public_ips") or "").split(", "):
            if p and p != ip and is_public(p) and not is_public(ip):
                pub_of.setdefault(ip, set()).add(p)
                priv_of.setdefault(p, set()).add(ip)
    from .surface import ASNS_KEY, RANGES_KEY, _setting_list
    from .registry import _nets
    our_nets = [n for e in _setting_list(c, RANGES_KEY) for n in _nets(e.get("value"))]
    asns = _setting_list(c, ASNS_KEY)
    if asns:
        for p in db.rows(c, f"SELECT prefix FROM asn_prefixes WHERE asn IN ({','.join('?' * len(asns))})", asns):
            try:
                our_nets.append(ipaddress.ip_network(p["prefix"]))
            except ValueError:
                pass
    marks = {r[0]: r[1] for r in c.execute("SELECT ip, class FROM ip_class")}

    def in_ours(n):
        return any(n.version == o.version and n.subnet_of(o) for o in our_nets)
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
    for pub in [k for k, e in ent.items() if e["kind"] == "ip" and k in priv_of and marks.get(k) != "non-enterprise"]:
        privs = [p for p in priv_of[pub] if p in ent]
        if not privs:
            continue
        e = ent.pop(pub)
        for p in privs:
            t = ent[p]
            t["roles"] |= {"public" if r in ("public", "exposed") else r for r in e["roles"]} - {"internal", "internet_src", "outbound"}
            for f in ("rules", "sheets", "apps", "owners", "ports"):
                t[f] |= e[f]
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
            mark = marks.get(e["address"])
            if _is_private(n):
                ours, why = True, "private address (our network)"
            elif mark == "non-enterprise":
                ours, why = False, "marked non-enterprise"
            elif mark == "enterprise":
                ours, why = True, "marked enterprise"
            elif e["address"] in natted:
                ours, why = True, "NAT of one of our private IPs in the matrix"
            elif e["address"] in direct:
                ours, why = True, "public IP directly on the internet (no private IP behind it)"
            elif in_ours(n):
                ours, why = True, "inside your public ranges / your ASNs' prefixes"
            elif "exposed" in e["roles"] or {"public", "public_src"} & e["roles"]:
                why = "public IP in our rules, but not NATed to a private IP and not in your ranges: check it (mark enterprise if it is ours)"
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
               else "unknown" if not ours and (e["kind"] == "name" or why.startswith("public IP in our rules")) else "external" if not ours else "internal")
        addr = e["address"][5:] if e["kind"] == "name" else e["address"]
        if e["kind"] == "ip" and _is_private(n) and addr in vmap:  # NAT / VIP: a translation layer, not a host
            private_ip, public_ip, akind = addr, ", ".join(sorted(pub_of.get(addr, ()))), "vip"
            why = f"NAT / VIP in front of {', '.join(resolve_vips([addr], vmap)[:4])} (not a host)"
            cat = "internal"
        elif e["kind"] == "ip" and _is_private(n):
            private_ip, public_ip = addr, ", ".join(sorted(pub_of.get(addr, ())))
            akind = "private_public" if public_ip else "private_only"
        elif e["kind"] == "ip":
            private_ip, public_ip = ", ".join(sorted(priv_of.get(addr, ()))), addr
            akind = "public_only" if ours else "external"
        else:
            private_ip, public_ip, akind = addr, "", e["kind"]
        out.append({"address": addr, "private_ip": private_ip, "public_ip": public_ip, "asset_kind": akind,
                    "asset_kind_text": ASSET_KIND.get(akind, akind), "kind": e["kind"], "ours": ours, "why": why,
                    "category": cat, "roles": sorted(roles), "rules": len(e["rules"]), "rule_ids": ", ".join(sorted(e["rules"])[:6]),
                    "sheets": ", ".join(sorted(e["sheets"])), "applications": ", ".join(sorted(e["apps"]))[:200],
                    "owners": ", ".join(sorted(e["owners"]))[:200], "ports": ", ".join(sorted(e["ports"]))[:120], **m,
                    "num": int(n.network_address) if n is not None and n.version == 4 else 0})
    out.sort(key=lambda x: ({"exposed": 0, "outbound": 1, "unknown": 2, "internal": 3, "external": 4}[x["category"]], x["kind"] != "ip", x["num"]))
    _IPS_CACHE.update(key=key, rows=out)
    return out


ASSET_KIND = {"vip": "NAT / VIP (translation layer, not a host)", "private_public": "Private + public / NAT IP", "private_only": "Private IP only", "public_only": "Public IP only (ours, no private IP)",
              "external": "Public IP, not ours", "subnet": "Subnet / range", "name": "Host / object name"}


def _ips_filter(p, rows):
    v = p.get("view") or "exposed"
    if v == "exposed":
        rows = [r for r in rows if r["category"] == "exposed"]
    elif v == "outbound":
        rows = [r for r in rows if r["category"] == "outbound" or ("outbound" in r["roles"] and r["ours"])]
    elif v == "public":
        rows = [r for r in rows if r["ours"] and ({"public", "public_src"} & set(r["roles"]) or (r["kind"] == "ip" and r["why"].startswith(("NAT of", "inside your", "marked enterprise"))))]
    elif v == "not_inventory":
        rows = [r for r in rows if r["ours"] and r["category"] in ("exposed", "outbound") and not r["in_inventory"]]
    elif v == "external":
        rows = [r for r in rows if r["category"] == "external"]
    elif v == "unknown":
        rows = [r for r in rows if r["category"] == "unknown"]
    q = (p.get("q") or "").strip().lower()
    if q:
        rows = [r for r in rows if q in f"{r['address']} {r['private_ip']} {r['public_ip']} {r['name'] or ''} {r['applications']} {r['owners']} {r['sheets']} {r['rule_ids']} {r['lobs'] or ''}".lower()]
    if p.get("kind"):
        rows = [r for r in rows if r["kind"] in db.multi(p, "kind")]
    if p.get("asset_kind"):
        rows = [r for r in rows if r["asset_kind"] in db.multi(p, "asset_kind")]
    return rows


@router.get("/api/comm/ips")
def comm_ips(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    with db.get_conn() as c:
        allr = matrix_ips(c)
    rows = _ips_filter(p, allr)
    cnt = lambda f: sum(1 for r in allr if f(r))  # noqa: E731
    counts = {"exposed": cnt(lambda r: r["category"] == "exposed"), "outbound": cnt(lambda r: r["category"] == "outbound" or ("outbound" in r["roles"] and r["ours"])),
              "public": cnt(lambda r: {"public", "public_src"} & set(r["roles"])),
              "not_inventory": cnt(lambda r: r["ours"] and r["category"] in ("exposed", "outbound") and not r["in_inventory"]),
              "external": cnt(lambda r: r["category"] == "external"), "unknown": cnt(lambda r: r["category"] == "unknown"), "all": len(allr),
              **{"kind_" + k: cnt(lambda r, k=k: r["asset_kind"] == k) for k in ASSET_KIND}}
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size], "counts": counts}


IPS_EXPORT = [("private_ip", "Private IP"), ("public_ip", "Public / NAT IP"), ("asset_kind_text", "Asset type"), ("address", "Address"), ("kind", "Kind"), ("category", "Category"), ("ours_text", "Ours"), ("why", "Why ours"), ("roles_text", "Roles"),
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
    return xlsx_response([("Matrix assets", IPS_EXPORT, rows)], "matrix_asset_register")



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
# Every column is a mappable field (no extra columns). Each sample row's Remarks says whether the console counts it as internet exposed.
UNIFIED_HEADERS = ["Rule ID", "Direction", "Source Zone", "Source IP / Subnet (inside)", "Source NAT / Outside IP (public)", "ISP / Link",
                   "Destination Zone", "Destination Public / NAT IP", "Destination IP / Subnet (inside)", "Protocol", "Port(s)", "Service / Use",
                   "Application", "Application Owner", "LOB", "MS Partner", "Domain", "Location / DC", "Firewall", "Firewall Rule Name", "Action",
                   "Change / SOD No.", "Valid Till", "Remarks"]
UNIFIED_ROWS = [
    # rule, direction, src zone, src inside, src NAT (public), ISP, dst zone, dst public / NAT, dst inside, proto, ports, service, application,
    # owner, LOB, MSP, domain, location, firewall, fw rule, action, CR / SOD, valid till, remarks
    ["MX-0001", "Inbound", "Internet", "Any", "", "Airtel ILL-01", "DMZ", "49.36.10.21", "10.10.4.21", "tcp", "443, 8443",
     "Customer self-care portal", "Self-care", "Digital Channels", "Retail Banking", "Wipro", "Digital", "DC-Mumbai", "DMZ-FW-01",
     "allow-https-selfcare", "Allow", "SOD-2026-0931", "",
     "EXPOSED - public + private (destination NAT): 49.36.10.21 and 10.10.4.21 both listed and linked. One public / private pair per row."],
    ["MX-0002", "Outbound", "OAM", "10.30.8.15", "49.36.10.30", "Jio ILL-02", "Internet", "", "Any", "tcp", "443",
     "Vendor patch download", "OSS patching", "NetOps", "Payments", "TCS", "OAM", "DC-Delhi", "EDGE-FW-02", "oam-out-443", "Allow",
     "CR-2026-1102", "2026-12-31",
     "EXPOSED - outbound through source NAT: 10.30.8.15 leaves through the public IP 49.36.10.30, both listed and linked."],
    ["MX-0003", "Inbound", "Internet", "Any", "", "Tata ILL-07", "Edge", "49.36.10.7", "", "tcp", "22, 443",
     "Edge router management", "Edge router", "NetOps", "", "", "Core", "POP-Pune", "", "", "Allow", "", "",
     "EXPOSED - public IP only (ISP direct, no NAT): public IP in Destination Public / NAT IP, inside IP left empty."],
    ["MX-0004", "Inbound", "Internet", "Any", "", "", "DMZ", "49.36.10.40", "10.40.0.5", "any", "any",
     "Partner API gateway", "Partner API", "API team", "Enterprise", "", "API", "DC-Mumbai", "EDGE-FW-02", "static-nat-40", "Allow",
     "SOD-2026-041", "", "EXPOSED - static one-to-one NAT, all ports: same result as MX-0001."],
    ["MX-0005", "Inbound", "NNI-Partner", "100.70.0.0/16", "", "", "Core", "", "10.50.1.10", "udp", "2152",
     "GTP-U roaming", "Packet core", "Core Ops", "", "", "Packet core", "DC-Chennai", "CORE-FW-01", "nni-gtpu", "Allow", "CR-2026-1150", "",
     "NOT EXPOSED directly - partner / NNI link. Add 100.70.0.0/16 under Internet exposed > Indirect ranges."],
    ["MX-0006", "Internal", "APP", "10.20.0.0/24", "", "", "DB", "", "10.20.1.10-20", "tcp", "1521", "App to database",
     "Billing", "Billing team", "Payments", "Wipro", "Billing", "DC-Mumbai", "CORE-FW-01", "app-db-1521", "Allow", "CR-2026-1200", "",
     "NOT EXPOSED - internal east-west flow."],
    ["MX-0007", "Inbound", "Internet", "Any", "", "", "DMZ", "", "49.36.10.50", "tcp", "443",
     "Public web server", "Corporate site", "Web team", "Enterprise", "", "Web", "DC-Mumbai", "DMZ-FW-01", "allow-web-50", "Allow", "", "",
     "EXPOSED - server owns a public IP, written in the inside column (no NAT): same result as MX-0003."],
    ["MX-0008", "Inbound", "Untrust", "Any", "", "", "DMZ", "", "10.10.5.30", "tcp", "8443",
     "Vendor support portal", "Support portal", "IT Ops", "Enterprise", "Wipro", "IT", "DC-Mumbai", "DMZ-FW-01", "allow-8443", "Allow", "", "",
     "EXPOSED - inbound from the internet to a private IP whose public IP is not known: listed as private, exposed by rule."],
    ["MX-0009", "Inbound", "Partner", "203.0.113.50", "", "", "DMZ", "", "10.40.0.6", "tcp", "443",
     "Partner settlement API", "Settlement", "API team", "Payments", "", "API", "DC-Mumbai", "EDGE-FW-02", "partner-in-443", "Allow", "", "",
     "EXPOSED - one public source IP (a partner) to an internal server. The partner IP itself is not listed as our asset."],
    ["MX-0010", "Inbound", "External", "203.0.113.0/24", "", "", "DMZ", "", "10.40.0.7", "tcp", "443",
     "Partner range to API", "Settlement", "API team", "Payments", "", "API", "DC-Mumbai", "EDGE-FW-02", "partner-range-443", "Allow", "", "",
     "EXPOSED - a partner public subnet / range allowed in to an internal server. The partner range is not listed as ours."],
    ["MX-0011", "", "", "49.36.10.9", "", "", "", "", "", "", "", "Public IP register entry", "Mail relay", "IT Messaging", "", "", "",
     "", "", "", "", "", "",
     "EXPOSED - a public IP alone in the source column (no destination, no NAT) is read as a public IP directly on the ISP link."],
    ["MX-0012", "Outbound", "Trust", "10.20.0.15", "", "", "Internet", "", "8.8.8.8", "udp", "53", "DNS forwarding",
     "DNS", "NetOps", "", "", "Core", "DC-Mumbai", "CORE-FW-01", "dns-out", "Allow", "", "",
     "NOT EXPOSED - outbound to an internet IP without NAT. 8.8.8.8 is not ours and is never listed. "
     "Use an MX-0002 sheet when the source leaves through a public NAT IP."],
    ["MX-0013", "Inbound", "Internet", "Any", "", "Airtel ILL-01", "DMZ", "49.36.10.60", "10.10.6.10", "tcp", "3389",
     "Blocked RDP", "Legacy app", "IT Ops", "", "", "", "DC-Mumbai", "DMZ-FW-01", "deny-rdp", "Deny", "", "",
     "NOT EXPOSED - Action Deny / Drop is never internet-facing."],
    ["MX-0014", "Inbound", "Internet", "Any", "", "Airtel ILL-01", "DMZ", "49.36.10.70", "10.10.7.10", "tcp", "443",
     "Old campaign site", "Campaign", "Marketing", "Retail Banking", "", "Digital", "DC-Mumbai", "DMZ-FW-01", "allow-campaign", "Allow",
     "CR-2025-0400", "2025-03-31", "NOT EXPOSED - Valid Till is in the past: an expired rule is ignored."],
]
# Template: one sheet per offered type, with sample rows taken from UNIFIED_ROWS (rule id -> new remark for that sheet)
SAMPLES = {
    "zones": ("Firewall rules", [
        ("MX-0001", "EXPOSED - Source Zone Internet + ISP link: public 49.36.10.21 and private 10.10.4.21 listed and linked."),
        ("MX-0008", "EXPOSED - Source Zone Untrust, source Any: the DMZ server 10.10.5.30 is listed."),
        ("MX-0006", "NOT EXPOSED - internal zones (APP to DB), no ISP link."),
        ("MX-0013", "NOT EXPOSED - Action Deny."),
    ]),
    "pubpriv": ("Public + private IP", [
        ("MX-0001", "EXPOSED - public 49.36.10.21 and private 10.10.4.21, linked."),
        ("MX-0004", "EXPOSED - public 49.36.10.40 and private 10.40.0.5, linked."),
    ]),
    "pubonly": ("Only public IP", [
        ("MX-0003", "EXPOSED - public IP 49.36.10.7 on the ISP link."),
    ]),
}
FILL = {"zones": "Source Zone, ISP / Link, Destination Zone, Source IP, Destination IP (+ Destination Public / NAT IP if you have it)",
        "pubpriv": "Destination Public / NAT IP = the public IP, Destination IP / Subnet = the private IP",
        "pubonly": "Destination Public / NAT IP = the public IP",
        "register": "Public IP, Internal IP (+ Port, Service Details, Destination IP, REMARK)"}
REGISTER_SHEET = ("Public-Internal IP register", "register", ["Public IP", "Internal IP", "Port", "Service Details", "Destination IP", "REMARK"],
                  [["198.51.100.50", "10.40.0.5", "443/tcp, 8443", "Partner API", "10.40.0.6",
                    "EXPOSED - public 198.51.100.50 leads to 10.40.0.5 and 10.40.0.6: all listed and linked."]])
SAMPLES["register"] = (REGISTER_SHEET[0], [])
FILL["snat"] = "source_ip, Source Natted IP (+ destination_ip, Port / Protocol)"
SNAT_SHEET = ("Source NAT", "snat", ["source_ip", "destination_ip", "Port / Protocol", "Source Natted IP"],
              [["10.30.8.15", "203.0.113.80", "443/tcp", "49.36.10.30"], ["10.30.8.16", "203.0.113.80", "443/tcp", "49.36.10.30"]])
SAMPLES["snat"] = (SNAT_SHEET[0], [])
FILL["sod"] = "dest_nat_ip + destination_ip (inbound) and / or nat_ip + source_ip (outbound); SODdetails, fwl, location, port, protocol, rule"
SOD_SHEET = ("SOD NAT", "sod", ["SODdetails", "dest_nat_ip", "destination_ip", "fwl", "location", "nat_ip", "port", "protocol", "rule", "source_ip"],
             [["SOD-2026-041", "198.51.100.40", "10.30.0.10", "EDGE-FW-02", "DC-Mumbai", "", "22", "tcp", "NAT-12", "203.0.113.5"],
              ["SOD-2026-052", "", "203.0.113.80", "EDGE-FW-02", "DC-Delhi", "49.36.10.30", "443", "tcp", "NAT-13", "10.30.8.15"]])
SAMPLES["sod"] = (SOD_SHEET[0], [])
FILL["fwpolicy"] = "Rule Name, Source Zone, Source IP/Object, Destination Zone, Destination IP/Object, Action (+ NAT Translated IP, Protocol, Port)"
FWP_SHEET = ("Firewall policy", "fwpolicy",
             ["Rule Name", "Source Zone", "Source IP/Object", "Destination Zone", "Destination IP/Object", "Protocol", "Port", "Action", "Logging",
              "NAT Rule", "NAT Translated IP", "VPN Peer", "Route Next Hop", "Remarks"],
             [["allow-web-in", "Untrust", "Any", "DMZ", "49.36.10.21", "tcp", "443", "Allow", "Yes", "DNAT-21", "10.10.4.21", "", "",
               "EXPOSED - inbound: public 49.36.10.21 translated to the DMZ server 10.10.4.21, both listed and linked."],
              ["oam-out", "Trust", "10.30.8.15", "Untrust", "Any", "tcp", "443", "Allow", "No", "SNAT-30", "49.36.10.30", "", "",
               "EXPOSED - outbound: 10.30.8.15 leaves as 49.36.10.30, linked."],
              ["vpn-partner-db", "VPN", "172.16.5.0/24", "Trust", "10.20.0.10", "tcp", "1521", "Allow", "Yes", "", "", "203.0.113.9", "10.0.0.1",
               "NOT EXPOSED - partner flow over site-to-site VPN."],
              ["deny-rdp", "Untrust", "Any", "DMZ", "10.10.6.10", "tcp", "3389", "Deny", "Yes", "", "", "", "", "NOT EXPOSED - Deny rule."]])
SAMPLES["fwpolicy"] = (FWP_SHEET[0], [])


def _type_sheet(k):
    """Template sheet of a type: only the columns that type reads, with its sample rows."""
    if k == "register":  # the register's own six columns
        return REGISTER_SHEET
    if k == "snat":  # the source NAT sheet's own four columns
        return SNAT_SHEET
    if k == "sod":  # the SOD NAT sheet's own ten columns
        return SOD_SHEET
    if k == "fwpolicy":  # the firewall policy export's own fourteen columns
        return FWP_SHEET
    col = suggest_mapping(UNIFIED_HEADERS)
    pf = pattern_fields(k)
    name, samples = SAMPLES[k]
    rows = []
    for rid, remark in samples:
        row = next(r for r in UNIFIED_ROWS if r[0] == rid)
        rows.append([remark if f == "remarks" else row[UNIFIED_HEADERS.index(col[f])] for f, _, _ in pf])
    return (name, k, [_LABEL.get(f) or col[f] for f, _, _ in pf], rows)


TEMPLATE_SHEETS = [_type_sheet(k) for k in OFFERED]
CHOOSE = [(PATTERNS[k][0], PATTERNS[k][1], FILL[k], SAMPLES[k][0]) for k in OFFERED]
TEMPLATE_GUIDE = [
    ("Sheet type", "Each sheet is one of seven types: Firewall rules (Source Zone / ISP / Destination Zone), Public IP + private IP, "
                   "Only public IP, the Public IP · Internal IP register, Source NAT, SOD NAT, or Firewall policy. The type is guessed from the columns on upload and can be changed in the dropdown."),
    ("Firewall rules", "Each row is checked on its own: Source Zone Internet / ISP / Untrust / Outside / External, a filled ISP / Link, "
                       "or a source of Any or one public IP makes it internet-facing; then its destination, public / NAT IP and source NAT "
                       "IP are listed as exposed. Deny rows, expired rows and internal zones are not."),
    ("Public IP + private IP", "Every row is exposed: the public IP and the private IP behind it are both listed and linked. "
                               "No zone or ISP column is needed."),
    ("Only public IP", "Every row is exposed: the public IP is listed. No zone or ISP column is needed."),
    ("Public IP · Internal IP register", "Columns Public IP, Internal IP, Port, Service Details, Destination IP, REMARK. Every row is "
                                         "exposed: the public IP, the internal IP and the destination IP (when filled) are listed and linked."),
    ("Source NAT", "Columns source_ip, destination_ip, Port / Protocol, Source Natted IP. A row whose Source Natted IP is public exposes "
                   "its source_ip, linked to that public IP (several sources may share one). destination_ip is the far end and is not "
                   "listed as ours. A private Source Natted IP exposes nothing."),
    ("SOD NAT", "Columns SODdetails, dest_nat_ip, destination_ip, fwl, location, nat_ip, port, protocol, rule, source_ip. Each row: a "
                "public dest_nat_ip exposes destination_ip, linked to it (inbound); a public nat_ip exposes source_ip, linked to it "
                "(outbound; destination_ip is then the far end and not listed). A row can be both."),
    ("Firewall policy", "Columns Rule Name, Source Zone, Source IP/Object, Destination Zone, Destination IP/Object, Protocol, Port, Action, "
                        "Logging, NAT Rule, NAT Translated IP, VPN Peer, Route Next Hop, Remarks. Each rule: from Untrust / Internet / "
                        "Outside or a source of Any (Allow) = internet-facing. Inbound with a NAT Translated IP: the destination is the "
                        "public IP and the translated IP the inside server, both exposed and linked. Outbound with a public NAT Translated "
                        "IP: the source is exposed, linked to it. Logging, VPN Peer and Route Next Hop are kept in the remarks."),
    ("Telco", "Partner / NNI / roaming / GRX links on a Firewall rules sheet: Source Zone NNI-Partner with ISP / Link EMPTY (a filled "
              "ISP / Link makes the row internet-facing); add the partner and CGNAT ranges under Internet exposed → Indirect ranges."),
    ("Sample rows", "Delete the sample rows before uploading your own rows. Delete the sheets you do not use."),
    ("Address cells", "One IP; lists split by , ; | / space or new line; ranges 10.1.1.10-10.1.1.20 or 10.1.1.10-20; subnets 10.1.0.0/24; "
                      "last-octet shorthand 10.1.55.194/195/200; h-10.1.1.5, n-10.1.0.0/24, 10.1.1.5_nat, 10.1.1.5_vm; IPv6 2101:3900:3d5a::/48; "
                      "host / object names (matched to inventory hostnames); Any. New assets are created only from single IPs; subnets "
                      "and ranges mark IPs already known from inventory, CrowdStrike, scans or NIAM."),
    ("Port cells", "443 · 80,443 · 8000-8100 · tcp/443 · 443/tcp · tcp_8443 · udp-53 · dns_tcp · https · any."),
    ("Mark by hand", "After upload, any row can be marked internet-facing or not on the Communication matrix page; the mark is kept when "
                     "the same workbook / sheet / row is uploaded again."),
]


@router.get("/api/comm/template")
def comm_template():
    sheets = [("Which sheet to use", [("a", "Sheet type (pick on upload)"), ("b", "Use when"), ("c", "Fill these columns"), ("d", "Template sheet")],
               [dict(zip("abcd", r)) for r in CHOOSE])]
    sheets += [(name, [(f"c{i}", h) for i, h in enumerate(hd)], [{f"c{i}": v for i, v in enumerate(r)} for r in rows]) for name, _, hd, rows in TEMPLATE_SHEETS]
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
