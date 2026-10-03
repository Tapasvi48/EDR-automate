"""WHOIS of public IPs (who the address block is registered to) and enterprise / non-enterprise marks.

WHOIS comes from RDAP, the JSON successor of WHOIS, through https://rdap.org (free, no key), which forwards each IP to the
registry that holds it (APNIC, RIPE NCC, ARIN, LACNIC, AFRINIC). From the network object we keep the netname, description,
registrant organisation, country and the registered range. One answer covers the whole registered block, so IPs inside a
block already looked up are answered from the cache without asking again. Only the IP address is sent.

Marks: each public IP can be marked "enterprise" (address space the organisation owns or runs) or "non-enterprise" (ISP
pools, cloud / third-party space, customer links). They are set from the Attack surface and Internet DB scan pages, for the
selected rows or for everything a filter (WHOIS name, description, search…) matches."""
import hashlib
import ipaddress
import time

from fastapi import APIRouter, Body, HTTPException

from . import config, db

router = APIRouter()
CLASSES = ("enterprise", "non-enterprise")
RDAP = "https://rdap.org/ip/{ip}"


# ------------------------------------------------------------------ RDAP
def _vcard_fn(entity):
    for item in ((entity.get("vcardArray") or [None, []])[1] or []):
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3]).strip()
    return ""


def _org(d):
    """Registrant organisation: the registrant entity (searched one level deep), else the first entity that is not abuse."""
    ents = list(d.get("entities") or [])
    for e in list(ents):
        ents += e.get("entities") or []
    for want in (("registrant",), ("administrative", "technical")):
        for e in ents:
            if set(e.get("roles") or []) & set(want):
                fn = _vcard_fn(e)
                if fn:
                    return fn
    return ""


def _vcard(entity, field):
    out = []
    for item in ((entity.get("vcardArray") or [None, []])[1] or []):
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            v = item[3]
            if field == "adr":
                lab = (item[1] or {}).get("label") if isinstance(item[1], dict) else None
                v = lab or ", ".join(str(x) for x in (v if isinstance(v, list) else [v]) if x)
            out.append(str(v).replace("mailto:", "").replace("tel:", "").strip())
    return [x for x in out if x]


def _details(d):
    """Contacts and the rest of the registration record: emails, abuse contact, addresses, phones, every contact with its
    roles, all remarks, status, type, registration / last-changed dates, parent block."""
    ents = []

    def walk(es):
        for e in es or []:
            ents.append(e)
            walk(e.get("entities"))
    walk(d.get("entities"))
    emails, abuse, addrs, phones, contacts = [], [], [], [], []
    for e in ents:
        roles = e.get("roles") or []
        em = _vcard(e, "email")
        emails += em
        if "abuse" in roles:
            abuse += em
        addrs += _vcard(e, "adr")
        phones += _vcard(e, "tel")
        name = _vcard_fn(e) or e.get("handle") or ""
        if name:
            contacts.append(f"{name} ({', '.join(roles)})" if roles else name)
    events = {ev.get("eventAction"): (ev.get("eventDate") or "")[:10] for ev in d.get("events") or []}
    remarks = " | ".join(" ".join(r.get("description") or []) for r in d.get("remarks") or [])
    uniq = lambda xs: ", ".join(dict.fromkeys(x for x in xs if x))  # noqa: E731
    return {"emails": uniq(emails), "abuse": uniq(abuse), "address": " | ".join(dict.fromkeys(addrs))[:500], "phones": uniq(phones),
            "contacts": uniq(contacts)[:800], "remarks": remarks[:1500], "status": ", ".join(d.get("status") or []),
            "net_type": d.get("type") or "", "registered": events.get("registration", ""), "changed": events.get("last changed", ""),
            "parent": d.get("parentHandle") or ""}


def _descr(d):
    rem = d.get("remarks") or []
    pick = [r for r in rem if str(r.get("title") or "").lower() in ("description", "descr")] or rem[:1]
    return " ".join(" ".join(r.get("description") or []) for r in pick).strip()[:400]


def _cidr(d, start, end):
    c = d.get("cidr0_cidrs") or []
    if c and c[0].get("v4prefix"):
        return f"{c[0]['v4prefix']}/{c[0].get('length')}"
    try:
        nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
        return ", ".join(str(n) for n in nets[:3]) + (" …" if len(nets) > 3 else "")
    except (ValueError, TypeError):
        return ""


def rdap(ip):
    """WHOIS network of one IP: dict(handle, start_num, end_num, cidr, name, descr, org, country, rir) or raises."""
    if config.DEMO:
        return _demo(ip)
    from .surface import _s
    for attempt in range(4):
        r = _s().get(RDAP.format(ip=ip), timeout=20, headers={"Accept": "application/rdap+json"})
        if r.status_code == 429:
            time.sleep(3 * (attempt + 1))
            continue
        if r.status_code == 404:
            raise LookupError("no WHOIS record (unallocated or private)")
        r.raise_for_status()
        d = r.json()
        start, end = d.get("startAddress"), d.get("endAddress")
        if not start or not end:
            raise LookupError("WHOIS answer without an address range")
        host = (r.url.split("/")[2] if r.url else "").lower()
        rir = next((n for k, n in (("apnic", "APNIC"), ("ripe", "RIPE NCC"), ("arin", "ARIN"), ("lacnic", "LACNIC"), ("afrinic", "AFRINIC"))
                    if k in host), host)
        return {"handle": d.get("handle") or f"{start}-{end}", "start_num": int(ipaddress.ip_address(start)),
                "end_num": int(ipaddress.ip_address(end)), "cidr": _cidr(d, start, end), "name": d.get("name") or "",
                "descr": _descr(d), "org": _org(d), "country": d.get("country") or "", "rir": rir, **_details(d)}
    raise LookupError("rate limited by the WHOIS (RDAP) service, try again later")


def _demo(ip):
    """Sample data: the documentation ranges stand in for an enterprise data centre, an ISP-provided link and ISP pools."""
    a = ipaddress.ip_address(ip)
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    p = str(ip)
    if p.startswith("198.51.100."):
        name, descr, org = "EXAMPLEBANK-DC", "Example Bank Ltd - primary data centre internet edge", "Example Bank Ltd"
    elif p.startswith("203.0.113."):
        name, descr, org = "EXAMPLE-ISP-CUST", "Leased line to Example Bank Ltd, static allocation", "Example ISP Pvt Ltd"
    elif p.startswith("192.0.2."):
        name, descr, org = "EXAMPLE-CLOUD-NET", "Example Cloud public compute range", "Example Cloud Inc"
    else:
        h = int(hashlib.md5(str(net).encode()).hexdigest(), 16) % 3
        name, descr, org = [("EXAMPLE-ISP-POOL", "Broadband customer pool", "Example ISP Pvt Ltd"),
                            ("EXAMPLE-MOBILE", "Mobile data subscribers (CGNAT)", "Example Mobile Ltd"),
                            ("EXAMPLE-HOSTING", "Shared hosting customers", "Example Hosting LLC")][h]
    dom = org.lower().split()[0] + ".example"
    return {"handle": f"SAMPLE-{net}", "start_num": int(net.network_address), "end_num": int(net.broadcast_address), "cidr": str(net),
            "name": name, "descr": descr, "org": org, "country": "IN", "rir": "APNIC (sample)",
            "emails": f"noc@{dom}, abuse@{dom}", "abuse": f"abuse@{dom}", "address": f"{org}, Example Tower, Mumbai, India",
            "phones": "+91-22-0000-0000", "contacts": f"{org} (registrant), NOC Team (technical), Abuse desk (abuse)",
            "remarks": descr, "status": "active", "net_type": "ASSIGNED PA", "registered": "2015-04-01", "changed": "2024-11-12",
            "parent": f"SAMPLE-{ipaddress.ip_network(f'{ip}/16', strict=False)}"}


def lookup(ips, refresh=False, progress=None):
    """WHOIS for the IPs (public IPv4), from the cached blocks where possible. Returns (looked up, errors)."""
    from .registry import exposed_by_itself
    ips = [ip for ip in dict.fromkeys(ips) if ip and ":" not in ip and exposed_by_itself(ip)]
    now, asked, errors = db.now_iso(), 0, 0
    with db.get_conn() as c:
        # blocks cached before contacts / emails were kept (contacts IS NULL) are asked again once
        done = set() if refresh else {r[0] for r in c.execute("""SELECT w.ip FROM ip_whois w JOIN whois_nets n ON n.handle=w.handle
                                                                  WHERE n.contacts IS NOT NULL""")}
        nets = [] if refresh else [tuple(r) for r in c.execute("SELECT start_num, end_num, handle FROM whois_nets WHERE contacts IS NOT NULL")]
    for i, ip in enumerate(ips):
        if ip in done:
            if progress:
                progress(i + 1)
            continue
        n = int(ipaddress.ip_address(ip))
        hit = min((x for x in nets if x[0] <= n <= x[1]), key=lambda x: x[1] - x[0], default=None)
        handle, err = (hit[2], None) if hit else (None, None)
        if not hit:
            try:
                w = rdap(ip)
                asked += 1
                handle = w["handle"]
                with db.get_conn() as c:
                    cols = ["handle", "start_num", "end_num", "cidr", "name", "descr", "org", "country", "rir", *EXTRA]
                    c.execute(f"INSERT OR REPLACE INTO whois_nets({', '.join(cols)}, fetched_at) VALUES ({','.join('?' * (len(cols) + 1))})",
                              [w.get(k, "") for k in cols] + [now])
                nets.append((w["start_num"], w["end_num"], handle))
                if not config.DEMO:
                    time.sleep(0.3)  # be gentle with the registries
            except Exception as e:  # noqa: BLE001
                err = str(e)[:200]
                errors += 1
        with db.get_conn() as c:
            c.execute("INSERT OR REPLACE INTO ip_whois(ip, handle, error, fetched_at) VALUES (?,?,?,?)", (ip, handle, err, now))
        if progress:
            progress(i + 1)
    return asked, errors


EXTRA = ["emails", "abuse", "address", "phones", "contacts", "remarks", "status", "net_type", "registered", "changed", "parent"]


def whois_map(c, ips=None):
    """{ip: {whois_name, whois_descr, whois_org, whois_country, whois_range, whois_rir, whois_error}} for looked-up IPs."""
    rows = db.rows(c, f"""SELECT w.ip, w.error, n.name, n.descr, n.org, n.country, n.cidr, n.rir, {', '.join('n.' + k for k in EXTRA)}
                          FROM ip_whois w LEFT JOIN whois_nets n ON n.handle=w.handle""")
    want = set(ips) if ips is not None else None
    return {r["ip"]: {"whois_name": r["name"], "whois_descr": r["descr"], "whois_org": r["org"], "whois_country": r["country"],
                      "whois_range": r["cidr"], "whois_rir": r["rir"], "whois_error": r["error"], **{"whois_" + k: r[k] for k in EXTRA}}
            for r in rows if want is None or r["ip"] in want}


def net_for(c, ip):
    """Cached WHOIS block that contains the IP (e.g. an advertised prefix's first address), or {}."""
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return {}
    return db.one(c, """SELECT * FROM whois_nets WHERE start_num<=? AND end_num>=?
                        ORDER BY end_num - start_num LIMIT 1""", (n, n)) or {}


def class_map(c):
    return {r[0]: r[1] for r in c.execute("SELECT ip, class FROM ip_class")}


def whois_text(r):
    return " ".join(str(r.get(k) or "") for k in ("whois_name", "whois_descr", "whois_org", "whois_country", "whois_range",
                                                  *("whois_" + x for x in EXTRA))).lower()


def matches(r, p, cls):
    """Filters shared by Attack surface and Internet DB scan: whois (netname), cls (enterprise / non-enterprise / none),
    wq (text in the WHOIS name / description / organisation)."""
    if p.get("whois") and (r.get("whois_name") or "(not looked up)") not in db.multi(p, "whois"):
        return False
    if p.get("cls"):
        have = cls.get(r["ip"]) or "none"
        if have not in p["cls"].split("|"):
            return False
    if p.get("wq") and p["wq"].lower() not in whois_text(r):
        return False
    return True


def facets(rows):
    """Distinct WHOIS names with counts and a sample description, for the filter."""
    out = {}
    for r in rows:
        k = r.get("whois_name") or "(not looked up)"
        f = out.setdefault(k, {"name": k, "n": 0, "descr": r.get("whois_descr") or "", "org": r.get("whois_org") or ""})
        f["n"] += 1
    return sorted(out.values(), key=lambda f: -f["n"])


def set_class(ips, cls, note=""):
    if cls not in CLASSES + (None, "", "none"):
        raise HTTPException(400, "class must be enterprise, non-enterprise or empty")
    with db.get_conn() as c:
        if cls in (None, "", "none"):
            c.executemany("DELETE FROM ip_class WHERE ip=?", [(i,) for i in ips])
        else:
            c.executemany("INSERT OR REPLACE INTO ip_class(ip, class, note, set_at) VALUES (?,?,?,?)",
                          [(i, cls, note, db.now_iso()) for i in ips])
    return len(ips)


# ------------------------------------------------------------------ routes
@router.post("/api/whois/lookup")
def whois_lookup(data: dict = Body(default={})):
    """WHOIS for every known public IP (Attack surface, Internet DB scan results) not looked up yet, in the background.
    {"ips": [...]} limits it; {"refresh": true} asks again."""
    from .surface import _build, _run
    with db.get_conn() as c:
        ips = data.get("ips") or [r["ip"] for r in _build(c)]
    if not ips:
        raise HTTPException(400, "No public IPs to look up")
    refresh = bool(data.get("refresh"))
    return _run("Looking up WHOIS", len(ips), lambda prog: (lambda r: f"WHOIS: {r[0]:,} registry look-ups"
                                                            + (f" · {r[1]:,} without an answer" if r[1] else ""))(lookup(ips, refresh, prog)),
                queue=True)


@router.get("/api/whois/ip")
def whois_ip(ip: str):
    ip = db.canon_ip(ip)
    lookup([ip])
    with db.get_conn() as c:
        return {**(whois_map(c, [ip]).get(ip) or {}), "class": class_map(c).get(ip)}


@router.post("/api/whois/class")
def whois_class(data: dict = Body(...)):
    """Mark IPs: {"ips": [...], "class": "enterprise" | "non-enterprise" | null}."""
    ips = [db.canon_ip(i) for i in data.get("ips") or [] if i]
    if data.get("others") in ("surface", "passive"):  # every other IP of that page that has no mark yet
        with db.get_conn() as c:
            if data["others"] == "surface":
                from .surface import _build
                universe = [r["ip"] for r in _build(c)]
            else:
                universe = [r[0] for r in c.execute("SELECT ip FROM passive_results")]
            marked = set(class_map(c))
        chosen = set(ips)
        ips = [i for i in universe if i not in chosen and i not in marked]
        if not ips:
            raise HTTPException(400, "Every other IP already has a mark")
    if not ips:
        raise HTTPException(400, "Nothing selected")
    return {"marked": set_class(ips, data.get("class"), data.get("note") or "")}
