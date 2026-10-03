"""Internet attack surface: every public IPv4 the console knows, grouped by /24 and by the BGP prefix that advertises it.

Where public IPs come from (any one is enough):
  inventory     an inventory row's own IP is public, or its Public / NAT IP column
  matrix        a public IP in the communication matrix (destination / source NAT, pool, register, public destination)
  crowdstrike   an agent's connection IP is public
  va scan       a VA scan covered a public IP
  passive       a passive (InternetDB) lookup was made for it
  your ranges   the public ranges you list on the Attack surface page

Free enrichment, no API keys (results cached in ip_intel / asn_prefixes):
  RIPEstat      network-info: the advertised prefix and origin ASN of an IP; as-overview: the ASN holder;
                announced-prefixes: every prefix an ASN announces -> the advertised space of the ASNs you mark as yours
  GreyNoise     community API: is the IP seen scanning the internet (noise) / a known benign service (riot)
  InternetDB    passive ports / CVEs (app.passive)
Your ASNs: an IP's origin ASN is often your ISP's, not yours, so only the ASNs you mark expand to "advertised space"."""
import ipaddress
import json
from datetime import datetime, timedelta, timezone
import threading
import time

from fastapi import APIRouter, Body, HTTPException, Request

from . import config, db
from .exporter import xlsx_response

router = APIRouter()
JOB = {"running": False, "kind": "", "total": 0, "done": 0, "message": "", "started_at": None, "finished_at": None}
_lock = threading.Lock()
_tls = threading.local()
RANGES_KEY, ASNS_KEY = "surface_ranges", "surface_asns"
ADV_SCAN_MAX = 4096


def _s():
    if getattr(_tls, "s", None) is None:
        import requests
        _tls.s = requests.Session()
        _tls.s.headers["User-Agent"] = "EDR-Asset-Console"
    return _tls.s


def _setting_list(c, key):
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return db.jloads(r["value"], []) if r else []


# ------------------------------------------------------------------ collect the known public IPs
def known_public(c):
    """{public ip: {"sources": set, "asset_ip": internal ip or None, "name": str}}"""
    from .registry import exposed_by_itself, _nets
    out = {}

    def add(ip, src, asset_ip=None, name=None):
        if not exposed_by_itself(ip):
            return
        d = out.setdefault(ip, {"sources": set(), "asset_ip": None, "name": None})
        d["sources"].add(src)
        d["asset_ip"] = d["asset_ip"] or asset_ip
        d["name"] = d["name"] or name
    for r in c.execute("SELECT ip, name, public_ips, sources, in_inventory, in_scan, in_edr FROM asset_registry"):
        srcs = (r["sources"] or "").split(",")
        if r["ip"]:
            if r["in_inventory"]:
                add(r["ip"], "inventory", None, r["name"])
            if r["in_scan"]:
                add(r["ip"], "va scan", None, r["name"])
        for p in (r["public_ips"] or "").split(", "):
            if p:
                add(p, "inventory" if "inventory" in srcs else "matrix", r["ip"], r["name"])
    for r in c.execute("SELECT connection_ip, hostname FROM hosts WHERE console_state='active' AND COALESCE(connection_ip,'')<>''"):
        add(r["connection_ip"], "crowdstrike", None, r["hostname"])
    try:
        from .commatrix import matrix_ips
        for e in matrix_ips(c):
            if e["kind"] == "ip" and e["ours"]:
                add(e["address"], "matrix", None, e.get("name"))
    except Exception:  # noqa: BLE001 - no matrix
        pass
    for r in c.execute("SELECT ip, asset_ip, asset_name FROM passive_results"):
        add(r["ip"], "passive", r["asset_ip"], r["asset_name"])
    for e in _setting_list(c, RANGES_KEY):
        for n in _nets(e.get("value")):
            if n.version == 4 and n.num_addresses <= 256:
                for a in (n if n.num_addresses > 1 else [n.network_address]):
                    add(str(a), "your ranges")
    return out


# ------------------------------------------------------------------ enrichment: RIPEstat, GreyNoise
def ripe_ip(ip):
    r = _s().get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip}, timeout=15)
    r.raise_for_status()
    d = (r.json() or {}).get("data") or {}
    asns = d.get("asns") or []
    return d.get("prefix") or "", asns[0] if asns else ""


_holders = {}


def ripe_holder(asn):
    if not asn:
        return ""
    if asn not in _holders:
        r = _s().get("https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{asn}"}, timeout=15)
        _holders[asn] = (((r.json() or {}).get("data") or {}).get("holder") or "") if r.ok else ""
    return _holders[asn]


def ripe_announced(asn):
    r = _s().get("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": f"AS{asn}", "min_peers_seeing": 10}, timeout=60)
    r.raise_for_status()
    return [p.get("prefix") for p in ((r.json() or {}).get("data") or {}).get("prefixes") or [] if p.get("prefix")]


def greynoise(ip):
    """(noise, riot, classification, name, message, last_seen) or None when rate limited."""
    r = _s().get(f"https://api.greynoise.io/v3/community/{ip}", timeout=15)
    if r.status_code == 429:
        return None
    d = r.json() if r.content else {}
    return (1 if d.get("noise") else 0, 1 if d.get("riot") else 0, d.get("classification") or "", d.get("name") or "",
            d.get("message") or "", d.get("last_seen") or "")


def _demo_intel(ip):
    a = ipaddress.ip_address(ip)
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    asn = "64500" if str(ip).startswith("198.51.100.") else "64501" if str(ip).startswith("203.0.113.") else "64510"
    h = int(a) % 13
    return (str(net), asn, {"64500": "EXAMPLE-ENTERPRISE (sample)", "64501": "EXAMPLE-ISP (sample)"}.get(asn, "EXAMPLE-NET (sample)"),
            (1 if h == 3 else 0, 1 if h == 7 else 0, "malicious" if h == 3 else "benign" if h == 7 else "", "", "", ""))


def enrich(ips, what=("ripe", "greynoise"), progress=None):
    """RIPEstat (prefix / ASN / holder, once per covered prefix) and GreyNoise per IP, cached in ip_intel."""
    now = db.now_iso()
    with db.get_conn() as c:
        have = {r["ip"]: r for r in db.rows(c, "SELECT * FROM ip_intel")}
    known_prefixes = [(ipaddress.ip_network(r["prefix"]), r["prefix"], r["asn"], r["holder"]) for r in have.values() if r["prefix"]]
    gn_stopped = False
    for i, ip in enumerate(ips):
        row = dict(have.get(ip) or {"ip": ip})
        if config.DEMO:
            pfx, asn, holder, gn = _demo_intel(ip)
            row.update(prefix=pfx, asn=asn, holder=holder, ripe_at=now)
            if "greynoise" in what:
                row.update(gn_noise=gn[0], gn_riot=gn[1], gn_class=gn[2], gn_name=gn[3], gn_message=gn[4], gn_last_seen=gn[5], gn_at=now)
        else:
            if "ripe" in what and not row.get("prefix"):
                a = ipaddress.ip_address(ip)
                hit = next((k for k in known_prefixes if a in k[0]), None)
                try:
                    if hit:
                        row.update(prefix=hit[1], asn=hit[2], holder=hit[3], ripe_at=now)
                    else:
                        pfx, asn = ripe_ip(ip)
                        row.update(prefix=pfx, asn=asn, holder=ripe_holder(asn), ripe_at=now)
                        if pfx:
                            known_prefixes.append((ipaddress.ip_network(pfx), pfx, asn, row["holder"]))
                except Exception as e:  # noqa: BLE001
                    row.setdefault("error", str(e)[:200])
            if "greynoise" in what and not gn_stopped:
                try:
                    gn = greynoise(ip)
                    if gn is None:
                        gn_stopped = True  # community quota reached: keep what we have
                    else:
                        row.update(gn_noise=gn[0], gn_riot=gn[1], gn_class=gn[2], gn_name=gn[3], gn_message=gn[4], gn_last_seen=gn[5], gn_at=now)
                except Exception:  # noqa: BLE001
                    pass
        with db.get_conn() as c:
            c.execute("""INSERT OR REPLACE INTO ip_intel(ip, prefix, asn, holder, gn_noise, gn_riot, gn_class, gn_name, gn_message, gn_last_seen,
                         ripe_at, gn_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (ip, row.get("prefix"), row.get("asn"), row.get("holder"), row.get("gn_noise"), row.get("gn_riot"), row.get("gn_class"),
                       row.get("gn_name"), row.get("gn_message"), row.get("gn_last_seen"), row.get("ripe_at"), row.get("gn_at")))
        if progress:
            progress(i + 1)
    return {"greynoise_limited": gn_stopped}


_PENDING = []  # jobs asked for while another one runs (e.g. ASNs saved during a prefix lookup); started when it ends


def _run(kind, total, fn, queue=False):
    with _lock:
        if JOB["running"]:
            if queue:
                _PENDING.append((kind, total, fn))
                return {"queued": kind}
            raise HTTPException(409, f"{JOB['kind']} is still running")
        JOB.update(running=True, kind=kind, total=total, done=0, message="", started_at=db.now_iso(), finished_at=None)

    def work():
        try:
            JOB["message"] = fn(lambda n: JOB.__setitem__("done", n)) or "done"
        except Exception as e:  # noqa: BLE001
            JOB["message"] = f"Stopped: {e}"
        finally:
            JOB.update(running=False, finished_at=db.now_iso())
            if _PENDING:
                k, t, f = _PENDING.pop(0)
                _run(k, t, f)
    threading.Thread(target=work, daemon=True).start()
    return {"started": kind, "total": total}


# ------------------------------------------------------------------ the surface
def _build(c):
    from .whois import class_map, whois_map
    known = known_public(c)
    who, cls = whois_map(c), class_map(c)
    intel = {r["ip"]: r for r in db.rows(c, "SELECT * FROM ip_intel")}
    passive = {r["ip"]: r for r in db.rows(c, "SELECT ip, status, ports, vulns, scanned_at FROM passive_results")}
    reg = {r["ip"]: r for r in db.rows(c, "SELECT ip, name, lobs, exposed, edr_status FROM asset_registry WHERE ip IS NOT NULL")}
    rows = []
    for ip, d in known.items():
        it, pv = intel.get(ip) or {}, passive.get(ip) or {}
        a = reg.get(d["asset_ip"] or ip) or reg.get(ip) or {}
        ports = db.jloads(pv.get("ports"), []) or []
        vulns = db.jloads(pv.get("vulns"), []) or []
        rows.append({"ip": ip, "sources": sorted(d["sources"]), "asset_ip": d["asset_ip"], "name": d["name"] or a.get("name"), "lobs": a.get("lobs"),
                     "exposed": (reg.get(ip) or a).get("exposed"), "edr_status": a.get("edr_status"),
                     "subnet": str(ipaddress.ip_network(f"{ip}/24", strict=False)), "prefix": it.get("prefix"), "asn": it.get("asn"),
                     "holder": it.get("holder"), "gn_noise": it.get("gn_noise"), "gn_riot": it.get("gn_riot"), "gn_class": it.get("gn_class"),
                     "scanned": bool(pv), "scan_status": pv.get("status"), "ports": ports, "vulns": vulns, "scanned_at": pv.get("scanned_at"),
                     "num": db.ip_to_num(ip) or 0, **(who.get(ip) or {}), "cls": cls.get(ip)})
    rows.sort(key=lambda r: r["num"])
    return rows


def _group(rows, key):
    g = {}
    for r in rows:
        k = r.get(key) or "(not looked up)"
        x = g.setdefault(k, {"key": k, "ips": 0, "exposed": 0, "scanned": 0, "with_ports": 0, "with_cves": 0, "noisy": 0, "asn": r.get("asn"),
                             "holder": r.get("holder"), "assets": set(), "lobs": set(), "_who": {}, "enterprise": 0, "non_enterprise": 0})
        x["enterprise"] += r.get("cls") == "enterprise"
        x["non_enterprise"] += r.get("cls") == "non-enterprise"
        if r.get("whois_name"):
            w = x["_who"].setdefault(r["whois_name"], [0, r.get("whois_descr") or "", r.get("whois_org") or ""])
            w[0] += 1
        x["ips"] += 1
        x["exposed"] += 1 if r["exposed"] else 0
        x["scanned"] += 1 if r["scanned"] else 0
        x["with_ports"] += 1 if r["ports"] else 0
        x["with_cves"] += 1 if r["vulns"] else 0
        x["noisy"] += 1 if r["gn_noise"] else 0
        if r["name"]:
            x["assets"].add(r["name"])
        for l in (r["lobs"] or "").split(", "):
            if l:
                x["lobs"].add(l)
    out = []
    for x in g.values():
        x["assets"], x["lobs"] = len(x["assets"]), ", ".join(sorted(x["lobs"]))
        who = sorted(x.pop("_who").items(), key=lambda w: -w[1][0])
        x["whois_name"] = ", ".join(n for n, _ in who[:3])
        x["whois_descr"] = who[0][1][1] if who else ""
        x["whois_org"] = who[0][1][2] if who else ""
        out.append(x)
    return sorted(out, key=lambda x: (-x["with_cves"], -x["with_ports"], -x["ips"]))


@router.get("/api/surface")
def surface(view: str = "subnet", bits: int = 24):
    bits = min(32, max(8, int(bits or 24)))
    with db.get_conn() as c:
        rows = _build(c)
        for r in rows:  # group public IPs by the subnet size picked on the page (/24 by default)
            r["group"] = str(ipaddress.ip_network(f"{r['ip']}/{bits}", strict=False))
        asns = _setting_list(c, ASNS_KEY)
        ranges = _setting_list(c, RANGES_KEY)
        adv = db.rows(c, "SELECT asn, prefix FROM asn_prefixes")
        oldest = db.one(c, "SELECT MIN(fetched_at) t FROM asn_prefixes")["t"]
    stale = (asns and not JOB["running"] and ((not adv) or (oldest and oldest < (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"))))
    if stale:  # never fetched, or older than a week: refresh from RIPEstat in the background
        try:
            start_advertised(asns)
        except HTTPException:
            pass
    by_asn = {}
    for r in rows:
        if r["asn"]:
            a = by_asn.setdefault(r["asn"], {"asn": r["asn"], "holder": r["holder"], "ips": 0, "ours": r["asn"] in asns})
            a["ips"] += 1
    # advertised space of the ASNs marked as ours: prefixes with no known public IP are unknown surface
    nets = [(ipaddress.ip_network(r["ip"] + "/32"), r) for r in rows]
    adv_rows = []
    c2 = db.connect()
    for p in adv:
        if p["asn"] not in asns:
            continue
        try:
            n = ipaddress.ip_network(p["prefix"])
        except ValueError:
            continue
        if n.version != 4:
            continue
        inside = [r for a, r in nets if a.subnet_of(n)]
        from .whois import net_for
        w = net_for(c2, str(n.network_address)) if c2 else {}
        adv_rows.append({"asn": p["asn"], "prefix": p["prefix"], "size": n.num_addresses, "known": len(inside),
                         "scanned": sum(1 for r in inside if r["scanned"]), "with_ports": sum(1 for r in inside if r["ports"]),
                         "whois_name": w.get("name"), "whois_descr": w.get("descr"), "whois_org": w.get("org")})
    c2.close()
    adv_rows.sort(key=lambda x: (x["known"] > 0, -x["size"]))
    return {"summary": {"ips": len(rows), "subnets": len({r["subnet"] for r in rows}), "prefixes": len({r["prefix"] for r in rows if r["prefix"]}),
                        "asns": len(by_asn), "exposed": sum(1 for r in rows if r["exposed"]), "scanned": sum(1 for r in rows if r["scanned"]),
                        "with_ports": sum(1 for r in rows if r["ports"]), "with_cves": sum(1 for r in rows if r["vulns"]),
                        "noisy": sum(1 for r in rows if r["gn_noise"]), "looked_up": sum(1 for r in rows if r["prefix"]),
                        "adv_prefixes": len(adv_rows), "adv_unknown": sum(1 for a in adv_rows if not a["known"]),
                        "whois": sum(1 for r in rows if r.get("whois_name")), "enterprise": sum(1 for r in rows if r.get("cls") == "enterprise"),
                        "non_enterprise": sum(1 for r in rows if r.get("cls") == "non-enterprise")},
            "subnets": _with_block(_group(rows, "group")), "bits": bits, "prefixes": _with_block(_group(rows, "prefix")), "asns": sorted(by_asn.values(), key=lambda a: -a["ips"]),
            "advertised": adv_rows[:2000], "ranges": ranges, "our_asns": asns, "job": JOB, "demo": config.DEMO}


def _with_block(groups):
    """WHOIS of the registered block that holds each subnet / prefix (its first address), next to the WHOIS of its known IPs."""
    from .whois import net_for
    c = db.connect()
    try:
        for g in groups:
            try:
                first = str(ipaddress.ip_network(g["key"], strict=False).network_address)
            except ValueError:
                continue
            b = net_for(c, first)
            g.update(block_name=b.get("name"), block_descr=b.get("descr"), block_org=b.get("org"), block_range=b.get("cidr"),
                     block_country=b.get("country"))
    finally:
        c.close()
    return groups


def _filter(rows, p):
    from .whois import matches, whois_text
    cls = {r["ip"]: r.get("cls") for r in rows}
    rows = [r for r in rows if matches(r, p, cls)]
    if p.get("subnet"):
        try:
            nets = [ipaddress.ip_network(x, strict=False) for x in db.multi(p, "subnet")]
            rows = [r for r in rows if any(ipaddress.ip_address(r["ip"]) in n for n in nets)]
        except ValueError:
            rows = []
    if p.get("prefix"):
        rows = [r for r in rows if r["prefix"] in db.multi(p, "prefix")]
    if p.get("asn"):
        rows = [r for r in rows if r["asn"] in db.multi(p, "asn")]
    show = p.get("show")
    rows = [r for r in rows if not show or (show == "ports" and r["ports"]) or (show == "cves" and r["vulns"]) or (show == "unscanned" and not r["scanned"])
            or (show == "noisy" and r["gn_noise"]) or (show == "exposed" and r["exposed"])]
    if p.get("q"):
        q = p["q"].lower()
        rows = [r for r in rows if q in f"{r['ip']} {r['name'] or ''} {r['lobs'] or ''} {r['holder'] or ''} {' '.join(r['vulns'])} {whois_text(r)}".lower()]
    return rows


@router.get("/api/surface/ips")
def surface_ips(request: Request):
    p = dict(request.query_params)
    page, size = db.page_args(p)
    with db.get_conn() as c:
        rows = _filter(_build(c), p)
    return {"total": len(rows), "rows": rows[(page - 1) * size: page * size]}


@router.get("/api/surface/ips/export")
def surface_export(request: Request):
    with db.get_conn() as c:
        rows = _filter(_build(c), dict(request.query_params))
    for r in rows:
        r["sources_text"], r["ports_text"], r["vulns_text"] = ", ".join(r["sources"]), ", ".join(map(str, r["ports"])), ", ".join(r["vulns"])
        r["gn_text"] = "seen scanning the internet" if r["gn_noise"] else "known benign service" if r["gn_riot"] else ""
    return xlsx_response([("Attack surface", [("ip", "Public IP"), ("name", "Asset"), ("asset_ip", "Behind NAT"), ("lobs", "LOB"), ("sources_text", "Known from"),
                                              ("subnet", "/24"), ("prefix", "Advertised prefix"), ("asn", "ASN"), ("holder", "Holder"),
                                              ("whois_name", "WHOIS name"), ("whois_descr", "WHOIS description"), ("whois_org", "WHOIS organisation"),
                                              ("whois_country", "WHOIS country"), ("whois_range", "WHOIS range"), ("cls", "Enterprise / non-enterprise"),
                                              ("ports_text", "Open ports (InternetDB)"), ("vulns_text", "CVEs"), ("gn_text", "GreyNoise"),
                                              ("scanned_at", "Passive scan")], rows)], "attack_surface")


@router.post("/api/surface/scan")
def surface_scan(data: dict = Body(default={})):
    """Passive InternetDB scan: scope "known" = every known public IP (default), "unscanned", or "prefix" = every address of one
    advertised prefix / range (at most 4,096)."""
    from . import passive
    scope = data.get("scope") or "known"
    with db.get_conn() as c:
        rows = _build(c)
    if scope == "prefix":
        try:
            n = ipaddress.ip_network(str(data.get("prefix")), strict=False)
        except ValueError:
            raise HTTPException(400, "Not a prefix")
        if n.version != 4 or n.num_addresses > ADV_SCAN_MAX:
            raise HTTPException(400, f"Pick an IPv4 prefix of at most {ADV_SCAN_MAX:,} addresses (/20 or smaller)")
        items = [str(a) for a in (n.hosts() if n.num_addresses > 2 else n)]
    else:
        items = [r["ip"] for r in rows if scope != "unscanned" or not r["scanned"]]
    if not items:
        raise HTTPException(400, "No public IPs to scan")
    return passive.start_job(items, f"Attack surface · {scope}", data.get("prefix") or "")


@router.post("/api/surface/enrich")
def surface_enrich(data: dict = Body(default={})):
    """RIPEstat prefix / ASN / holder and GreyNoise for the known public IPs (background)."""
    what = tuple(data.get("what") or ("ripe", "greynoise"))
    with db.get_conn() as c:
        ips = [r["ip"] for r in _build(c)]
        if data.get("only_new"):
            done = {r[0] for r in c.execute("SELECT ip FROM ip_intel WHERE ripe_at IS NOT NULL")}
            ips = [i for i in ips if i not in done]
    if not ips:
        raise HTTPException(400, "No public IPs to look up")
    def fn(prog):
        from .whois import lookup
        r = enrich(ips, what, prog)
        nets24 = sorted({str(ipaddress.ip_network(f"{i}/24", strict=False).network_address) for i in ips})
        asked, errs = lookup(ips + nets24, progress=prog)  # WHOIS too (and each /24's own block): cached per registered block
        return ("done" + (" · GreyNoise daily quota reached, the rest later" if r["greynoise_limited"] else "")
                + f" · WHOIS {asked:,} registry look-ups" + (f", {errs:,} without an answer" if errs else ""))
    return _run("Looking up prefixes, GreyNoise and WHOIS", len(ips), fn)


def start_advertised(asns=None, queue=False):
    """Fetch the prefixes announced by the given ASNs (default: the ones marked as yours) from RIPEstat, in the background."""
    with db.get_conn() as c:
        asns = asns if asns is not None else _setting_list(c, ASNS_KEY)
    if not asns:
        raise HTTPException(400, "Mark at least one ASN as yours first")

    def fn(prog):
        rows = []
        for i, a in enumerate(asns):
            if config.DEMO:  # sample: the documentation ranges stand in for an ASN's advertised space
                pref = ["198.51.100.0/25", "198.51.100.128/25", "192.0.2.0/24"] if a == "64500" else ["203.0.113.0/24"]
            else:
                pref = ripe_announced(a)
            rows += [(a, p, db.now_iso()) for p in pref]
            prog(i + 1)
        with db.get_conn() as c:
            c.execute(f"DELETE FROM asn_prefixes WHERE asn IN ({','.join('?' * len(asns))})", asns)
            c.executemany("INSERT OR REPLACE INTO asn_prefixes(asn, prefix, fetched_at) VALUES (?,?,?)", rows)
        from .whois import lookup
        firsts = []
        for _, p, _ in rows:
            try:
                n = ipaddress.ip_network(p)
                if n.version == 4:
                    firsts.append(str(n.network_address))
            except ValueError:
                pass
        lookup(firsts[:2000])  # who each advertised prefix is registered to (one registry answer per block)
        return f"{len(rows):,} advertised prefixes for {', '.join('AS' + a for a in asns)}"
    return _run("Fetching advertised prefixes", len(asns), fn, queue=queue)


@router.post("/api/surface/advertised")
def surface_advertised(data: dict = Body(default={})):
    """Fetch the prefixes announced by the ASNs marked as yours (RIPEstat announced-prefixes)."""
    return start_advertised()


@router.put("/api/surface/settings")
def surface_settings(data: dict = Body(...)):
    from .registry import _nets
    with db.get_conn() as c:
        new_asns = []
        if "asns" in data:
            asns = sorted({str(a).upper().replace("AS", "").strip() for a in data["asns"] if str(a).strip()})
            bad = [a for a in asns if not a.isdigit()]
            if bad:
                raise HTTPException(400, "Not an ASN: " + ", ".join(bad))
            had = set(_setting_list(c, ASNS_KEY))
            have_pfx = {r[0] for r in c.execute("SELECT DISTINCT asn FROM asn_prefixes")}
            new_asns = [a for a in asns if a not in had or a not in have_pfx]
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", (ASNS_KEY, json.dumps(asns)))
            gone = sorted(had - set(asns))
            if gone:  # an ASN that is no longer yours: forget its advertised prefixes
                c.execute(f"DELETE FROM asn_prefixes WHERE asn IN ({','.join('?' * len(gone))})", gone)
        if "ranges" in data:
            bad = [e.get("value") for e in data["ranges"] if e.get("value") and not _nets(e.get("value"))]
            if bad:
                raise HTTPException(400, "Not an IP or range: " + ", ".join(bad))
            c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", (RANGES_KEY, json.dumps([e for e in data["ranges"] if e.get("value")])))
    fetching = None
    if new_asns:  # ASNs just added: fetch their advertised prefixes from RIPEstat right away
        fetching = start_advertised(new_asns, queue=True)
    return {"ok": True, "fetching": new_asns if fetching else [], "queued": bool(fetching and fetching.get("queued"))}


@router.get("/api/surface/whois-facets")
def surface_whois_facets():
    from .whois import facets
    with db.get_conn() as c:
        return {"rows": facets(_build(c))}


@router.post("/api/surface/classify")
def surface_classify(data: dict = Body(...)):
    """Mark the public IPs a filter matches: {"filter": {page filters}, "class": "enterprise" | "non-enterprise" | null,
    "scope": "filtered" (default) | "others" (every other known IP that has no mark yet)}."""
    from .whois import set_class
    with db.get_conn() as c:
        rows = _build(c)
    hit = {r["ip"] for r in _filter(rows, {k: v for k, v in (data.get("filter") or {}).items() if k not in ("page", "size", "tab")})}
    if data.get("scope") == "others":
        ips = [r["ip"] for r in rows if r["ip"] not in hit and not r.get("cls")]
    else:
        ips = sorted(hit)
    if not ips:
        raise HTTPException(400, "No IPs match")
    return {"marked": set_class(ips, data.get("class"), data.get("note") or "")}


@router.get("/api/surface/job")
def surface_job():
    return JOB


@router.get("/api/asset/intel")
def asset_intel(ips: str = ""):
    ipl = [db.canon_ip(i) for i in ips.split(",") if i]
    if not ipl:
        return {"rows": []}
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT * FROM ip_intel WHERE ip IN ({','.join('?' * len(ipl))})", ipl)
    return {"rows": rows}


@router.post("/api/asset/intel/refresh")
def asset_intel_refresh(data: dict = Body(...)):
    """RIPEstat + GreyNoise for the public IPs of one asset, now."""
    from .registry import exposed_by_itself
    ips = [db.canon_ip(i) for i in (data.get("ips") or []) if exposed_by_itself(db.canon_ip(i))][:8]
    if not ips:
        raise HTTPException(400, "No public IPv4 to look up")
    enrich(ips)
    return asset_intel(",".join(ips))
