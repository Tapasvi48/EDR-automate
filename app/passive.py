"""Passive internet scan with Shodan InternetDB (https://internetdb.shodan.io): open ports, CVEs, CPEs, hostnames and tags
that internet-wide scanning already recorded for a PUBLIC IP. Nothing is sent to the asset itself; only the IP is sent to
Shodan. No API key is needed.

Targets: a public IP is looked up as is. A private IP is looked up through the public / NAT IPs the console knows for it
(inventory Public IP column, communication-matrix NAT, source NAT); without one it is skipped ("private, no public IP known").
Results (latest per public IP) are stored in passive_results; open ports found there count as internet-exposure evidence
("Passive scan"). Jobs run in the background, a few lookups at a time; sample-data mode simulates the answers."""
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Body, HTTPException, Request

from . import config, db
from .exporter import xlsx_response

router = APIRouter()
URL = "https://internetdb.shodan.io/{ip}"
WORKERS = 16  # InternetDB answers in ~0.1-0.3 s and tolerates parallel lookups; one HTTPS session per worker thread
JOB = {"running": False, "id": None, "total": 0, "done": 0, "found": 0, "errors": 0, "source": "", "started_at": None, "finished_at": None,
       "message": ""}
_lock = threading.Lock()


_tls = threading.local()


def _session():
    """One keep-alive HTTPS session per thread: no new TLS handshake for every IP (that was most of the time per lookup)."""
    if getattr(_tls, "s", None) is None:
        import requests
        _tls.s = requests.Session()
        _tls.s.headers["User-Agent"] = "EDR-Asset-Console"
    return _tls.s


def _lookup(ip):
    """(status, data, error) for one public IP. status: ok | none (InternetDB has nothing) | error."""
    if config.DEMO:
        return _demo(ip)
    for attempt in range(4):
        try:
            r = _session().get(URL.format(ip=ip), timeout=12)
        except Exception as e:  # noqa: BLE001
            if attempt == 3:
                return "error", None, str(e)[:300]
            time.sleep(1.5 * (attempt + 1))
            continue
        if r.status_code == 404:
            return "none", {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}, None
        if r.status_code == 429:  # rate limited: back off and retry
            time.sleep(2 * (attempt + 1))
            continue
        if r.status_code >= 400:
            return "error", None, f"HTTP {r.status_code}: {r.text[:200]}"
        return "ok", r.json(), None
    return "error", None, "rate limited by InternetDB, try again later"


def _demo(ip):
    """Sample data: deterministic answers for the documentation ranges the sample uses."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    if h % 4 == 0:
        return "none", {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}, None
    pool = [22, 25, 53, 80, 443, 3389, 8080, 8443, 1723, 500, 4500, 161]
    ports = sorted({pool[(h >> (k * 4)) % len(pool)] for k in range(1 + h % 4)})
    cves = ["CVE-2023-48795", "CVE-2021-44228", "CVE-2022-3602", "CVE-2023-44487", "CVE-2024-6387", "CVE-2019-0708"]
    vulns = sorted({cves[(h >> (k * 3)) % len(cves)] for k in range((h >> 9) % 3)})
    cpes = [c for c, p in (("cpe:/a:openbsd:openssh", 22), ("cpe:/a:nginx:nginx", 443), ("cpe:/a:apache:http_server", 80),
                           ("cpe:/o:microsoft:windows", 3389)) if p in ports]
    return "ok", {"ports": ports, "vulns": vulns, "cpes": cpes, "hostnames": [f"host{h % 97}.example.net"] if h % 3 else [],
                  "tags": ["cloud"] if h % 5 == 0 else []}, None


def resolve_targets(c, items):
    """Inputs (IPs, ranges, registry keys) -> [(public_ip, asset_ip, asset_name)] plus skipped [(input, reason)]."""
    from .addrparse import parse_addresses
    from .registry import exposed_by_itself
    out, skipped, seen = [], [], set()
    reg_by_ip = {}
    keys = [str(x).strip() for x in items if str(x).strip()]
    ips = []
    for k in keys:
        if k.startswith("name:"):
            r = db.one(c, "SELECT ip, name, public_ips FROM asset_registry WHERE asset_key=?", (k,))
            if r:
                reg_by_ip[r["ip"] or k] = r
                ips.append(r["ip"] or k)
            continue
        nets = parse_addresses(k)[1]
        if not nets:
            skipped.append((k, "not an IP"))
            continue
        for n in nets:
            if n.num_addresses > 256:
                skipped.append((str(n), "range larger than 256 addresses: list the IPs"))
                continue
            ips += [str(a) for a in (n if n.num_addresses > 1 else [n.network_address])]
    for ip in ips:
        r = reg_by_ip.get(ip) or db.one(c, "SELECT ip, name, public_ips, nat_of FROM asset_registry WHERE ip=?", (ip,))
        name = r["name"] if r else None
        if ip and ":" not in ip and exposed_by_itself(ip):
            targets = [ip]
            inner = ((r or {}).get("nat_of") or "").split(", ")[0]  # a public NAT IP: keep the asset behind it
            if inner:
                inner_r = db.one(c, "SELECT name FROM asset_registry WHERE ip=?", (inner,))
                out.append((ip, inner, (inner_r or {}).get("name") or name))
                seen.add((ip, ip))
                continue
        else:
            targets = [p for p in ((r or {}).get("public_ips") or "").split(", ") if p and exposed_by_itself(p)]
            if not targets:
                skipped.append((ip, "private IP and no public / NAT IP known" if ip and ":" not in ip else "IPv6 or no IP: InternetDB covers public IPv4"))
                continue
        for t in targets:
            if (t, ip) in seen:
                continue
            seen.add((t, ip))
            out.append((t, ip if t != ip else None, name))
    return out, skipped


def _store(c, rows):
    c.executemany("""INSERT OR REPLACE INTO passive_results(ip, asset_ip, asset_name, status, ports, vulns, cpes, hostnames, tags, error,
                     scanned_at, job_id, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def scan_now(c, targets, job_id=None, source="manual"):
    rows, now = [], db.now_iso()
    for ip, asset_ip, name in targets:
        st, d, err = _lookup(ip)
        d = d or {}
        rows.append((ip, asset_ip, name, st, json.dumps(d.get("ports") or []), json.dumps(d.get("vulns") or []), json.dumps(d.get("cpes") or []),
                     json.dumps(d.get("hostnames") or []), json.dumps(d.get("tags") or []), err, now, job_id, source))
    _store(c, rows)
    return rows


def start_job(items, source="selection", note=""):
    with db.get_conn() as c:
        targets, skipped = resolve_targets(c, items)
        if not targets:
            raise HTTPException(400, "Nothing to scan: " + "; ".join(f"{a} ({b})" for a, b in skipped[:5]))
    with _lock:
        if JOB["running"]:
            raise HTTPException(409, "A passive scan is already running; wait for it to finish")
        with db.get_conn() as c:
            jid = c.execute("""INSERT INTO passive_jobs(started_at, source, note, total, skipped) VALUES (?,?,?,?,?)""",
                            (db.now_iso(), source, note, len(targets), json.dumps(skipped[:500]))).lastrowid
        JOB.update(running=True, id=jid, total=len(targets), done=0, found=0, errors=0, source=source, started_at=db.now_iso(), finished_at=None,
                   message=f"{len(targets):,} public IPs to look up" + (f" · {len(skipped):,} skipped" if skipped else ""))
    threading.Thread(target=_worker, args=(jid, targets, source), daemon=True).start()
    return {"job_id": jid, "targets": len(targets), "skipped": skipped[:200]}


def _worker(jid, targets, source):
    def one(t):
        st, d, err = _lookup(t[0])
        return t, st, d or {}, err
    buf = []
    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for (ip, asset_ip, name), st, d, err in ex.map(one, targets):
                buf.append((ip, asset_ip, name, st, json.dumps(d.get("ports") or []), json.dumps(d.get("vulns") or []),
                            json.dumps(d.get("cpes") or []), json.dumps(d.get("hostnames") or []), json.dumps(d.get("tags") or []), err,
                            db.now_iso(), jid, source))
                JOB["done"] += 1
                JOB["found"] += 1 if d.get("ports") else 0
                JOB["errors"] += 1 if st == "error" else 0
                if len(buf) >= 200:
                    with db.get_conn() as c:
                        _store(c, buf)
                    buf = []
        with db.get_conn() as c:
            _store(c, buf)
            c.execute("UPDATE passive_jobs SET finished_at=?, done=?, found=?, errors=? WHERE id=?",
                      (db.now_iso(), JOB["done"], JOB["found"], JOB["errors"], jid))
        JOB["message"] = f"{JOB['done']:,} looked up · {JOB['found']:,} with open ports" + (f" · {JOB['errors']} errors" if JOB["errors"] else "")
        from . import inventory
        inventory.refresh_async("Updating exposure from the passive scan")  # open ports count as exposure evidence
    except Exception as e:  # noqa: BLE001
        JOB["message"] = f"Stopped: {e}"
    finally:
        JOB.update(running=False, finished_at=db.now_iso())


# ------------------------------------------------------------------ routes
def _row(r):
    for k in ("ports", "vulns", "cpes", "hostnames", "tags"):
        r[k] = db.jloads(r.get(k), []) or []
    return r


@router.post("/api/passive/scan")
def passive_scan(data: dict = Body(...)):
    """Background scan of many targets: {"items": [ip | range | registry key, ...], "source": "...", "note": "..."}."""
    items = data.get("items") or data.get("keys") or []
    if not items:
        raise HTTPException(400, "Nothing selected")
    return start_job(items[:50000], data.get("source") or "selection", data.get("note") or "")


@router.post("/api/passive/scan-one")
def passive_scan_one(data: dict = Body(...)):
    """Look up one IP (or a private IP through its public / NAT IPs) right away and return the result."""
    q = str(data.get("ip") or "").strip()
    with db.get_conn() as c:
        targets, skipped = resolve_targets(c, [q])
        if not targets:
            raise HTTPException(400, skipped[0][1] if skipped else "Not an IP")
        scan_now(c, targets[:8], source="manual")
        rows = [_row(r) for r in db.rows(c, f"SELECT * FROM passive_results WHERE ip IN ({','.join('?' * len(targets[:8]))})",
                                         [t[0] for t in targets[:8]])]
    from . import inventory
    inventory.refresh_async("Updating exposure from the passive scan")  # answer now; exposure catches up in the background
    return {"rows": rows}


@router.post("/api/passive/upload")
def passive_upload(data: dict = Body(...)):
    """Scan the IPs of an uploaded Excel / CSV: {token, sheet?, header_row?, column?}. Without a column every cell is searched."""
    from . import inventory
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    col = data.get("column")
    idx = parsed["headers"].index(col) if col in parsed["headers"] else None
    items = []
    for r in parsed["rows"]:
        cells = [r[idx]] if idx is not None else r
        for v in cells:
            items += db.all_ips(v)
    items = list(dict.fromkeys(items))
    if not items:
        raise HTTPException(400, "No IP addresses found in the file")
    return {**start_job(items, "upload", parsed["filename"]), "ips_in_file": len(items)}


@router.post("/api/passive/upload/columns")
def passive_upload_columns(data: dict = Body(...)):
    """Sheets and columns of the uploaded file, with the column that holds the most IPs pre-selected."""
    from . import inventory
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    counts = {h: sum(1 for r in parsed["rows"][:2000] if i < len(r) and db.all_ips(r[i])) for i, h in enumerate(parsed["headers"])}
    best = max(counts, key=counts.get) if counts and max(counts.values()) else None
    return {"filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"], "headers": parsed["headers"],
            "row_count": len(parsed["rows"]), "column": best, "ip_counts": counts}


@router.get("/api/passive/status")
def passive_status():
    with db.get_conn() as c:
        jobs = db.rows(c, "SELECT * FROM passive_jobs ORDER BY id DESC LIMIT 10")
        s = db.one(c, """SELECT COUNT(*) ips, SUM(status='ok' AND ports<>'[]') with_ports, SUM(vulns<>'[]') with_vulns,
                         SUM(status='error') errors, MAX(scanned_at) last FROM passive_results""")
    for j in jobs:
        j["skipped"] = db.jloads(j.get("skipped"), [])
    return {"job": JOB, "jobs": jobs, "summary": {k: (v or 0) if k != "last" else v for k, v in s.items()}, "demo": config.DEMO}


def _query(p):
    w, params = [], []
    if p.get("q"):
        like = f"%{p['q']}%"
        w.append("(ip LIKE ? OR asset_ip LIKE ? OR asset_name LIKE ? OR vulns LIKE ? OR ports LIKE ? OR hostnames LIKE ?)")
        params += [like] * 6
    show = p.get("show")
    if show == "ports":
        w.append("ports<>'[]'")
    elif show == "vulns":
        w.append("vulns<>'[]'")
    elif show == "none":
        w.append("status='none'")
    elif show == "error":
        w.append("status='error'")
    if p.get("port"):
        w.append("(',' || REPLACE(REPLACE(REPLACE(ports,'[',''),']',''),' ','') || ',') LIKE ?")
        params.append(f"%,{int(p['port'])},%")
    return ("WHERE " + " AND ".join(w)) if w else "", params


@router.get("/api/passive/results")
def passive_results(request: Request):
    p = dict(request.query_params)
    page, size = max(1, int(p.get("page") or 1)), min(1000, max(1, int(p.get("size") or 50)))
    where, params = _query(p)
    with db.get_conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM passive_results {where}", params).fetchone()[0]
        rows = [_row(r) for r in db.rows(c, f"""SELECT r.*, (SELECT lobs FROM asset_registry g WHERE g.ip=COALESCE(r.asset_ip, r.ip)) lobs
                                                FROM passive_results r {where} ORDER BY LENGTH(vulns) DESC, LENGTH(ports) DESC, scanned_at DESC
                                                LIMIT ? OFFSET ?""", params + [size, (page - 1) * size])]
    return {"total": total, "rows": rows}


@router.get("/api/passive/results/export")
def passive_export(request: Request):
    where, params = _query(dict(request.query_params))
    with db.get_conn() as c:
        rows = [_row(r) for r in db.rows(c, f"SELECT * FROM passive_results {where} ORDER BY scanned_at DESC", params)]
    for r in rows:
        for k in ("ports", "vulns", "cpes", "hostnames", "tags"):
            r[k + "_text"] = ", ".join(str(x) for x in r[k])
    return xlsx_response([("Passive scan", [("ip", "Public IP"), ("asset_ip", "Asset IP (behind NAT)"), ("asset_name", "Asset"), ("status", "Result"),
                                            ("ports_text", "Open ports"), ("vulns_text", "CVEs"), ("cpes_text", "Software (CPE)"),
                                            ("hostnames_text", "Hostnames"), ("tags_text", "Tags"), ("scanned_at", "Looked up"), ("error", "Error")], rows)],
                         "passive_scan")


@router.get("/api/asset/passive")
def asset_passive(ips: str = ""):
    """Passive-scan results for an asset: its own public IPs and the public / NAT IPs it sits behind."""
    ipl = [db.canon_ip(i) for i in ips.split(",") if i]
    if not ipl:
        return {"rows": []}
    ph = ",".join("?" * len(ipl))
    with db.get_conn() as c:
        rows = [_row(r) for r in db.rows(c, f"SELECT * FROM passive_results WHERE ip IN ({ph}) OR asset_ip IN ({ph}) ORDER BY scanned_at DESC",
                                         ipl + ipl)]
    return {"rows": rows, "demo": config.DEMO}
