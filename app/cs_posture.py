"""CrowdStrike posture beyond the host list: Spotlight vulnerabilities (the agent's own vulnerability view) and prevention
policies. Both are fetched during the sync (Spotlight incrementally, see fetch_spotlight); both scopes are optional ("Vulnerabilities: Read", "Prevention policies: Read").

Spotlight covers hosts the VA scanner does not reach (laptops, segmented networks) and gives a second opinion on the ones
it does: Asset 360 lines the two up by CVE (both / Spotlight only / scanner only)."""
import json

from fastapi import APIRouter

from . import db

router = APIRouter()


OPEN = ("open", "reopen")
SPOT_COLS = ["id", "aid", "hostname", "ip", "cve", "severity", "score", "exprt", "exploit_status", "product", "remediation", "status",
             "created_at", "updated_at", "fetched_at", "title", "description", "published", "vector", "kev", "kev_due", "vendor_advisory",
             "refs", "app_vendor", "remediation_link", "raw"]


def _title(cve):
    """A readable name for the finding: Spotlight's own name when it has one, else the first sentence of the description."""
    if cve.get("name"):
        return str(cve["name"])[:200]
    d = (cve.get("description") or "").strip()
    first = d.split(". ")[0].strip().rstrip(".")
    return first[:160] + ("…" if len(first) > 160 else "")


def spot_row(v, now):
    """One Spotlight finding (combined API, facets cve / host_info / remediation / evaluation_logic) as a spotlight_vulns row."""
    import json as _json
    cve, host = v.get("cve") or {}, v.get("host_info") or {}
    rem = (v.get("remediation") or {}).get("entities") or []
    apps = v.get("apps") or []
    kev = cve.get("cisa_info") or {}
    refs = cve.get("references") or []
    return {"id": v.get("id"), "aid": v.get("aid") or "", "hostname": host.get("hostname") or "", "ip": db.canon_ip(host.get("local_ip") or ""),
            "cve": cve.get("id") or "", "severity": cve.get("severity") or "", "score": cve.get("base_score"),
            "exprt": cve.get("exprt_rating") or "", "exploit_status": cve.get("exploit_status_label") or str(cve.get("exploit_status") or ""),
            "product": ", ".join(a.get("product_name_version") or "" for a in apps if a.get("product_name_version"))[:500],
            "remediation": "; ".join(r.get("action") or r.get("title") or "" for r in rem)[:1000], "status": v.get("status") or "",
            "created_at": v.get("created_timestamp") or "", "updated_at": v.get("updated_timestamp") or "", "fetched_at": now,
            "title": _title(cve), "description": (cve.get("description") or "")[:4000], "published": cve.get("published_date") or "",
            "vector": cve.get("vector") or "", "kev": 1 if kev.get("is_cisa_kev") else 0, "kev_due": kev.get("due_date") or "",
            "vendor_advisory": ", ".join(cve.get("vendor_advisory") or [])[:1000] if isinstance(cve.get("vendor_advisory"), list) else (cve.get("vendor_advisory") or ""),
            "refs": ", ".join(str(x) for x in refs[:10])[:2000] if isinstance(refs, list) else str(refs)[:2000],
            "app_vendor": ", ".join(dict.fromkeys(a.get("vendor_normalized") or "" for a in apps if a.get("vendor_normalized")))[:300],
            "remediation_link": ", ".join(r.get("link") or "" for r in rem if r.get("link"))[:1000],
            "raw": _json.dumps(v, default=str)[:20000]}


def fetch_spotlight(client, cap=200_000, full_every_days=7):
    """Open Spotlight vulnerabilities. A full read (every open finding) runs once every `full_every_days`; the syncs in
    between ask only for findings updated since the last fetch: new and reopened ones are added, closed ones removed."""
    from datetime import datetime, timedelta, timezone
    now_dt = datetime.now(timezone.utc)
    st = db.get_settings()
    last, last_full = st.get("spotlight_last_fetch"), st.get("spotlight_last_full")
    full = (not last or not last_full or full_every_days <= 0
            or last_full < (now_dt - timedelta(days=full_every_days)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    with db.get_conn() as c:  # findings stored by an older version (no name / description / record): read everything again
        full = full or c.execute("SELECT 1 FROM spotlight_vulns WHERE raw IS NULL LIMIT 1").fetchone() is not None
    if full:
        flt = "status:['open','reopen']"
    else:
        since = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(minutes=15)
        flt = f"updated_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    now, rows, after = db.now_iso(), [], None
    while True:
        kw = {"filter": flt, "limit": 5000, "facet": ["cve", "host_info", "remediation", "evaluation_logic"]}
        if after:
            kw["after"] = after
        body = client._call(client.spotlight.query_vulnerabilities_combined, "Spotlight vulnerabilities", **kw)
        res = body.get("resources") or []
        rows += [spot_row(v, now) for v in res]
        after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
        if not res or not after or len(rows) >= cap:
            break
    keep = [r for r in rows if (r["status"] or "").lower() in OPEN]
    gone = [(r["id"],) for r in rows if (r["status"] or "").lower() not in OPEN]
    with db.get_conn() as c:
        if full:
            c.execute("DELETE FROM spotlight_vulns")
        c.executemany("DELETE FROM spotlight_vulns WHERE id=?", gone)
        c.executemany(f"INSERT OR REPLACE INTO spotlight_vulns({', '.join(SPOT_COLS)}) VALUES ({','.join('?' * len(SPOT_COLS))})",
                      [[r.get(k) for k in SPOT_COLS] for r in keep])
        upd = [("spotlight_last_fetch", now)] + ([("spotlight_last_full", now)] if full else [])
        c.executemany("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", upd)
        total = c.execute("SELECT COUNT(*) FROM spotlight_vulns").fetchone()[0]
    if full:
        return f"{total:,} open Spotlight vulnerabilities"
    return f"{total:,} open Spotlight vulnerabilities ({len(keep):,} new / updated, {len(gone):,} closed since the last sync)"


def fetch_policies(client):
    import json as _json
    body = client._call(client.prevention.query_combined_policies, "Prevention policies", limit=5000)
    rows = [(p.get("id"), p.get("name") or "", p.get("platform_name") or "", 1 if p.get("enabled") else 0, p.get("description") or "",
             p.get("modified_timestamp") or "", _json.dumps(p, default=str)) for p in body.get("resources") or []]
    with db.get_conn() as c:
        c.execute("DELETE FROM prevention_policies")
        c.executemany("INSERT OR REPLACE INTO prevention_policies(id, name, platform, enabled, description, modified_at, raw) VALUES (?,?,?,?,?,?,?)", rows)
    return f"{len(rows):,} prevention policies"


def agent_posture(c, agents):
    """Prevention policy (name, applied?), containment and reduced functionality mode, from each agent's device record."""
    names = {r["id"]: r for r in db.rows(c, "SELECT * FROM prevention_policies")}
    out = []
    for a in agents:
        raw = db.one(c, "SELECT containment_status, rfm FROM hosts WHERE aid=?", (a["aid"],)) or {}
        d = db.get_raw(c, a["aid"])
        pol = ((d.get("device_policies") or {}).get("prevention")) or {}
        p = names.get(pol.get("policy_id")) or {}
        out.append({"aid": a["aid"], "hostname": a["hostname"], "policy_id": pol.get("policy_id"), "policy": p.get("name") or pol.get("policy_id") or "",
                    "policy_enabled": p.get("enabled"), "applied": pol.get("applied"), "applied_date": pol.get("applied_date"),
                    "containment": raw.get("containment_status") or "", "rfm": raw.get("rfm") or ""})
    return out


@router.get("/api/asset/crowdstrike")
def asset_crowdstrike(aids: str = "", ips: str = ""):
    """Spotlight vulnerabilities and prevention posture for an asset's agents, with a CVE cross-check against the scanner."""
    aid_l = [a for a in aids.split(",") if a]
    ip_l = [db.canon_ip(i) for i in ips.split(",") if i]
    with db.get_conn() as c:
        spot = db.rows(c, f"""SELECT * FROM spotlight_vulns WHERE aid IN ({','.join('?' * len(aid_l))})
                              ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, score DESC
                              LIMIT 1000""", aid_l) if aid_l else []
        scanner = set()
        if ip_l:
            for r in c.execute(f"SELECT cve FROM vuln_findings WHERE status='open' AND ip IN ({','.join('?' * len(ip_l))}) AND COALESCE(cve,'')<>''",
                               ip_l):
                scanner |= {x.strip().upper() for x in r["cve"].split(",") if x.strip()}
        agents = db.rows(c, f"SELECT aid, hostname FROM hosts WHERE aid IN ({','.join('?' * len(aid_l))})", aid_l) if aid_l else []
        posture = agent_posture(c, agents)
        fetched = db.one(c, "SELECT MAX(fetched_at) at FROM spotlight_vulns")["at"]
    spot_cves = {s["cve"].upper() for s in spot if s["cve"]}
    for s in spot:
        s["in_scanner"] = s["cve"].upper() in scanner
    return {"spotlight": spot, "posture": posture, "fetched_at": fetched,
            "cross": {"both": len(spot_cves & scanner), "spotlight_only": len(spot_cves - scanner), "scanner_only": len(scanner - spot_cves),
                      "scanner_only_cves": sorted(scanner - spot_cves)[:50]}}


# ------------------------------------------------------------------ CrowdStrike → Prevention policies
def _policy_settings(raw):
    """[{category, settings: [{name, value}]}] from a prevention policy record (ML sliders as detection / prevention levels)."""
    out = []
    for cat in (db.jloads(raw, {}) or {}).get("prevention_settings") or []:
        items = []
        for s in cat.get("settings") or []:
            v = s.get("value") or {}
            if s.get("type") == "mlslider":
                val = f"detection {str(v.get('detection', '–')).lower()} · prevention {str(v.get('prevention', '–')).lower()}"
                on = str(v.get("prevention", "")).upper() not in ("", "DISABLED")
            else:
                on = bool(v.get("enabled"))
                val = "on" if on else "off"
            items.append({"name": s.get("name") or s.get("id"), "value": val, "on": on})
        out.append({"category": cat.get("name") or "", "settings": items})
    return out


@router.get("/api/crowdstrike/policies")
def cs_policies():
    """Prevention policies with how many agents run each (applied or still pending) and how many settings are on."""
    with db.get_conn() as c:
        pols = db.rows(c, "SELECT * FROM prevention_policies ORDER BY platform, name")
        counts = {r["pid"]: r for r in db.rows(c, """SELECT COALESCE(prevention_policy_id,'') pid, COUNT(*) agents,
            SUM(prevention_applied=1) applied, SUM(prevention_applied=0) pending, SUM(online_state='online') online
            FROM hosts WHERE console_state='active' AND is_primary=1 GROUP BY 1""")}
        fetched = db.one(c, "SELECT MAX(modified_at) m FROM prevention_policies")["m"]
    out = []
    for p in pols:
        st = _policy_settings(p.get("raw"))
        flat = [s for cat in st for s in cat["settings"]]
        n = counts.get(p["id"]) or {}
        raw = db.jloads(p.get("raw"), {}) or {}
        out.append({**{k: p[k] for k in ("id", "name", "platform", "enabled", "description", "modified_at")},
                    "agents": n.get("agents") or 0, "applied": n.get("applied") or 0, "pending": n.get("pending") or 0, "online": n.get("online") or 0,
                    "settings_on": sum(1 for s in flat if s["on"]), "settings_total": len(flat),
                    "groups": ", ".join(g.get("name") or "" for g in raw.get("groups") or [])})
    none = counts.get("") or {}
    return {"rows": out, "no_policy": none.get("agents") or 0, "total": len(out), "fetched_at": fetched}


@router.get("/api/crowdstrike/policies/{policy_id}")
def cs_policy(policy_id: str):
    with db.get_conn() as c:
        p = db.one(c, "SELECT * FROM prevention_policies WHERE id=?", (policy_id,))
    if not p:
        from fastapi import HTTPException
        raise HTTPException(404, "Policy not found")
    raw = db.jloads(p.pop("raw", None), {}) or {}
    return {**p, "settings": _policy_settings(json.dumps(raw)), "groups": [g.get("name") for g in raw.get("groups") or []],
            "created_by": raw.get("created_by"), "modified_by": raw.get("modified_by")}


# ------------------------------------------------------------------ CrowdStrike → Sensor versions
@router.get("/api/crowdstrike/sensors")
def cs_sensors():
    """Agents per sensor version with its N / N-1 / N-2 / older level, next to the builds CrowdStrike publishes."""
    from .queries import sensor_levels
    from .sensor_support import sensor_support_get
    with db.get_conn() as c:
        lv = {(p, v): (l, rel) for p, v, l, rel in sensor_levels(c)}
        rows = db.rows(c, """SELECT platform_name platform, agent_version version, COUNT(*) agents, SUM(online_state='online') online
                             FROM hosts WHERE console_state='active' AND is_primary=1 AND COALESCE(agent_version,'')<>''
                             GROUP BY 1, 2 ORDER BY 1, 3 DESC""")
    for r in rows:
        r["level"], r["release"] = lv.get((r["platform"] or "", r["version"]), ("", ""))
    levels = {}
    for r in rows:
        x = levels.setdefault(r["platform"] or "", {"N": 0, "N-1": 0, "N-2": 0, "older": 0})
        x[r["level"] or "older"] = x.get(r["level"] or "older", 0) + r["agents"]
    return {"fleet": rows, "levels": levels, **sensor_support_get()}
