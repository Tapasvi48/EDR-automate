"""CrowdStrike posture beyond the host list: Spotlight vulnerabilities (the agent's own vulnerability view) and prevention
policies. Both are fetched during the sync (Spotlight incrementally, see fetch_spotlight); both scopes are optional ("Vulnerabilities: Read", "Prevention policies: Read").

Spotlight covers hosts the VA scanner does not reach (laptops, segmented networks) and gives a second opinion on the ones
it does: Asset 360 lines the two up by CVE (both / Spotlight only / scanner only)."""
import json

from fastapi import APIRouter

from . import db

router = APIRouter()


OPEN = ("open", "reopen")


def fetch_spotlight(client, cap=200_000, full_every_days=7):
    """Open Spotlight vulnerabilities. A full read (every open finding) runs once every `full_every_days`; the syncs in
    between ask only for findings updated since the last fetch: new and reopened ones are added, closed ones removed."""
    from datetime import datetime, timedelta, timezone
    now_dt = datetime.now(timezone.utc)
    st = db.get_settings()
    last, last_full = st.get("spotlight_last_fetch"), st.get("spotlight_last_full")
    full = not last or not last_full or last_full < (now_dt - timedelta(days=full_every_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if full:
        flt = "status:['open','reopen']"
    else:
        since = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(minutes=15)
        flt = f"updated_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    now, rows, after = db.now_iso(), [], None
    while True:
        kw = {"filter": flt, "limit": 5000, "facet": ["cve", "host_info", "remediation"]}
        if after:
            kw["after"] = after
        body = client._call(client.spotlight.query_vulnerabilities_combined, "Spotlight vulnerabilities", **kw)
        res = body.get("resources") or []
        for v in res:
            cve, host = v.get("cve") or {}, v.get("host_info") or {}
            rem = (v.get("remediation") or {}).get("entities") or []
            apps = v.get("apps") or []
            rows.append((v.get("id"), v.get("aid") or "", host.get("hostname") or "", db.canon_ip(host.get("local_ip") or ""),
                         cve.get("id") or "", cve.get("severity") or "", cve.get("base_score"), cve.get("exprt_rating") or "",
                         cve.get("exploit_status_label") or str(cve.get("exploit_status") or ""),
                         ", ".join(a.get("product_name_version") or "" for a in apps if a.get("product_name_version"))[:500],
                         "; ".join(r.get("action") or r.get("title") or "" for r in rem)[:1000],
                         v.get("status") or "", v.get("created_timestamp") or "", v.get("updated_timestamp") or "", now))
        after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
        if not res or not after or len(rows) >= cap:
            break
    keep = [r for r in rows if (r[11] or "").lower() in OPEN]
    gone = [(r[0],) for r in rows if (r[11] or "").lower() not in OPEN]
    with db.get_conn() as c:
        if full:
            c.execute("DELETE FROM spotlight_vulns")
        c.executemany("DELETE FROM spotlight_vulns WHERE id=?", gone)
        c.executemany(f"INSERT OR REPLACE INTO spotlight_vulns VALUES ({','.join('?' * 15)})", keep)
        upd = [("spotlight_last_fetch", now)] + ([("spotlight_last_full", now)] if full else [])
        c.executemany("INSERT OR REPLACE INTO settings(key, value) VALUES (?,?)", upd)
        total = c.execute("SELECT COUNT(*) FROM spotlight_vulns").fetchone()[0]
    if full:
        return f"{total:,} open Spotlight vulnerabilities"
    return f"{total:,} open Spotlight vulnerabilities ({len(keep):,} new / updated, {len(gone):,} closed since the last sync)"


def fetch_policies(client):
    body = client._call(client.prevention.query_combined_policies, "Prevention policies", limit=5000)
    rows = [(p.get("id"), p.get("name") or "", p.get("platform_name") or "", 1 if p.get("enabled") else 0, p.get("description") or "",
             p.get("modified_timestamp") or "") for p in body.get("resources") or []]
    with db.get_conn() as c:
        c.execute("DELETE FROM prevention_policies")
        c.executemany("INSERT OR REPLACE INTO prevention_policies VALUES (?,?,?,?,?,?)", rows)
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
