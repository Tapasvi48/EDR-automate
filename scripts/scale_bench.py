"""Scale benchmark: fill a COPY of the sample database with lakhs of hosts, inventory nodes and vulnerability findings, then
time the matching pipeline and the busiest pages. Never touches data/edr_assets.db or data/demo.db.

    .venv/bin/python scripts/scale_bench.py --hosts 100000 --inventory 1000000 --vulns 2000000 [--out /tmp/scale.db] [--keep]

Prints the seconds of every step of a full re-match, of a scan upload (diff + insert), and of the main list / summary APIs."""
import argparse
import os
import random
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def ip_of(i, base=10):
    return f"{base}.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"


def build(path, n_hosts, n_inv, n_vulns, seed=7):
    rnd = random.Random(seed)
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=OFF")
    lobs = [r[0] for r in c.execute("SELECT id FROM lobs ORDER BY id")]
    msps = {l: [r[0] for r in c.execute("SELECT name FROM msps WHERE lob_id=?", (l,))] or ["MSP-A"] for l in lobs}
    t = time.time()
    # CrowdStrike agents: connection IP = inventory IP for ~70% of the nodes
    rows = []
    for i in range(n_hosts):
        ip = ip_of(i + 1_000_000)
        rows.append((f"bench{i:024x}", f"BENCH-H{i:07d}", f"bench-h{i:07d}", ip, ip, ip, rnd.choice(["Windows", "Linux"]),
                     "Windows Server 2019" if i % 2 else "RHEL 8", "7.18.1", "active", "online" if i % 5 else "offline",
                     "2026-10-04T10:00:00Z", "2026-01-01T00:00:00Z", 0, 1))
        if len(rows) == 50_000:
            c.executemany("""INSERT OR IGNORE INTO hosts(aid, hostname, hostname_norm, local_ip, connection_ip, external_ip, platform_name,
                             os_version, agent_version, console_state, online_state, last_seen, first_seen, is_reinstall, is_primary)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            rows = []
    c.executemany("""INSERT OR IGNORE INTO hosts(aid, hostname, hostname_norm, local_ip, connection_ip, external_ip, platform_name,
                     os_version, agent_version, console_state, online_state, last_seen, first_seen, is_reinstall, is_primary)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    c.execute("UPDATE hosts SET connection_ip_num=(CAST(substr(connection_ip,1,instr(connection_ip,'.')-1) AS INTEGER)) WHERE aid LIKE 'bench%'")
    c.commit()
    print(f"  hosts: {n_hosts:,} in {time.time() - t:.1f}s", flush=True)
    t = time.time()
    rows = []
    for i in range(n_inv):
        lob = lobs[i % len(lobs)]
        hi = i if i < n_hosts else None
        ip = ip_of(i + 1_000_000)
        rows.append((lob, f"b{i}", ip, f"BENCH-H{i:07d}" if hi is not None else f"NODE-{i:07d}", rnd.choice(msps[lob]),
                     rnd.choice(["Server", "VM", "Router", "Switch"]), "Live", "Windows Server 2019" if i % 2 else "RHEL 8",
                     "Yes", "Yes" if hi is not None else "No", "{}"))
        if len(rows) == 50_000:
            c.executemany("""INSERT OR IGNORE INTO inventory_current(lob_id, item_key, ip, node_name, msp, node_type, live, os, edr_feasible,
                             edr_installed, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", rows)
            rows = []
    c.executemany("""INSERT OR IGNORE INTO inventory_current(lob_id, item_key, ip, node_name, msp, node_type, live, os, edr_feasible,
                     edr_installed, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", rows)
    c.commit()
    print(f"  inventory: {n_inv:,} in {time.time() - t:.1f}s", flush=True)
    t = time.time()
    sev = [("Critical", 4), ("High", 3), ("Medium", 2), ("Low", 1), ("Info", 0)]
    rows = []
    for i in range(n_vulns):
        node = rnd.randrange(max(1, n_inv))
        s, r = sev[i % 5]
        rows.append((lobs[node % len(lobs)], f"bench|{node}|{i}", ip_of(node + 1_000_000), 167772160 + node, str(10000 + i % 5000),
                     f"Benchmark finding {i % 5000}", s, r, "tcp", str(443 + i % 7), "open", "2026-10-01T00:00:00Z"))
        if len(rows) == 100_000:
            c.executemany("""INSERT OR IGNORE INTO vuln_findings(lob_id, finding_key, ip, ip_num, plugin_id, name, severity, sev_rank, protocol,
                             port, status, last_observed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
            rows = []
    c.executemany("""INSERT OR IGNORE INTO vuln_findings(lob_id, finding_key, ip, ip_num, plugin_id, name, severity, sev_rank, protocol,
                     port, status, last_observed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    c.execute("""INSERT OR IGNORE INTO vuln_scan_hosts(lob_id, ip, scan_id, scanned_at)
                 SELECT lob_id, ip, 1, '2026-10-01T00:00:00Z' FROM vuln_findings WHERE finding_key LIKE 'bench|%' GROUP BY lob_id, ip""")
    c.commit()
    print(f"  vulnerabilities: {n_vulns:,} in {time.time() - t:.1f}s", flush=True)
    c.close()


def timed(label, fn):
    t = time.time()
    out = fn()
    print(f"{label:<44} {time.time() - t:8.2f}s", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=100_000)
    ap.add_argument("--inventory", type=int, default=300_000)
    ap.add_argument("--vulns", type=int, default=1_000_000)
    ap.add_argument("--out", default=str(ROOT / "data" / "scale_bench.db"))
    ap.add_argument("--keep", action="store_true", help="reuse an existing benchmark database")
    ap.add_argument("--only", default="", help="comma list: match,registry,pages,scan")
    a = ap.parse_args()
    out = Path(a.out)
    if not (a.keep and out.exists()):
        for suffix in ("", "-wal", "-shm"):
            Path(str(out) + suffix).unlink(missing_ok=True)
        shutil.copy(ROOT / "data" / "demo.db", out)
        print(f"building {out} …", flush=True)
        build(str(out), a.hosts, a.inventory, a.vulns)
    os.environ["DEMO"] = "1"
    os.environ["DEMO_DB_PATH"] = str(out)
    from app import db, inventory, registry  # noqa: E402 - after DEMO_DB_PATH is set
    from fastapi.testclient import TestClient
    db.init_db()  # schema upgrades of the copied sample database
    only = set(filter(None, a.only.split(",")))
    with db.get_conn() as c:
        print("rows:", dict(zip(["hosts", "inventory", "vulns", "registry"], c.execute(
            "SELECT (SELECT COUNT(*) FROM hosts),(SELECT COUNT(*) FROM inventory_current),(SELECT COUNT(*) FROM vuln_findings),"
            "(SELECT COUNT(*) FROM asset_registry)").fetchone())), flush=True)
    if not only or "match" in only:
        steps = {}
        orig = inventory.refresh_matches

        def step_timer():
            last = [time.time()]

            def cp():
                now = time.time()
                steps[len(steps) + 1] = now - last[0]
                last[0] = now
            return cp
        with db.get_conn() as c:
            timed("full re-match (refresh_matches)", lambda: orig(c, checkpoint=step_timer()))
        print("   per step:", {k: round(v, 1) for k, v in steps.items()})
    if not only or "registry" in only:
        with db.get_conn() as c:
            timed("asset registry rebuild", lambda: registry.refresh(c))
    if not only or "pages" in only:
        from app.main import app
        cl = TestClient(app)
        for path in ["/api/overview", "/api/lobs/1/inventory?page=1&size=100", "/api/lobs/1/inventory?page=500&size=100",
                     "/api/inventory/facets?lob=1", "/api/registry?page=1&size=100", "/api/exposure/summary", "/api/vulns/summary",
                     "/api/vulns/findings?page=1&size=100", "/api/vulns/findings?page=200&size=100&severity=Critical", "/api/vulns/assets?page=1&size=100",
                     "/api/search/ip?q=10.15.66.10", "/api/fabric/ontology", "/api/lobs/1/inventory?page=1&size=100&q=BENCH-H0000999"]:
            r = timed(f"GET {path[:42]}", lambda p=path: cl.get(p))
            if r.status_code != 200:
                print("   ->", r.status_code, r.text[:200])


if __name__ == "__main__":
    main()
