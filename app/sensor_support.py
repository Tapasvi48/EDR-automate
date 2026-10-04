"""Which OS versions the supported CrowdStrike sensors (N, N-1, N-2) run on.

Two sources:
  * Falcon API (Sensor update policies: Read), fetched on every sync or on demand:
      - sensor builds per platform with their N / N-1 / N-2 tag -> the oldest supported sensor release per platform
      - the supported Linux kernel list -> every Linux distribution / version the N-2 (or newer) sensors support
  * an OS support catalog for everything the API does not list (Windows, macOS, non-supported systems). It starts
    from a built-in baseline and is editable on the EDR feasibility page; CrowdStrike's own Linux data and your edits
    win over the baseline. The baseline is verified against CrowdStrike's public Deployment FAQ
    (https://www.crowdstrike.com/en-us/products/faq/ - "What Windows/Linux/macOS versions does the Falcon agent
    support?"): everything under "Legacy Operating Systems with Falcon for Legacy Systems" is Legacy, everything in
    the standard lists is Supported, systems no Falcon sensor ever shipped for are Not supported. Check the baseline
    against the FAQ / your support portal once and edit what differs.

Status of an OS: Supported (current sensors run on it) | Legacy (only an old, end-of-life sensor or Falcon for Legacy
Systems) | Not supported (no Falcon sensor at all, e.g. network OS, AIX, Solaris). Matching ignores case and vendor
wording ("Red Hat Enterprise Linux 8.8" = "RHEL 8.8", "Microsoft Windows Server 2019 Standard" = "Windows Server 2019");
a pattern matches whole words / version parts and the longest matching pattern wins, so "Windows Server 2008 R2" and
"Windows Server 2008" can have different statuses."""
import json
import re

from fastapi import APIRouter, Body, HTTPException

from . import db

router = APIRouter()

KEY = "os_catalog"            # settings: your own entries (they win over CrowdStrike data and the baseline)
STATUSES = ("Supported", "Legacy", "Not supported")
# Legacy: the OS was supported by a sensor release that is now end of life. That package is no longer built,
# maintained or downloadable and the current cloud certificates do not cover it, so no supported sensor (N / N-1 / N-2)
# can be deployed on it - it needs Falcon for Legacy Systems or an extended-support agreement.
LEGACY_NOTE = ("Supported only by end-of-life sensor releases: the current N-2 (or newer) sensors do not run on it and "
               "that old sensor package is no longer maintained - needs Falcon for Legacy Systems / extended support")
_S, _L, _N = STATUSES

# platform, pattern, status, last sensor, source. Status: Supported = in CrowdStrike's current supported list; Legacy =
# "old sensors only" (a sensor release ran on it, current releases do not; still EDR feasible); Not supported = no sensor.
# Sources (checked Sep 2026):
#   FAQ    - CrowdStrike Deployment FAQ, crowdstrike.com/en-us/products/faq (current supported list, Legacy Operating Systems)
#   MAC25  - Macnica CrowdStrike update notices 2025 (distributor): Windows 7 / 2008 R2 end at Windows sensor 7.16;
#            Windows 10 v1507 and Windows 11 v22H2 locked to 7.29; macOS Ventura 13 support ended Dec 31, 2025
#   DELL   - Dell KB 000177899 "CrowdStrike Falcon Sensor System Requirements" (sensors 6.44 / 6.45 and later; macOS Big
#            Sur last supported sensor 6.57)
# Where no source names the last version, it is left blank: the console fills it from CrowdStrike's own kernel data
# (Linux) after a sync, or you set it on the OS support list.
FLS = "Falcon for Legacy Systems"
BASELINE = [
    ("Windows", "Windows 11", _S, "", "FAQ: 25H2, 24H2, 23H2, 21H2"),
    ("Windows", "Windows 11 22H2", _L, "7.29", "MAC25: end of support Apr 12, 2026; lock hosts to Windows sensor 7.29"),
    ("Windows", "Windows 10", _S, "", "FAQ: 22H2, 21H2, 1809, 1607 - other feature updates are not supported"),
    ("Windows", "Windows 10 1507", _L, "7.29", "MAC25: end of support Apr 12, 2026; lock hosts to Windows sensor 7.29"),
    ("Windows", "Windows 7", _L, "7.16", "MAC25: Windows sensor 7.16 ends support for Windows 7 SP1 / POSReady 7 (FAQ still lists it)"),
    ("Windows", "POSReady 7", _L, "7.16", "MAC25: Windows sensor 7.16 ends support"),
    ("Windows", "Windows Server 2025", _S, "", "FAQ"), ("Windows", "Windows Server 2022", _S, "", "FAQ (incl. Server Core)"),
    ("Windows", "Windows Server 2019", _S, "", "FAQ (incl. Server Core)"), ("Windows", "Windows Server 2016", _S, "", "FAQ (incl. Server Core)"),
    ("Windows", "Windows Server 2012 R2", _S, "", "FAQ"), ("Windows", "Windows Server 2012", _S, "", "FAQ (Server Core / Minimal Server not supported: DELL)"),
    ("Windows", "Windows Server 2008 R2", _L, "7.16", "MAC25: Windows sensor 7.16 ends support; ML updates and critical fixes until Dec 9, 2026"),
    ("Windows", "Windows 8.1", _L, "", "FAQ: Legacy Operating Systems (" + FLS + "); DELL: ran on sensor 6.44+"),
    ("Windows", "Windows 8", _L, FLS, "FAQ: Legacy Operating Systems"),
    ("Windows", "Windows Server 2008", _L, FLS, "FAQ: Legacy Operating Systems (SP2)"),
    ("Windows", "Windows Server 2003", _L, FLS, "FAQ: Legacy Operating Systems (SP2, incl. R2)"),
    ("Windows", "Windows Vista", _L, FLS, "FAQ: Legacy Operating Systems (SP2)"),
    ("Windows", "Windows XP", _L, FLS, "FAQ: Legacy Operating Systems (SP3 32-bit, SP2 64-bit)"),
    ("Windows", "POSReady 2009", _L, FLS, "FAQ: Legacy Operating Systems"),
    ("Windows", "Windows 2000", _N, "", "no Falcon sensor"), ("Windows", "Windows NT", _N, "", "no Falcon sensor"),
    ("macOS", "macOS 27", _S, "", "FAQ: Golden Gate 27, sensor 8.10+"), ("macOS", "Golden Gate", _S, "", "FAQ: sensor 8.10+"),
    ("macOS", "macOS 26", _S, "", "FAQ"), ("macOS", "Tahoe", _S, "", "FAQ"),
    ("macOS", "macOS 15", _S, "", "FAQ"), ("macOS", "Sequoia", _S, "", "FAQ"),
    ("macOS", "macOS 14", _S, "", "FAQ"), ("macOS", "Sonoma", _S, "", "FAQ"),
    ("macOS", "macOS 13", _L, "", "MAC25: support ended Dec 31, 2025"), ("macOS", "Ventura", _L, "", "MAC25: support ended Dec 31, 2025"),
    ("macOS", "macOS 12", _L, "", "DELL: ran on sensor 6.45+; not in the current list"), ("macOS", "Monterey", _L, "", "DELL: ran on sensor 6.45+; not in the current list"),
    ("macOS", "macOS 11", _L, "6.57", "DELL: last supported sensor version 6.57"), ("macOS", "Big Sur", _L, "6.57", "DELL: last supported sensor version 6.57"),
    ("Linux", "RHEL 10", _S, "", "FAQ: 10.2 needs sensor 7.38.19102+"), ("Linux", "RHEL 9", _S, "", "FAQ: 9.8 needs sensor 7.38.19102+"),
    ("Linux", "RHEL 8", _S, "", "FAQ: 8.10 needs sensor 7.16.16903+"), ("Linux", "RHEL 7", _S, "", "FAQ: 7.9, all supported sensor versions"),
    ("Linux", "RHEL 6", _L, "", "DELL: 6.7-6.10 on sensor 6.45+; not in the current list"),
    ("Linux", "Alma Linux 10", _S, "", "FAQ: sensor 7.38.19102+"), ("Linux", "Alma Linux 9", _S, "", "FAQ"), ("Linux", "Alma Linux 8", _S, "", "FAQ: 8.10 needs 7.16.16903+"),
    ("Linux", "Rocky Linux 10", _S, "", "FAQ: sensor 7.38.19102+"), ("Linux", "Rocky Linux 9", _S, "", "FAQ"), ("Linux", "Rocky Linux 8", _S, "", "FAQ: 8.10 needs 7.16.16903+"),
    ("Linux", "Oracle Linux 10", _S, "", "FAQ: UEK 8, sensor 7.27.18003+"), ("Linux", "Oracle Linux 9", _S, "", "FAQ: UEK 8, sensor 7.25.17804+"),
    ("Linux", "Oracle Linux 8", _S, "", "FAQ: UEK 7"), ("Linux", "Oracle Linux 7", _S, "", "FAQ: UEK 6, sensor 7.15.16803+"),
    ("Linux", "Oracle Linux 6", _L, "", "DELL: UEK 3/4 on sensor 6.45+; not in the current list"),
    ("Linux", "SLES 16", _S, "", "FAQ: sensor 7.40.19311+"), ("Linux", "SLES 15", _S, "", "FAQ: 15 SP7 needs 7.29.18202+"),
    ("Linux", "SLES 12", _S, "", "FAQ: 12 SP5, all supported sensor versions"), ("Linux", "SLES 11", _L, "", "DELL: 11.4 on sensor 6.45+; not in the current list"),
    ("Linux", "openSUSE Leap 16", _S, "", "FAQ: sensor 7.40.19311+"), ("Linux", "openSUSE Leap 15", _S, "", "FAQ: 15.6 needs 7.19.17219+"),
    ("Linux", "Ubuntu 24.04", _S, "", "FAQ: sensor 7.19.17219+"), ("Linux", "Ubuntu 22.04", _S, "", "FAQ"), ("Linux", "Ubuntu 20.04", _S, "", "FAQ"),
    ("Linux", "Ubuntu 18.04", _S, "", "FAQ"), ("Linux", "Ubuntu 16.04", _S, "", "FAQ: all supported sensor versions"),
    ("Linux", "Ubuntu 14.04", _L, "", "DELL: sensor 6.45+; not in the current list"),
    ("Linux", "CentOS 7", _S, "", "Same kernels as RHEL 7.9 (FAQ); sensor 7.32 still adds RHEL / CentOS 7 kernels"),
    ("Linux", "CentOS 8", _L, "", "DELL: 8.0-8.5 on sensor 6.45+; not in the current list"),
    ("Linux", "CentOS 6", _L, "", "DELL: 6.7-6.10 on sensor 6.45+; not in the current list"),
    ("Linux", "Debian 11", _L, "", "DELL: sensor 6.45+; not in CrowdStrike's current public list - a sync with the kernel list decides"),
    ("Linux", "Debian 10", _L, "", "DELL: sensor 6.45+; not in the current public list"), ("Linux", "Debian 9", _L, "", "DELL: 9.1-9.4 on sensor 6.45+"),
    ("Linux", "Amazon Linux 2", _L, "", "DELL: sensor 6.45+; not in CrowdStrike's current public list - a sync with the kernel list decides"),
    ("Linux", "Amazon Linux AMI", _L, "", "DELL: 2018.03 / 2017.09 on sensor 6.45+"),
    ("Other", "AIX", _N, "", "no Falcon sensor"), ("Other", "Solaris", _N, "", "no Falcon sensor"), ("Other", "HP-UX", _N, "", "no Falcon sensor"),
    ("Other", "Cisco IOS", _N, "", "network OS"), ("Other", "Cisco NX-OS", _N, "", "network OS"), ("Other", "Junos", _N, "", "network OS"),
    ("Other", "FortiOS", _N, "", "network OS"), ("Other", "PAN-OS", _N, "", "network OS"), ("Other", "Arista EOS", _N, "", "network OS"),
    ("Other", "VMware ESXi", _N, "", "hypervisor: protect the VMs"), ("Other", "z/OS", _N, "", ""), ("Other", "OS/400", _N, "", ""),
]
SOURCES = [
    ("CrowdStrike Deployment FAQ", "https://www.crowdstrike.com/en-us/products/faq/"),
    ("Macnica CrowdStrike update notices (Jul / Oct 2025)", "https://www.macnica.co.jp/en/business/security/manufacturers/crowdstrike/202510_update.html"),
    ("Dell KB 000177899 - CrowdStrike Falcon Sensor System Requirements", "https://www.dell.com/support/kbdoc/en-in/000177899/crowdstrike-falcon-sensor-system-requirements"),
]

_REWRITES = [(re.compile(p, re.I), r) for p, r in [
    (r"\(r\)|®|\(tm\)|™", ""), (r"\bmicrosoft\s+", ""), (r"\blinux kernel \S+ on\s+", ""),
    (r"red hat enterprise linux( server| workstation)?", "rhel"), (r"suse linux enterprise server|suse linux enterprise|\bsles\b", "sles"),
    (r"\balmalinux\b", "alma linux"), (r"\blinux release\b", ""), (r"\brelease\b", ""), (r"\bmac ?os ?x\b|\bos x\b", "macos"),
    (r"\boracle linux server\b|\boel\b|\bol(?=\s*\d)", "oracle linux"), (r"\bamzn\b", "amazon linux"), (r"\bjunos os\b", "junos"),
]]


def norm_os(s):
    s = (s or "").lower()
    for rx, r in _REWRITES:
        s = rx.sub(r, s)
    return " ".join(s.replace("_", " ").split())


def version_key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def release(v):
    return ".".join(re.findall(r"\d+", v or "")[:2])


# ------------------------------------------------------------------ catalog
def custom_entries(c):
    r = c.execute("SELECT value FROM settings WHERE key=?", (KEY,)).fetchone()
    return (db.jloads(r["value"], {}) if r else {}).get("entries") or []


def crowdstrike_entries(c):
    """Linux entries derived from CrowdStrike's supported-kernel list (only when it has been fetched)."""
    out = []
    for r in db.rows(c, "SELECT * FROM linux_support ORDER BY distro, version"):
        fam = FAMILIES.get(r["distro"])
        if not fam:
            continue
        status = _S if r["n2_supported"] else _L
        note = (f"CrowdStrike: {r['kernels']} kernels, sensors {r['oldest_sensor']} – {r['newest_sensor']}"
                + ("" if r["n2_supported"] else " (no N-2 or newer sensor)"))
        out.append({"platform": "Linux", "pattern": f"{fam} {r['version']}", "status": status, "note": note, "source": "crowdstrike",
                    "last_sensor": "" if r["n2_supported"] else r["newest_sensor"]})
    return out


# last sensor release known to support an OS that only old sensors run on (from CrowdStrike's system requirements);
# anything else is blank until the Linux kernel list is fetched or you fill it in on the page



def catalog(c):
    """Effective catalog: baseline < CrowdStrike Linux data < your entries (same normalised pattern = replaced)."""
    merged = {}
    for p, pat, st, last, note in BASELINE:
        merged[norm_os(pat)] = {"platform": p, "pattern": pat, "status": st, "note": note, "source": "baseline",
                                "last_sensor": last}
    for e in crowdstrike_entries(c):
        merged[norm_os(e["pattern"])] = e
    for e in custom_entries(c):
        merged[norm_os(e["pattern"])] = {**e, "source": "custom"}
    return list(merged.values())


class Classifier:
    def __init__(self, entries):
        self.rx = sorted(((len(norm_os(e["pattern"])), re.compile(r"(?<![a-z0-9])" + re.escape(norm_os(e["pattern"])) + r"(?![a-z0-9])"), e)
                          for e in entries if norm_os(e["pattern"])), key=lambda t: -t[0])
        self.cache = {}

    def __call__(self, os_):
        """-> catalog entry or None (OS unknown / not in the catalog)."""
        if not os_:
            return None
        if os_ not in self.cache:
            n = norm_os(os_)
            self.cache[os_] = next((e for _, rx, e in self.rx if rx.search(n)), None)
        return self.cache[os_]


def classifier(c):
    return Classifier(catalog(c))


# ------------------------------------------------------------------ Falcon fetch
PLATFORMS = {"windows": "Windows", "linux": "Linux"}
FAMILIES = {"rhel": "RHEL", "redhat": "RHEL", "centos": "CentOS", "oracle": "Oracle Linux", "ol": "Oracle Linux", "oel": "Oracle Linux",
            "ubuntu": "Ubuntu", "debian": "Debian", "sles": "SLES", "suse": "SLES", "amzn": "Amazon Linux", "amazon": "Amazon Linux",
            "rocky": "Rocky Linux", "alma": "Alma Linux", "almalinux": "Alma Linux"}


def _tag(build):
    for part in str(build or "").lower().split("|")[1:]:
        if re.fullmatch(r"n(-\d)?", part):
            return part.upper()
    return None


def n2_min(c):
    """{platform name as in hosts: oldest release tagged N-2 (or the oldest tagged)} from the fetched builds."""
    out = {}
    for r in db.rows(c, "SELECT platform, sensor_version, tag FROM sensor_builds WHERE tag IS NOT NULL"):
        plat = PLATFORMS.get(r["platform"], r["platform"])
        k = version_key(release(r["sensor_version"]))
        if k and (plat not in out or k < out[plat]):
            out[plat] = k
    return out


def refresh_from_falcon(client):
    """Fetch builds and supported Linux kernels; returns a one-line summary. Raises if the scope is missing."""
    now = db.now_iso()
    builds = []
    for plat in PLATFORMS:
        for b in client.sensor_builds(plat):
            builds.append((plat, b.get("sensor_version") or "", b.get("build") or "", _tag(b.get("build")), b.get("stage") or "", now))
    kernels = []
    kerr = None
    try:
        kernels = client.linux_kernels()
    except Exception as e:  # noqa: BLE001 - keep the builds even if the kernel list fails
        kerr = str(e)
    with db.get_conn() as c:
        c.execute("DELETE FROM sensor_builds")
        c.executemany("INSERT INTO sensor_builds(platform, sensor_version, build, tag, stage, fetched_at) VALUES (?,?,?,?,?,?)", builds)
        if kernels:
            store_kernels(c, kernels, now)
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES ('sensor_support_fetched', ?)",
                  (json.dumps({"at": now, "builds": len(builds), "kernels": len(kernels), "kernel_error": kerr}),))
    tagged = sum(1 for b in builds if b[3])
    return f"{tagged} tagged sensor builds · {len(kernels):,} supported Linux kernels" + (f" (kernels skipped: {kerr})" if kerr else "")


def store_kernels(c, kernels, now):
    mins = n2_min(c).get("Linux")
    agg = {}
    for k in kernels:
        distro_raw = str(k.get("distro") or "").lower()
        fam = re.match(r"[a-z]+", distro_raw)
        fam = fam.group(0) if fam else ""
        ver = str(k.get("distro_version") or "").strip() or "".join(re.findall(r"\d+", distro_raw))
        ver = ver.split(".")[0] if fam not in ("ubuntu",) else ".".join(ver.split(".")[:2])
        if fam == "ubuntu" and re.fullmatch(r"\d{2}", ver):  # ubuntu20 -> 20.04
            ver += ".04"
        if not fam or not ver:
            continue
        sensors = [*(k.get("base_package_supported_sensor_versions") or []), *(k.get("ztl_supported_sensor_versions") or []),
                   *(k.get("ztl_module_supported_sensor_versions") or [])]
        a = agg.setdefault((fam, ver), {"kernels": 0, "sensors": set(), "ztl": False})
        a["kernels"] += 1
        a["sensors"].update(s for s in sensors if re.match(r"^\d", str(s)))
        a["ztl"] |= bool(k.get("ztl_supported_sensor_versions") or k.get("ztl_module_supported_sensor_versions"))
    rows = []
    for (fam, ver), a in agg.items():
        ks = sorted(a["sensors"], key=version_key)
        newest = ks[-1] if ks else ""
        ok = a["ztl"] or (bool(newest) and (not mins or version_key(release(newest)) >= mins))
        rows.append((fam, ver, a["kernels"], newest, ks[0] if ks else "", 1 if ok else 0, now))
    c.execute("DELETE FROM linux_support")
    c.executemany("INSERT INTO linux_support(distro, version, kernels, newest_sensor, oldest_sensor, n2_supported, fetched_at) VALUES (?,?,?,?,?,?,?)", rows)


# ------------------------------------------------------------------ API
def _builds(c):
    """Published N / N-1 / N-2 builds per platform. Only the platforms we deploy: no Mac sensors are in use, so
    macOS rows (left over in sensor_builds) are left out and the page only shows the platforms actually in use."""
    out = {}
    for r in db.rows(c, "SELECT * FROM sensor_builds WHERE tag IS NOT NULL ORDER BY platform, tag"):
        if r["platform"] not in PLATFORMS:
            continue
        plat = PLATFORMS[r["platform"]]
        out.setdefault(plat, []).append(
            {"tag": r["tag"], "version": r["sensor_version"], "release": release(r["sensor_version"]), "stage": r["stage"]})
    return out


@router.get("/api/sensor-support")
def sensor_support_get():
    with db.get_conn() as c:
        cls = classifier(c)
        counts = {}
        for r in c.execute("SELECT os_resolved os, COUNT(*) n, SUM(edr_state IN ('Online','Offline')) inst FROM inventory_current "
                           "WHERE COALESCE(os_resolved,'')<>'' GROUP BY os_resolved"):
            e = cls(r["os"])
            if e:
                k = norm_os(e["pattern"])
                x = counts.setdefault(k, [0, 0])
                x[0] += r["n"]
                x[1] += r["inst"] or 0
        entries = sorted(catalog(c), key=lambda e: (["Windows", "Linux", "macOS", "Other"].index(e["platform"]) if e["platform"] in ("Windows", "Linux", "macOS", "Other") else 9,
                                                   STATUSES.index(e["status"]) if e["status"] in STATUSES else 9, e["pattern"].lower()))
        for e in entries:
            e["nodes"], e["installed"] = counts.get(norm_os(e["pattern"]), [0, 0])
        fetched = db.jloads((c.execute("SELECT value FROM settings WHERE key='sensor_support_fetched'").fetchone() or {"value": None})["value"], None)
        unmatched = db.rows(c, """SELECT os_resolved os, COUNT(*) n FROM inventory_current WHERE COALESCE(os_resolved,'')<>''
                                  AND os_support IS NULL GROUP BY os_resolved ORDER BY n DESC LIMIT 50""")
        linux = db.rows(c, "SELECT * FROM linux_support ORDER BY distro, version")
        builds = _builds(c)
    return {"builds": builds, "catalog": entries, "fetched": fetched, "unmatched": unmatched,
            "linux": linux, "statuses": STATUSES}


STATUS_LABEL = {"Supported": "Supported by current sensors", "Legacy": "Old sensors only", "Not supported": "No sensor"}


@router.get("/api/sensor-support/export")
def sensor_support_export():
    """Excel: every OS with its CrowdStrike support, the last sensor version for OS only old sensors run on, and whether
    it is EDR feasible (any sensor at all = feasible); plus the current N / N-1 / N-2 sensor builds."""
    from .exporter import xlsx_response
    d = sensor_support_get()
    # last sensor version only where a source states it; no filler for the rest
    rows = [{**e, "feasible": "No" if e["status"] == "Not supported" else "Yes", "last_sensor": e.get("last_sensor") or "",
             "source": {"custom": "Edited", "crowdstrike": "CrowdStrike API", "baseline": "Built-in"}.get(e["source"], e["source"])}
            for e in d["catalog"]]
    cols = [("platform", "Platform"), ("pattern", "OS"), ("feasible", "EDR Feasible"), ("last_sensor", "Last Sensor Version"),
            ("nodes", "Inventory Nodes"), ("installed", "With EDR"), ("note", "Source / note"), ("source", "Entry")]
    builds = [{"platform": "macOS" if p == "Mac" else p, **b} for p, bs in d["builds"].items() for b in bs]
    bcols = [("platform", "Platform"), ("tag", "Level"), ("version", "Sensor Version"), ("release", "Release"), ("stage", "Stage")]
    unmatched = [{"os": u["os"], "n": u["n"]} for u in d["unmatched"]]
    srcs = [{"name": n, "url": u} for n, u in SOURCES] + [
        {"name": "Linux rows marked 'CrowdStrike API'", "url": "your console: Sensor update policies - supported kernels (fetched on sync)"}]
    from .cs_posture import cs_sensors
    fleet = cs_sensors()["fleet"]
    fcols = [("platform", "Platform"), ("version", "Sensor Version"), ("level", "Level (N / N-1 / N-2)"), ("release", "Release"),
             ("agents", "Agents"), ("online", "Online")]
    lcols = [(k, k.replace("_", " ").title()) for k in (d["linux"][0].keys() if d["linux"] else ["distro", "version"])]
    return xlsx_response([("OS vs sensor", cols, rows), ("Sensor builds N-2", bcols, builds), ("Agents per version", fcols, fleet),
                          ("Linux kernels", lcols, d["linux"]),
                          ("OS not in list", [("os", "OS (inventory)"), ("n", "Nodes")], unmatched),
                          ("Sources", [("name", "Source"), ("url", "Link")], srcs)], "os_sensor_support")


@router.post("/api/sensor-support/refresh")
def sensor_support_refresh():
    from . import config, falcon
    if getattr(config, "DEMO", False):
        raise HTTPException(400, "Sample data mode: not connected to CrowdStrike")
    try:
        client = falcon.get_client()
        client.login()
        msg = refresh_from_falcon(client)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))
    with db.get_conn() as c:
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
    return {"ok": True, "message": msg}


@router.put("/api/sensor-support/catalog")
def sensor_support_save(data: dict = Body(...)):
    """Save your own entries: [{platform, pattern, status, note}]. An entry with the same pattern as a baseline /
    CrowdStrike entry replaces it."""
    entries = []
    for e in data.get("entries") or []:
        pat = " ".join(str(e.get("pattern") or "").split())
        if not pat:
            continue
        if e.get("status") not in STATUSES:
            raise HTTPException(400, f"Status of '{pat}' must be one of {', '.join(STATUSES)}")
        entries.append({"platform": str(e.get("platform") or "Other"), "pattern": pat, "status": e["status"], "note": str(e.get("note") or ""),
                        "last_sensor": str(e.get("last_sensor") or "").strip()})
    with db.get_conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (KEY, json.dumps({"entries": entries})))
        from .inventory import refresh_feasibility
        refresh_feasibility(c)
    return {"ok": True, "entries": len(entries)}
