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

# platform, pattern, status, note. Verified against the CrowdStrike Deployment FAQ (products/faq): the standard
# Windows/Linux/macOS lists = Supported; "Legacy Operating Systems with Falcon for Legacy Systems" = Legacy.
BASELINE = [
    ("Windows", "Windows 11", _S, ""), ("Windows", "Windows 10", _S, "only the feature updates CrowdStrike lists are supported"),
    ("Windows", "Windows Server 2025", _S, ""), ("Windows", "Windows Server 2022", _S, ""),
    ("Windows", "Windows Server 2019", _S, ""), ("Windows", "Windows Server 2016", _S, ""),
    ("Windows", "Windows Server 2012 R2", _S, "in CrowdStrike's standard supported list; the OS itself needs Microsoft ESU"),
    ("Windows", "Windows Server 2012", _S, "in CrowdStrike's standard supported list; the OS itself needs Microsoft ESU"),
    ("Windows", "Windows 8.1", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"), ("Windows", "Windows 8", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"),
    ("Windows", "Windows 7", _S, "in CrowdStrike's standard supported list (SP1); the OS itself needs Microsoft ESU"),
    ("Windows", "Windows Server 2008 R2", _S, "in CrowdStrike's standard supported list (SP1); the OS itself needs Microsoft ESU"),
    ("Windows", "Windows Server 2008", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"),
    ("Windows", "Windows Server 2003", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"), ("Windows", "Windows XP", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"),
    ("Windows", "Windows Vista", _L, "FAQ: Legacy Operating Systems - Falcon for Legacy Systems only"),
    ("Windows", "Windows 2000", _N, "no Falcon sensor"),
    ("Windows", "Windows NT", _N, "no Falcon sensor"),
    ("macOS", "macOS 26", _S, ""), ("macOS", "Tahoe", _S, ""), ("macOS", "macOS 15", _S, ""), ("macOS", "Sequoia", _S, ""),
    ("macOS", "macOS 14", _S, ""), ("macOS", "Sonoma", _S, ""),
    ("macOS", "macOS 13", _L, "FAQ: not on the current list - only sensor 6.x (<= 6.57) ever ran on it: " + LEGACY_NOTE), ("macOS", "Ventura", _L, LEGACY_NOTE),
    ("macOS", "macOS 12", _L, LEGACY_NOTE), ("macOS", "Monterey", _L, LEGACY_NOTE),
    ("macOS", "macOS 11", _L, LEGACY_NOTE), ("macOS", "Big Sur", _L, LEGACY_NOTE), ("macOS", "Catalina", _L, LEGACY_NOTE),
    ("Linux", "RHEL 10", _S, ""), ("Linux", "RHEL 9", _S, ""), ("Linux", "RHEL 8", _S, ""),
    ("Linux", "RHEL 7", _S, "7.9 in CrowdStrike's current supported list: Red Hat ELS only - confirm the kernel is on the supported-kernel list"),
    ("Linux", "RHEL 6", _L, LEGACY_NOTE), ("Linux", "RHEL 5", _N, "no supported sensor and no kernel on the supported-kernel list"),
    ("Linux", "CentOS Stream 9", _S, ""), ("Linux", "CentOS 8", _S, "vendor end of life: ELS/ESM style support needed"),
    ("Linux", "CentOS 7", _S, "vendor end of life Jun 2024 - RHEL 7.9 kernels are still on CrowdStrike's list, confirm the kernel"),
    ("Linux", "CentOS 6", _L, LEGACY_NOTE), ("Linux", "CentOS 5", _N, ""),
    ("Linux", "Oracle Linux 10", _S, ""), ("Linux", "Oracle Linux 9", _S, ""), ("Linux", "Oracle Linux 8", _S, ""), ("Linux", "Oracle Linux 7", _S, ""),
    ("Linux", "Oracle Linux 6", _L, LEGACY_NOTE),
    ("Linux", "Rocky Linux 10", _S, ""), ("Linux", "Rocky Linux 9", _S, ""), ("Linux", "Rocky Linux 8", _S, ""),
    ("Linux", "Alma Linux 10", _S, ""), ("Linux", "Alma Linux 9", _S, ""), ("Linux", "Alma Linux 8", _S, ""),
    ("Linux", "Ubuntu 24.04", _S, ""), ("Linux", "Ubuntu 22.04", _S, ""), ("Linux", "Ubuntu 20.04", _S, ""),
    ("Linux", "Ubuntu 18.04", _S, "FAQ: all supported sensor versions; Ubuntu Pro / ESM"),
    ("Linux", "Ubuntu 16.04", _S, "FAQ: all supported sensor versions; vendor LTS ended - Ubuntu Pro / ESM recommended"),
    ("Linux", "Ubuntu 14.04", _L, "not in CrowdStrike's current list - only sensor 6.x (>= 6.48) ever ran on it: " + LEGACY_NOTE),
    ("Linux", "Debian 12", _S, ""), ("Linux", "Debian 11", _S, ""), ("Linux", "Debian 10", _S, "vendor LTS ended: check the kernel"),
    ("Linux", "Debian 9", _L, LEGACY_NOTE),
    ("Linux", "SLES 16", _S, ""), ("Linux", "SLES 15", _S, ""), ("Linux", "SLES 12", _S, "FAQ: 12.5 - all supported sensor versions"), ("Linux", "SLES 11", _L, LEGACY_NOTE),
    ("Linux", "Amazon Linux 2023", _S, ""), ("Linux", "Amazon Linux 2", _S, ""), ("Linux", "Amazon Linux AMI", _L, LEGACY_NOTE),
    ("Other", "AIX", _N, "no Falcon sensor"), ("Other", "Solaris", _N, "no Falcon sensor"), ("Other", "HP-UX", _N, "no Falcon sensor"),
    ("Other", "Cisco IOS", _N, "network OS: no sensor, protect it through the network"), ("Other", "Cisco NX-OS", _N, "network OS"),
    ("Other", "Junos", _N, "network OS"), ("Other", "FortiOS", _N, "network OS"), ("Other", "PAN-OS", _N, "network OS"),
    ("Other", "Arista EOS", _N, "network OS"), ("Other", "VMware ESXi", _N, "hypervisor: no sensor, protect the VMs"),
    ("Other", "z/OS", _N, ""), ("Other", "OS/400", _N, ""),
]

_REWRITES = [(re.compile(p, re.I), r) for p, r in [
    (r"\(r\)|®|\(tm\)|™", ""), (r"\bmicrosoft\s+", ""), (r"\blinux kernel [\d.x\-]+ on\s+", ""),
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
        out.append({"platform": "Linux", "pattern": f"{fam} {r['version']}", "status": status, "note": note, "source": "crowdstrike"})
    return out


def catalog(c):
    """Effective catalog: baseline < CrowdStrike Linux data < your entries (same normalised pattern = replaced)."""
    merged = {}
    for p, pat, st, note in BASELINE:
        merged[norm_os(pat)] = {"platform": p, "pattern": pat, "status": st, "note": note, "source": "baseline"}
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
        from .inventory import refresh_matches
        refresh_matches(c)
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
        entries.append({"platform": str(e.get("platform") or "Other"), "pattern": pat, "status": e["status"], "note": str(e.get("note") or "")})
    with db.get_conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (KEY, json.dumps({"entries": entries})))
        from .inventory import refresh_matches
        refresh_matches(c)
    return {"ok": True, "entries": len(entries)}
