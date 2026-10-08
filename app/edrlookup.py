"""EDR lookup: match any uploaded list (an IP column and / or a hostname column) to CrowdStrike and hand back the same file
with EDR columns appended. Stand-alone and read-only: nothing is stored, inventories and every other page are untouched.

Matched against every EDR asset: agents in the console (online / offline / inactive), agents removed from it and the old EDR
inventory import. The steps are the ones LOB inventory matching uses (inventory.refresh_matches), re-implemented here so that
feature is not touched:
  1. the IP is an agent's connection IP                         (+ same hostname, when there is one, picks among several)
  2. the IP is an earlier connection IP of the agent (history)  -> with the same hostname (by IP only: noted as such)
  3. same hostname                                              (hostname, case-insensitive, domain dropped)
  4. the IP is a NAT IP / the private IP behind one / an agent's external IP -> when exactly one active agent sits behind it
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, HTTPException, Request

from . import db, inventory
from .exporter import xlsx_response

router = APIRouter()

MODES = {"both": "IP and hostname", "ip": "IP only", "hostname": "Hostname only"}
OUT = [("edr_status", "EDR Status"), ("edr_match", "EDR Match Method"), ("cs_hostname", "CrowdStrike Hostname"), ("cs_aid", "CrowdStrike AID"),
       ("cs_os", "OS (CrowdStrike)"), ("cs_platform", "Platform"), ("cs_agent", "Sensor Version"), ("cs_last_seen", "EDR Last Seen"),
       ("cs_first_seen", "EDR First Seen"), ("cs_conn_ip", "Connection IP"), ("cs_ext_ip", "External IP"), ("cs_agents", "Agents Matching")]


def _ts(ts):
    return ts or ""


class Matcher:
    """Indexes of every non-hidden CrowdStrike asset (console, removed, old EDR import), built once per lookup."""

    def __init__(self, c):
        st = db.get_settings(c)
        self.stale_cut = (datetime.now(timezone.utc) - timedelta(days=float(st.get("inventory_stale_days") or 7))).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.hosts, self.by_conn, self.by_nic, self.by_hn, self.by_ext = {}, {}, {}, {}, {}
        for r in db.rows(c, """SELECT aid, hostname, hostname_norm, local_ip, connection_ip, external_ip, console_state, online_state,
                               last_seen, first_seen, agent_version, os_version, platform_name, removal_type FROM hosts
                               WHERE console_state<>'hidden'"""):
            self.hosts[r["aid"]] = r
            if r["connection_ip"]:
                self.by_conn.setdefault(r["connection_ip"], set()).add(r["aid"])
            if r["hostname_norm"]:
                self.by_hn.setdefault(r["hostname_norm"], set()).add(r["aid"])
            if r["external_ip"]:
                self.by_ext.setdefault(r["external_ip"], set()).add(r["aid"])
        for r in c.execute("""SELECT DISTINCT ih.ip, ih.aid FROM ip_history ih JOIN hosts h ON h.aid=ih.aid
                              WHERE ih.kind='connection' AND h.console_state<>'hidden'"""):
            self.by_nic.setdefault(r["ip"], set()).add(r["aid"])
        from .commatrix import nat_map
        self.nat = nat_map(c)
        self.back = {}
        for pub, privs in self.nat.items():
            for p in privs:
                self.back.setdefault(p, set()).add(pub)

    def _rank(self, aid):
        h = self.hosts[aid]
        return ({"active": 0, "hidden": 1}.get(h["console_state"], 2), -(inventory._ts_num(h["last_seen"])))

    def status(self, h):
        if h["console_state"] == "removed":
            return "Old EDR import" if h["removal_type"] == "imported" else "Removed from console"
        if h["online_state"] == "online":
            return "Online"
        return "Inactive" if (h["last_seen"] or "") < self.stale_cut else "Offline"

    def match(self, ip, hostname, mode="both"):
        ip = db.canon_ip((ip or "").strip()) if ip and mode != "hostname" else ""
        hn = db.norm_hostname(hostname) if hostname and mode != "ip" else ""
        conn = self.by_conn.get(ip, set()) if ip else set()
        nic = (self.by_nic.get(ip, set()) - conn) if ip else set()
        same = self.by_hn.get(hn, set()) if hn else set()
        method, pool = None, set()
        if conn:
            named = conn & same
            method, pool = ("connection ip + hostname", named) if named else ("connection ip", conn)
        elif nic & same:
            method, pool = "earlier ip + hostname", nic & same
        elif same:
            method, pool = "hostname", same
        elif ip and (self.nat.get(ip) or self.back.get(ip) or self.by_ext.get(ip)):
            via = set()
            for x in self.nat.get(ip, set()) | self.back.get(ip, set()):
                via |= self.by_conn.get(x, set()) | self.by_nic.get(x, set())
            via |= self.by_ext.get(ip, set())
            active = {a for a in via if self.hosts[a]["console_state"] == "active"}
            if len(active) == 1:
                method, pool = "nat / external ip", active
        if not pool and nic and not hn:  # IP only, seen earlier on an agent: reported, flagged as unconfirmed
            method, pool = "earlier ip (no hostname to confirm)", nic
        if not pool:
            return {"edr_status": "IP used by another host" if nic else "Not found", "edr_match": "", "cs_agents": 0}
        best = sorted(pool, key=self._rank)[0]
        h = self.hosts[best]
        return {"edr_status": self.status(h), "edr_match": method, "cs_hostname": h["hostname"], "cs_aid": h["aid"],
                "cs_os": h["os_version"], "cs_platform": h["platform_name"], "cs_agent": h["agent_version"],
                "cs_last_seen": _ts(h["last_seen"]), "cs_first_seen": _ts(h["first_seen"]), "cs_conn_ip": h["connection_ip"],
                "cs_ext_ip": h["external_ip"], "cs_agents": len(pool)}


def _guess(headers):
    norm = {h: "".join(ch for ch in str(h).lower() if ch.isalnum()) for h in headers}
    ip = next((h for h in headers if norm[h] in ("ip", "ipaddress", "hostip", "privateip", "localip", "nodeip", "serverip", "address")), None) \
        or next((h for h in headers if "ip" in norm[h]), None)
    hn = next((h for h in headers if norm[h] in ("hostname", "host", "nodename", "devicename", "servername", "computername", "name")), None) \
        or next((h for h in headers if "host" in norm[h] or "name" in norm[h]), None)
    return ip, hn


def _run(data):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    headers = parsed["headers"]
    ip_col, hn_col, mode = data.get("ip_col") or "", data.get("host_col") or "", data.get("mode") or "both"
    if mode not in MODES:
        raise HTTPException(400, "Unknown match mode")
    if mode in ("both", "ip") and ip_col and ip_col not in headers or hn_col and hn_col not in headers:
        raise HTTPException(400, "Pick columns from this sheet")
    if (mode == "ip" and not ip_col) or (mode == "hostname" and not hn_col) or (mode == "both" and not (ip_col or hn_col)):
        raise HTTPException(400, "Pick the IP column and / or the hostname column")
    ii = headers.index(ip_col) if ip_col else None
    hi = headers.index(hn_col) if hn_col else None
    with db.get_conn() as c:
        m = Matcher(c)
    out = []
    for r in parsed["rows"]:
        cell = lambda i: str(r[i] if i is not None and i < len(r) and r[i] is not None else "").strip()  # noqa: E731
        res = m.match(cell(ii), cell(hi), mode)
        out.append(({f"c{i}": (r[i] if i < len(r) else "") for i in range(len(headers))}, res))
    return parsed, headers, out


@router.post("/api/edr-lookup/parse")
def lookup_parse(data: dict = Body(...)):
    parsed = inventory.parse_upload(data["token"], data.get("sheet"), data.get("header_row"))
    ip, hn = _guess(parsed["headers"])
    return {"token": data["token"], "filename": parsed["filename"], "sheets": parsed["sheets"], "sheet": parsed["sheet"],
            "header_row": parsed["header_row"], "headers": parsed["headers"], "row_count": len(parsed["rows"]),
            "sample": parsed["rows"][:5], "ip_col": ip, "host_col": hn, "mode": "both" if ip and hn else ("ip" if ip else "hostname"),
            "modes": [{"value": k, "label": v} for k, v in MODES.items()]}


@router.post("/api/edr-lookup/preview")
def lookup_preview(data: dict = Body(...)):
    _, headers, out = _run(data)
    counts = {}
    for _, res in out:
        counts[res["edr_status"]] = counts.get(res["edr_status"], 0) + 1
    order = ["Online", "Offline", "Inactive", "Removed from console", "Old EDR import", "IP used by another host", "Not found"]
    key = lambda col: f"c{headers.index(col)}" if col in headers else None  # noqa: E731
    ki, kh = key(data.get("ip_col")), key(data.get("host_col"))
    return {"rows": len(out), "counts": [[k, counts[k]] for k in order if k in counts] + [[k, v] for k, v in counts.items() if k not in order],
            "sample": [{"ip": orig.get(ki, "") if ki else "", "hostname": orig.get(kh, "") if kh else "", **res} for orig, res in out[:30]]}


@router.get("/api/edr-lookup/export")
def lookup_export(request: Request):
    p = dict(request.query_params)
    if p.get("header_row"):
        p["header_row"] = int(p["header_row"])
    parsed, headers, out = _run(p)
    cols = [(f"c{i}", h or f"Column {i + 1}") for i, h in enumerate(headers)] + OUT
    rows = [{**orig, **res} for orig, res in out]
    counts = {}
    for _, res in out:
        counts[res["edr_status"]] = counts.get(res["edr_status"], 0) + 1
    summary = [{"k": "File", "v": parsed["filename"]}, {"k": "Matched by", "v": MODES[p.get("mode") or "both"]},
               {"k": "IP column", "v": p.get("ip_col") or "–"}, {"k": "Hostname column", "v": p.get("host_col") or "–"},
               {"k": "Rows", "v": len(out)}, *[{"k": k, "v": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])],
               {"k": "Matched against", "v": "every CrowdStrike asset: in the console, removed from it, and the old EDR inventory import"}]
    base = (parsed["filename"].rsplit(".", 1)[0] or "lookup")[:40]
    return xlsx_response([((parsed["sheet"] or "Lookup")[:31], cols, rows), ("Summary", [("k", "Item"), ("v", "Value")], summary)],
                         f"{base}_with_edr")
