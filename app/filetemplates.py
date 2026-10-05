"""Downloadable Excel templates for every file the console takes, each with a filled example and a column guide."""
import json

from fastapi import APIRouter, Body, HTTPException

from . import db

from .exporter import xlsx_response

router = APIRouter()

# kind: (title, description, status, [(column, required, meaning, example 1, example 2)])
TEMPLATES = {
    "inventory": ("LOB inventory (Standard)", "One row per node of a LOB. Upload per LOB, per MSP or per inventory type. The same IP may appear on more than one row "
                  "(e.g. two node names on one IP): every row is kept and both are tagged under Duplicates.", "live", [
        ("IP", "yes*", "Node IP (IPv4 or IPv6). *IP or Node Name is required", "10.10.4.21", "2001:db8:30::15"),
        ("Node Name", "yes*", "Hostname / node name", "RB-WEB-021", "NC-FW-015"),
        ("MSP", "", "MSP that manages the node (created automatically)", "Wipro", "Tech Mahindra"),
        ("Node Type", "", "Server, Database, Web, App, Network Device, Firewall…", "Web", "Firewall"),
        ("Domain", "", "AD / DNS domain", "retail.corp", "noc.corp"),
        ("Live/Non Live", "", "Live or Non Live", "Live", "Live"),
        ("OS", "", "Operating system with version. If blank, the OS comes from CrowdStrike or the VA scan", "RHEL 8.8", "Cisco IOS XE 17.3"),
        ("EDR Feasible", "", "Optional, informational. Feasibility is decided by the rules on the EDR feasibility page", "Yes", "No"),
        ("EDR Installed", "", "Yes / No — what the LOB says (checked against CrowdStrike)", "Yes", "No"),
        ("Remarks", "", "Free text", "Prod", "Managed by NOC"),
        ("Internet Facing", "", "Yes / No, or a zone such as DMZ / Internet — marks the node internet-exposed", "Yes", "No"),
        ("Public IP", "", "Public / NAT IP the node is reachable on from the internet", "198.51.100.21", ""),
        ("NIAM Integrated", "", "Yes / No. Blank = taken from the NIAM dump (IP found in the dump = Yes)", "Yes", ""),
        ("NE ID", "", "NIAM NE ID. Blank = the NE ID(s) of the IP in the NIAM dump", "NE-RB-00021", ""),
    ]),
    "vulnerability": ("Vulnerability scan (Nessus)", "Nessus export for one LOB. Findings missing from a rescan of the same IP are marked fixed.", "live", [
        ("S.No.", "", "Row number (ignored)", "1", "2"),
        ("IP Address", "yes", "Scanned IP", "10.10.4.21", "198.51.100.21"),
        ("Vulnerability Name", "yes", "Plugin / vulnerability name", "OpenSSL 3.0.0 < 3.0.7 Multiple Vulnerabilities", "SSL Certificate Cannot Be Trusted"),
        ("Severity", "yes", "Critical / High / Medium / Low / Info", "High", "Medium"),
        ("Protocol", "", "tcp / udp / icmp", "tcp", "tcp"),
        ("Port", "", "Port number", "443", "8443"),
        ("Synopsis", "", "", "The remote service is affected by…", ""),
        ("Description", "", "", "", ""),
        ("Steps to Remediate", "", "", "Upgrade OpenSSL to 3.0.7 or later", ""),
        ("Plugin Text", "", "Plugin output. Include plugin 11936 'OS Identification' rows (severity None): the OS is read from them", "Remote operating system : Microsoft Windows Server 2019 Standard", ""),
        ("See Also", "", "Reference links", "", ""),
        ("CVE", "", "Comma-separated CVEs", "CVE-2022-3602, CVE-2022-3786", ""),
        ("Exploit Ease", "", "Used for risk: 'Exploits are available' adds +10 on critical / high", "Exploits are available", "No known exploits are available"),
        ("Plugin ID", "", "Nessus plugin ID (recommended: identifies the finding across scans)", "168828", "51192"),
        ("First Discovered", "", "Date", "2026-06-01", "2026-07-15"),
        ("Last Observed", "", "Date (used as the scan date)", "2026-09-20", "2026-09-20"),
        ("Vuln Publication Date", "", "Date", "2022-11-01", ""),
        ("Patch Publication Date", "", "Date", "2022-11-01", ""),
        ("Remarks", "", "Free text", "", ""),
        ("Operating System", "", "Optional OS column (Tenable exports). Plugin 11936 output wins when both exist", "Microsoft Windows Server 2019", "Linux Kernel 4.18"),
    ]),
    "old_edr": ("Old EDR inventory", "An older CrowdStrike host export. Agents no longer in the console go to EDR history (counted as offline).", "live", [
        ("Host ID", "yes*", "Agent ID (AID). *AID, Hostname or Local IP is required", "4f1c…9a2e", ""),
        ("Hostname", "yes*", "", "RB-APP-044", "PAY-DB-010"),
        ("Local IP", "yes*", "", "10.10.0.54", "10.20.0.30"),
        ("OS Version", "", "", "Windows Server 2016", "RHEL 7.9"),
        ("Sensor Version", "", "", "7.05.15000", "6.45.14203"),
        ("First Seen", "", "Date", "2023-02-11", "2022-10-03"),
        ("Last Seen", "", "Date", "2025-03-30", "2024-12-18"),
        ("Domain", "", "", "retail.corp", "pay.corp"),
    ]),
    "agent_tags": ("Agent tags (AID + MSP)", "Assign CrowdStrike agents that are missing from the inventory to a LOB / MSP (they show as EDR only).", "live", [
        ("Agent ID", "yes", "AID, hostname or IP of the agent", "4f1c…9a2e", "RB-NEW-004"),
        ("MSP", "", "MSP within the LOB you upload to", "Wipro", "TCS"),
    ]),
    "niam": ("NIAM dump", "Host (IP) → NE ID. Full snapshot each time; nodes missing from a newer dump are marked dropped.", "live", [
        ("Host", "yes", "Node IP (IPv4 / IPv6); a hostname also works", "10.30.0.12", "2001:db8:30::1"),
        ("NE ID", "yes", "Network element ID", "NE-MUM-00012", "NE-DEL-00458"),
        ("NE Name", "", "", "MUM-CORE-RTR-01", "DEL-AGG-SW-12"),
        ("NE Type", "", "", "Router", "Switch"),
        ("Vendor", "", "", "Cisco", "Nokia"),
        ("Circle", "", "Circle / region", "Mumbai", "Delhi"),
    ]),
    "comm_matrix": ("Communication matrix", "Three sheet types: Firewall rules (Source Zone / ISP / Destination Zone; each row is "
                    "internet-facing when its source zone is Internet / ISP / Untrust / Outside, an ISP link is filled, or the source is "
                    "Any / a public IP), Public IP + private IP (every row exposed, both IPs linked), and Only public IP (every row "
                    "exposed). The type is guessed from the columns on upload; the ‘Which sheet to use’ sheet of the download explains "
                    "each. Exposed rows list every IP they name on Internet exposed, even when no other source knows the address.", "live", [
        ("Rule ID", "", "Unique rule / flow ID (blank = row number)", "MX-0001", "MX-0002"),
        ("Direction", "", "Inbound · Outbound · Internal (for people; exposure comes from the zone / source / ISP / NAT columns)", "Inbound", "Outbound"),
        ("Source Zone", "", "Internet / ISP / Untrust / Outside / External make the row internet-facing; DMZ, Core, OAM, NNI-Partner do not", "Internet", "OAM"),
        ("Source IP / Subnet (inside)", "yes*", "*one of Source IP, Destination Public / NAT IP or Destination IP is required. Our inside IP / CIDR / range, "
         "Any for the internet, or a partner public IP", "Any", "10.30.8.15"),
        ("Source NAT / Outside IP (public)", "", "Public IP the inside source leaves through (outbound NAT): the source becomes exposed", "", "49.36.10.30"),
        ("ISP / Link", "", "ILL / ISP link; filled = internet-facing (leave empty for partner / NNI links)", "Airtel ILL-01", "Jio ILL-02"),
        ("Destination Zone", "", "", "DMZ", "Internet"),
        ("Destination Public / NAT IP", "yes*", "Public / VIP IP (inbound NAT), or the public IP of a host with only a public IP", "49.36.10.21", ""),
        ("Destination IP / Subnet (inside)", "yes*", "Our inside IP / CIDR behind the public IP; empty for a public-IP-only host", "10.10.4.21", "Any"),
        ("Protocol", "", "tcp / udp / icmp / any", "tcp", "tcp"),
        ("Port(s)", "", "Port, list or range", "443, 8443", "443"),
        ("Service / Use", "", "", "Customer self-care portal", "Vendor patch download"),
        ("Application", "", "Also used as the name of assets only the matrix knows", "Self-care", "OSS patching"),
        ("Application Owner", "", "", "Digital Channels", "NetOps"),
        ("LOB", "", "Owner LOB (used for assets no inventory lists)", "Retail Banking", "Payments"),
        ("MS Partner", "", "", "Wipro", "TCS"),
        ("Domain", "", "", "Digital", "OAM"),
        ("Location / DC", "", "DC, circle or POP", "DC-Mumbai", "DC-Delhi"),
        ("Firewall", "", "Firewall / cluster name", "DMZ-FW-01", "EDGE-FW-02"),
        ("Firewall Rule Name", "", "", "allow-https-selfcare", "oam-out-443"),
        ("Action", "", "Allow / Deny (Deny / Drop is never internet-facing; blank = Allow)", "Allow", "Allow"),
        ("Change / SOD No.", "", "Approval reference", "SOD-2026-0931", "CR-2026-1102"),
        ("Valid Till", "", "Date, blank = permanent; past date = rule ignored", "", "2026-12-31"),
        ("Remarks", "", "", "EXPOSED - public + private (destination NAT)", "EXPOSED - outbound through source NAT"),
    ]),
    "sod": ("Vulnerability exceptions (SOD)", "Approved exceptions (SOD / risk acceptance). Matching findings are shown as Accepted, "
            "left out of open counts and risk, and reopen automatically when the exception expires.", "live", [
        ("Exception ID", "yes", "Unique ID", "SOD-2026-014", "SOD-2026-021"),
        ("Scope", "yes", "IP / Subnet / LOB / All", "IP", "Subnet"),
        ("IP / Subnet", "", "Required for IP or Subnet scope", "10.10.4.21", "10.30.0.0/24"),
        ("LOB", "", "Required for LOB scope", "", ""),
        ("Plugin ID", "yes*", "*Plugin ID, CVE or Vulnerability Name is required", "51192", ""),
        ("CVE", "", "", "", "CVE-2016-2183"),
        ("Vulnerability Name", "", "", "SSL Certificate Cannot Be Trusted", ""),
        ("Port", "", "Blank = any port", "443", ""),
        ("Justification", "yes", "Why the risk is accepted", "Internal CA; certificate trusted by all clients", "Vendor appliance; fix in next release"),
        ("Compensating Control", "", "", "Access restricted to OAM VLAN", "IPS signature 44521 enabled"),
        ("Approved By", "yes", "", "CISO", "Head of Network Security"),
        ("Approval Date", "yes", "Date", "2026-08-01", "2026-09-10"),
        ("Valid Till", "yes", "Date the exception expires", "2027-01-31", "2026-12-31"),
        ("Ticket / CR No.", "", "", "RISK-4411", "RISK-4502"),
        ("Remarks", "", "", "", ""),
    ]),
    "ndr": ("Seceon NDR alerts", "Alert export from Seceon aiXDR / OTM (or any NDR). Added to stored alerts; shown per asset on Asset 360.", "live", [
        ("Alert ID", "", "Seceon alert / incident ID (same ID = updated)", "SEC-2026-104233", "SEC-2026-104251"),
        ("Time", "yes", "When the alert was raised", "2026-09-27 14:05", "2026-09-28 02:41"),
        ("Severity", "", "Critical / High / Medium / Low, or a 0-10 / 0-100 score", "High", "Medium"),
        ("Alert Name", "yes", "Threat / detection name", "Outbound C2 beaconing", "SMB brute force"),
        ("Category / Tactic", "", "Kill-chain stage or category", "Command and Control", "Credential Access"),
        ("Source IP", "yes*", "*a Source IP, Destination IP or Host is required", "10.20.0.50", "198.51.100.44"),
        ("Destination IP", "", "", "203.0.113.9", "10.10.0.145"),
        ("Host", "", "Host name as Seceon shows it", "PAY-WEB-040", ""),
        ("Description", "", "", "Periodic HTTPS to a newly registered domain", "Repeated failed SMB logons"),
        ("Status", "", "Open / Investigating / Closed", "Open", "Closed"),
    ]),
}


FIELD = {'ndr': {'Alert ID': 'alert_id', 'Time': 'created_at', 'Severity': 'severity', 'Alert Name': 'name', 'Category / Tactic': 'category', 'Source IP': 'src_ip', 'Destination IP': 'dst_ip', 'Host': 'host', 'Description': 'description', 'Status': 'status'}, 'inventory': {'IP': 'ip', 'Node Name': 'node_name', 'MSP': 'msp', 'Node Type': 'node_type', 'Domain': 'domain', 'Live/Non Live': 'live', 'OS': 'os', 'EDR Feasible': 'edr_feasible', 'EDR Installed': 'edr_installed', 'Remarks': 'remarks', 'NIAM Integrated': 'niam_integrated', 'NE ID': 'ne_id'}, 'vulnerability': {'IP Address': 'ip', 'Vulnerability Name': 'name', 'Severity': 'severity', 'Protocol': 'protocol', 'Port': 'port', 'Synopsis': 'synopsis', 'Description': 'description', 'Steps to Remediate': 'solution', 'Plugin Text': 'plugin_text', 'See Also': 'see_also', 'CVE': 'cve', 'Exploit Ease': 'exploit_ease', 'Plugin ID': 'plugin_id', 'First Discovered': 'first_discovered', 'Last Observed': 'last_observed', 'Vuln Publication Date': 'vuln_pub_date', 'Patch Publication Date': 'patch_pub_date', 'Remarks': 'remarks', 'Operating System': 'os'}, 'old_edr': {'Host ID': 'aid', 'Hostname': 'hostname', 'Local IP': 'local_ip', 'OS Version': 'os_version', 'Sensor Version': 'agent_version', 'First Seen': 'first_seen', 'Last Seen': 'last_seen', 'Domain': 'machine_domain'}, 'agent_tags': {'Agent ID': 'id', 'MSP': 'msp'}, 'niam': {'Host': 'host', 'NE ID': 'ne_id', 'NE Name': 'ne_name', 'NE Type': 'ne_type', 'Vendor': 'vendor', 'Circle': 'circle'}, 'comm_matrix': {'Rule ID': 'rule_id', 'Direction': 'direction', 'Source Zone': 'src_zone', 'Source IP / Subnet (inside)': 'src', 'Source NAT / Outside IP (public)': 'src_nat', 'ISP / Link': 'isp', 'Firewall': 'firewall', 'Firewall Rule Name': 'fw_rule', 'Destination Zone': 'dst_zone', 'Destination Public / NAT IP': 'dst_nat', 'Destination IP / Subnet (inside)': 'dst', 'Protocol': 'protocol', 'Port(s)': 'ports', 'Service / Use': 'service', 'Application': 'application', 'Application Owner': 'app_owner', 'LOB': 'lob', 'MS Partner': 'msp', 'Domain': 'domain', 'Location / DC': 'location', 'Action': 'action', 'Change / SOD No.': 'cr', 'Valid Till': 'valid_till', 'Remarks': 'remarks'}, 'sod': {'Exception ID': 'exception_id', 'Scope': 'scope', 'IP / Subnet': 'target', 'LOB': 'lob', 'Plugin ID': 'plugin_id', 'CVE': 'cve', 'Vulnerability Name': 'name', 'Port': 'port', 'Justification': 'justification', 'Compensating Control': 'control', 'Approved By': 'approved_by', 'Approval Date': 'approval_date', 'Valid Till': 'valid_till', 'Ticket / CR No.': 'ticket', 'Remarks': 'remarks'}}


def _defaults(kind):
    t = TEMPLATES[kind]
    return {"description": t[1], "columns": [{"field": FIELD.get(kind, {}).get(c[0]), "name": c[0], "required": c[1] in ("yes", "yes*"),
                                              "required_note": c[1], "meaning": c[2], "example": c[3], "example2": c[4]} for c in t[3]]}


def config(kind, conn=None):
    """Effective template for a kind: the saved edit, or the built-in default."""
    raw = db.get_settings(conn).get("file_template:" + kind)
    saved = db.jloads(raw, None) if raw else None
    return (saved or _defaults(kind)), bool(saved)


def custom_aliases(kind):
    """{field: [header names]} from an edited template, so uploads with those headers map automatically."""
    cfg, edited = config(kind)
    if not edited:
        return {}
    out = {}
    for col in cfg["columns"]:
        if col.get("field"):
            out.setdefault(col["field"], []).append(col["name"])
    return out


@router.get("/api/file-templates")
def file_templates():
    rows = []
    with db.get_conn() as c:
        for k, t in TEMPLATES.items():
            cfg, edited = config(k, c)
            rows.append({"kind": k, "title": t[0], "description": cfg.get("description") or t[1], "status": t[2], "edited": edited,
                         "columns": [col["name"] for col in cfg["columns"]],
                         "required": [col["name"] for col in cfg["columns"] if col.get("required")]})
    return {"rows": rows}


@router.get("/api/file-templates/{kind}/config")
def file_template_config(kind: str):
    if kind not in TEMPLATES:
        raise HTTPException(404, "Unknown template")
    cfg, edited = config(kind)
    return {"kind": kind, "title": TEMPLATES[kind][0], "edited": edited, **cfg, "defaults": _defaults(kind)}


@router.put("/api/file-templates/{kind}/config")
def file_template_save(kind: str, data: dict = Body(...)):
    if kind not in TEMPLATES:
        raise HTTPException(404, "Unknown template")
    defaults = {c["field"]: c for c in _defaults(kind)["columns"] if c["field"]}
    cols, seen = [], set()
    for col in data.get("columns") or []:
        name = str(col.get("name") or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        f = col.get("field") or None
        cols.append({"field": f, "name": name, "required": bool(defaults[f]["required"]) if f in defaults else bool(col.get("required")),
                     "required_note": defaults[f]["required_note"] if f in defaults else ("yes" if col.get("required") else ""),
                     "meaning": str(col.get("meaning") or ""), "example": str(col.get("example") or ""), "example2": str(col.get("example2") or "")})
    missing = [d["name"] for f, d in defaults.items() if d["required"] and f not in {c["field"] for c in cols}]
    if missing:
        raise HTTPException(400, f"Required columns cannot be removed: {', '.join(missing)}")
    db.set_settings({"file_template:" + kind: json.dumps({"description": str(data.get("description") or TEMPLATES[kind][1]), "columns": cols})})
    return file_template_config(kind)


@router.delete("/api/file-templates/{kind}/config")
def file_template_reset(kind: str):
    with db.get_conn() as c:
        c.execute("DELETE FROM settings WHERE key=?", ("file_template:" + kind,))
    return file_template_config(kind)


@router.get("/api/file-templates/{kind}")
def file_template(kind: str):
    if kind == "comm_matrix":  # a workbook with one example sheet per sheet type
        from .commatrix import comm_template
        return comm_template()
    t = TEMPLATES.get(kind)
    if not t:
        raise HTTPException(404, "Unknown template")
    cols = config(kind)[0]["columns"]
    data_cols = [(f"c{i}", c["name"]) for i, c in enumerate(cols)]
    examples = [{f"c{i}": c.get("example", "") for i, c in enumerate(cols)}, {f"c{i}": c.get("example2", "") for i, c in enumerate(cols)}]
    guide = [{"col": c["name"], "req": {"yes": "Required", "yes*": "Required (one of)"}.get(c.get("required_note") or ("yes" if c.get("required") else ""), "Optional"),
              "meaning": c.get("meaning", "")} for c in cols]
    return xlsx_response([
        (t[0][:31], data_cols, examples),
        ("How to fill", [("col", "Column"), ("req", "Required"), ("meaning", "What to put in it")], guide),
    ], "template_" + kind)
