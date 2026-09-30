"""Parsing the address and port cells of communication matrices / NAT sheets, which are written by hand in many styles.

Addresses (source / destination / NAT / public IP columns). A cell may hold any mix of:
  10.1.1.5                          single IP
  10.1.1.5, 10.1.1.6; 10.1.1.7      separated by , ; | space or new line
  10.1.1.0/24;10.2.0.0/16           subnets
  10.1.1.10-10.1.1.20 / 10.1.1.10-20   ranges, inclusive (full end address or last octet)
  10.1.55.194/195/200/201           last-octet shorthand: .194 .195 .200 .201
  10.1.1.5/10.1.1.6, 10.0.0.0/24/10.1.0.0/24   several IPs or subnets joined by /
  h-10.1.1.5, n-10.1.0.0/24, 10.1.1.5_nat, 10.1.1.5_vm     object-name prefixes / suffixes around the IP
  2101:3900:3d5a::/48, 2001:db8::10  IPv6 addresses and prefixes, with the same separators
  WEB-SRV-01, dns_servers           host / object names (kept as names; matched to inventory hostnames)
  Any, all, *, internet, 0.0.0.0/0   anything
A "/" after an IPv4 address is a prefix length when it is on a network boundary (10.1.1.192/26, 10.1.0.0/16), or 0-24 and not
just above the last octet (10.1.1.1/24). Otherwise it is last-octet shorthand: 10.1.55.194/195 = .194 and .195, 10.1.1.10/11 =
.10 and .11; a chain of numbers (a/b/c) is always shorthand.

Ports (service column): 443 · 80,443 · 8000-8100 · tcp/443 · 443/tcp · tcp_8443 · udp-53 · dns_tcp · https · any.
Service names map to their well-known ports (SERVICE_PORTS); tokens naming only a protocol (icmp, ping) carry no port."""
import ipaddress
import re
from functools import lru_cache

ANY_WORDS = {"any", "all", "*", "internet", "0.0.0.0/0", "::/0", "any4", "any6", "anyip", "all-ip", "world"}
NOT_NAMES = ANY_WORDS | {"na", "n/a", "nil", "none", "-", "tbd", "tcp", "udp", "ip", "and", "or", "to", "from", "same", "as", "above", "nat", "vm"}
_SPLIT = re.compile(r"[\s,;|\n\r]+")
_V4CHUNK = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:\s*[/\-]\s*\d{1,3}(?:\.\d{1,3}){0,3})*")
_V6TOK = re.compile(r"(?<![0-9A-Za-z])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?:/(\d{1,3}))?")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{1,62}$")


def _v4(s):
    try:
        a = ipaddress.IPv4Address(s)
        return a
    except ValueError:
        return None


def _parse_v4_chunk(chunk):
    """'10.1.55.194/195/200' -> networks. Handles CIDR, / lists, last-octet shorthand and ranges."""
    parts = [p.strip() for p in re.split(r"/", re.sub(r"\s*-\s*", "-", chunk))]
    out, last, i = [], None, 0
    while i < len(parts):
        p = parts[i]
        if "-" in p:  # range: a-b, a-N (last octet), or N-M after a shorthand base
            a, _, b = p.partition("-")
            lo = _v4(a) or (last and a.isdigit() and int(a) <= 255 and _v4(str(last).rsplit(".", 1)[0] + "." + a))
            hi = _v4(b) or (lo and b.isdigit() and int(b) <= 255 and _v4(str(lo).rsplit(".", 1)[0] + "." + b))
            if lo and hi:
                if int(hi) < int(lo):
                    lo, hi = hi, lo
                out += list(ipaddress.summarize_address_range(lo, hi))
                last = lo
            i += 1
            continue
        ip = _v4(p)
        if ip:
            nxt = parts[i + 1] if i + 1 < len(parts) else ""
            chain = len(parts) > i + 2 and all(x.isdigit() or "-" in x for x in parts[i + 1:])  # a/b/c/d = last-octet list
            if nxt.isdigit() and "-" not in nxt and not chain:
                n = int(nxt)
                last_oct = int(str(ip).rsplit(".", 1)[1])
                aligned = n <= 32 and int(ip) & ((1 << (32 - n)) - 1) == 0
                near = not aligned and last_oct < n <= last_oct + 16  # 10.1.1.10/11 = .10 and .11
                if (n <= 24 and not near) or (n <= 32 and aligned):
                    out.append(ipaddress.IPv4Network(f"{ip}/{n}", strict=False))
                    last, i = ip, i + 2
                    continue
            out.append(ipaddress.IPv4Network(f"{ip}/32"))
            last, i = ip, i + 1
            continue
        if p.isdigit() and last and int(p) <= 255:  # last-octet shorthand
            ip2 = _v4(str(last).rsplit(".", 1)[0] + "." + p)
            if ip2:
                out.append(ipaddress.IPv4Network(f"{ip2}/32"))
        i += 1
    return out


@lru_cache(maxsize=65536)
def parse_addresses(text):
    """Returns (is_any, (networks...), (names...)) for one cell."""
    t = str(text or "").replace("–", "-").replace("—", "-").replace("\\", "/").strip()
    if not t:
        return False, (), ()
    t = re.sub(r"(\d)\s*-\s*(\d)", r"\1-\2", t)
    t = re.sub(r"(\d)\s*/\s*(\d)", r"\1/\2", t)
    anyv, nets, names = False, [], []
    for tok in _SPLIT.split(t):
        if not tok:
            continue
        low = tok.lower().strip("()[]{}\"'")
        if low in ANY_WORDS:
            anyv = True
            continue
        found = False
        for m in _V4CHUNK.finditer(tok):
            got = _parse_v4_chunk(m.group(0))
            nets += got
            found = found or bool(got)
        if not found and ":" in tok:
            for m in _V6TOK.finditer(tok):
                try:
                    a = ipaddress.IPv6Address(m.group(1))
                except ValueError:
                    continue
                n = int(m.group(2)) if m.group(2) and int(m.group(2)) <= 128 else 128
                nets.append(ipaddress.IPv6Network(f"{a}/{n}", strict=False))
                found = True
        if not found:
            nm = low.strip(".-_")
            if nm not in NOT_NAMES and _NAME.match(nm) and not nm.isdigit():
                names.append(nm)
    # de-duplicate, keep order
    seen, uniq = set(), []
    for n in nets:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return anyv, tuple(uniq), tuple(dict.fromkeys(names))


SERVICE_PORTS = {
    "http": [(80, 80, "tcp")], "https": [(443, 443, "tcp")], "ssl": [(443, 443, "tcp")], "http-alt": [(8080, 8080, "tcp")],
    "https-alt": [(8443, 8443, "tcp")], "ssh": [(22, 22, "tcp")], "sftp": [(22, 22, "tcp")], "scp": [(22, 22, "tcp")],
    "telnet": [(23, 23, "tcp")], "ftp": [(20, 21, "tcp")], "ftps": [(989, 990, "tcp")], "tftp": [(69, 69, "udp")],
    "smtp": [(25, 25, "tcp")], "smtps": [(465, 465, "tcp")], "submission": [(587, 587, "tcp")], "pop3": [(110, 110, "tcp")],
    "pop3s": [(995, 995, "tcp")], "imap": [(143, 143, "tcp")], "imaps": [(993, 993, "tcp")],
    "dns": [(53, 53, None)], "domain": [(53, 53, None)], "ntp": [(123, 123, "udp")], "snmp": [(161, 161, "udp")],
    "snmptrap": [(162, 162, "udp")], "snmp-trap": [(162, 162, "udp")], "syslog": [(514, 514, None)], "ldap": [(389, 389, None)],
    "ldaps": [(636, 636, "tcp")], "kerberos": [(88, 88, None)], "radius": [(1812, 1813, "udp")], "tacacs": [(49, 49, "tcp")],
    "rdp": [(3389, 3389, "tcp")], "vnc": [(5900, 5900, "tcp")], "winrm": [(5985, 5986, "tcp")], "smb": [(445, 445, "tcp")],
    "cifs": [(445, 445, "tcp")], "microsoft-ds": [(445, 445, "tcp")], "netbios": [(137, 139, None)], "nfs": [(2049, 2049, None)],
    "mssql": [(1433, 1433, "tcp")], "sql": [(1433, 1433, "tcp")], "ms-sql": [(1433, 1433, "tcp")], "mysql": [(3306, 3306, "tcp")],
    "oracle": [(1521, 1521, "tcp")], "sqlnet": [(1521, 1521, "tcp")], "postgres": [(5432, 5432, "tcp")], "postgresql": [(5432, 5432, "tcp")],
    "mongodb": [(27017, 27017, "tcp")], "redis": [(6379, 6379, "tcp")], "netconf": [(830, 830, "tcp")], "bgp": [(179, 179, "tcp")],
    "sip": [(5060, 5061, None)], "diameter": [(3868, 3868, None)], "gtp": [(2123, 2123, "udp"), (2152, 2152, "udp")],
    "gtpc": [(2123, 2123, "udp")], "gtpu": [(2152, 2152, "udp")], "sctp": [], "icmp": [], "ping": [], "echo": [],
}
_PROTO = {"tcp", "udp", "sctp"}


@lru_cache(maxsize=16384)
def parse_ports(text):
    """None = every port; else a tuple of (low, high, protocol or None)."""
    t = str(text or "").strip().lower()
    if not t or t in ("any", "*", "all", "0-65535", "1-65535", "any/any", "ip", "tcp/udp any"):
        return None
    out = []
    for tok in re.split(r"[,;\s|\n]+", t):
        if not tok:
            continue
        if tok in ("any", "all", "*"):
            return None
        words = [w for w in re.split(r"[_\-/:.()]+", tok) if w]
        proto = next((w for w in words if w in _PROTO), None)
        nums = re.findall(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", tok)
        if nums:
            for a, b in nums:
                lo, hi = int(a), int(b or a)
                if 0 < lo <= 65535 and 0 < hi <= 65535:
                    out.append((min(lo, hi), max(lo, hi), proto))
            continue
        for w in words:
            for lo, hi, p in SERVICE_PORTS.get(w, []):
                out.append((lo, hi, proto or p))
    return tuple(out)


def ports_allow(text, port, proto=None):
    toks = parse_ports(text)
    if toks is None:
        return True
    try:
        n = int(port)
    except (TypeError, ValueError):
        return False
    return any(lo <= n <= hi and (not p or not proto or p == proto.lower()) for lo, hi, p in toks)
