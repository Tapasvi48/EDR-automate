"""CQL (CrowdStrike Query Language — the LogScale query language of Falcon NG-SIEM / Event Search) for threat hunting:
generate, check, explain and run hunting queries, built so a small on-prem model (4B–8B) produces correct queries.

Why it works with a small model:
  * The model does not write CQL text. It fills a small JSON query plan — one event type, filters (field, operator, value),
    an output shape — forced by a JSON schema whose event / field / operator values are enums. The plan is compiled to CQL by
    code, so syntax is always right, values are escaped, and fields always exist on the chosen event.
  * Retrieval first: the question is matched against a library of ~45 tested hunting queries (MITRE-tagged) and the
    analyst's saved queries; the closest ones are the model's few-shot examples (question -> plan), so it copies a proven
    shape instead of inventing one.
  * Grounding after: IPs, hashes, domains, users and hostnames found in the question by regex are checked against the plan and
    injected if the model dropped them; the time range comes from the question.
  * Without a model (or when it fails) the same retrieval + entity rules produce the query, so hunting always works.
  * A free-form mode (the model writes CQL directly, for larger models) goes through the auto-fixer and linter: common
    SQL / SPL / KQL habits (WHERE, ==, | stats count by, | limit, | sort by) are rewritten and unknown functions / fields flagged.

Running: direct CrowdStrike API (FalconPy, NG-SIEM StartSearchV1 / GetSearchStatusV1) when credentials are set, else the Falcon
MCP server, else (sample-data mode) a local evaluator over synthetic endpoint telemetry. Saved queries feed the retrieval."""
import difflib
import json
import math
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, HTTPException

from . import db

router = APIRouter()


class CqlError(ValueError):
    pass


# ------------------------------------------------------------------ Falcon event schema (the events hunters use most)
# name: (what it is, fields, default table columns)
EVENTS = {
    "ProcessRollup2": ("a process started (Windows, Linux, Mac)",
                       ["FileName", "ImageFileName", "FilePath", "CommandLine", "ParentBaseFileName", "UserName", "UserSid", "SHA256HashData",
                        "MD5HashData", "TargetProcessId", "ParentProcessId", "RawProcessId"],
                       ["@timestamp", "ComputerName", "UserName", "ParentBaseFileName", "FileName", "CommandLine"]),
    "NetworkConnectIP4": ("an outbound network connection (IPv4)",
                          ["RemoteAddressIP4", "RemotePort", "LocalPort", "Protocol", "ContextProcessId"],
                          ["@timestamp", "ComputerName", "LocalAddressIP4", "RemoteAddressIP4", "RemotePort"]),
    "NetworkReceiveAcceptIP4": ("an inbound network connection accepted (IPv4)",
                                ["RemoteAddressIP4", "RemotePort", "LocalPort", "Protocol", "ContextProcessId"],
                                ["@timestamp", "ComputerName", "RemoteAddressIP4", "LocalPort"]),
    "NetworkListenIP4": ("a process listening on a port", ["LocalPort", "Protocol", "ContextProcessId"], ["@timestamp", "ComputerName", "LocalPort"]),
    "DnsRequest": ("a DNS lookup", ["DomainName", "RequestType", "ContextProcessId"], ["@timestamp", "ComputerName", "DomainName"]),
    "UserLogon": ("a successful logon", ["UserName", "UserSid", "LogonType", "LogonDomain", "LogonServer", "RemoteAddressIP4", "AuthenticationPackage"],
                  ["@timestamp", "ComputerName", "UserName", "LogonType", "RemoteAddressIP4"]),
    "UserLogonFailed2": ("a failed logon", ["UserName", "LogonType", "LogonDomain", "RemoteAddressIP4", "SubStatus"],
                         ["@timestamp", "ComputerName", "UserName", "LogonType", "RemoteAddressIP4"]),
    "NewExecutableWritten": ("a new executable file written to disk", ["TargetFileName", "FileName", "ContextProcessId"],
                             ["@timestamp", "ComputerName", "TargetFileName"]),
    "PeFileWritten": ("a PE (Windows executable) file written", ["TargetFileName", "FileName", "SHA256HashData", "ContextProcessId"],
                      ["@timestamp", "ComputerName", "TargetFileName", "SHA256HashData"]),
    "AsepValueUpdate": ("an autostart (ASEP) registry value changed, e.g. Run keys", ["RegObjectName", "RegValueName", "RegStringValue", "ContextProcessId"],
                        ["@timestamp", "ComputerName", "RegObjectName", "RegValueName", "RegStringValue"]),
    "ScheduledTaskRegistered": ("a scheduled task was created", ["TaskName", "TaskExecCommand", "TaskExecArguments", "TaskAuthor"],
                                ["@timestamp", "ComputerName", "TaskName", "TaskExecCommand", "TaskAuthor"]),
    "CommandHistory": ("commands typed in a console window", ["CommandHistory", "ApplicationName"], ["@timestamp", "ComputerName", "CommandHistory"]),
    "ImageHash": ("a module / DLL loaded", ["FileName", "ImageFileName", "SHA256HashData", "MD5HashData", "ContextProcessId"],
                  ["@timestamp", "ComputerName", "ImageFileName", "SHA256HashData"]),
}
COMMON = ["@timestamp", "aid", "cid", "ComputerName", "event_platform", "#event_simpleName", "LocalAddressIP4", "aip", "@rawstring", "_count"]
NUMERIC = {"RemotePort", "LocalPort", "LogonType", "RequestType", "Protocol", "TargetProcessId", "ParentProcessId", "RawProcessId",
           "ContextProcessId", "SubStatus", "_count"}
EXACT = {"RemoteAddressIP4", "LocalAddressIP4", "SHA256HashData", "MD5HashData", "aid"}
ALL_FIELDS = sorted({f for _, fs, _ in EVENTS.values() for f in fs} | set(COMMON) - {"#event_simpleName", "@rawstring", "_count", "cid", "aip"})
FIELD_HELP = {
    "FileName": "process / file name, e.g. powershell.exe", "ImageFileName": "full path of the executable", "CommandLine": "full command line",
    "ParentBaseFileName": "parent process name", "UserName": "account name", "SHA256HashData": "SHA256 of the file", "MD5HashData": "MD5 of the file",
    "RemoteAddressIP4": "remote IPv4 address", "RemotePort": "remote port", "LocalPort": "local port", "DomainName": "domain looked up",
    "LogonType": "2 interactive, 3 network, 10 remote interactive (RDP)", "ComputerName": "hostname", "aid": "agent ID",
    "event_platform": "Win, Lin or Mac", "TaskExecCommand": "program the task runs", "RegObjectName": "registry key", "RegStringValue": "registry value data",
    "TargetFileName": "path of the file written", "LocalAddressIP4": "the host's own IP",
}
SYNONYMS = {"process": "FileName", "processname": "FileName", "filename": "FileName", "image": "ImageFileName", "path": "ImageFileName", "filepath": "ImageFileName",
            "cmd": "CommandLine", "cmdline": "CommandLine", "commandline": "CommandLine", "command": "CommandLine", "host": "ComputerName",
            "hostname": "ComputerName", "computer": "ComputerName", "device": "ComputerName", "user": "UserName", "username": "UserName", "account": "UserName",
            "parent": "ParentBaseFileName", "parentprocess": "ParentBaseFileName", "parentname": "ParentBaseFileName", "ip": "RemoteAddressIP4",
            "remoteip": "RemoteAddressIP4", "destip": "RemoteAddressIP4", "dstip": "RemoteAddressIP4", "destinationip": "RemoteAddressIP4",
            "port": "RemotePort", "destport": "RemotePort", "dstport": "RemotePort", "remoteport": "RemotePort", "domain": "DomainName",
            "query": "DomainName", "sha256": "SHA256HashData", "hash": "SHA256HashData", "md5": "MD5HashData", "localip": "LocalAddressIP4",
            "platform": "event_platform", "os": "event_platform", "logontype": "LogonType", "srcip": "RemoteAddressIP4", "sourceip": "RemoteAddressIP4"}

FUNCS = {"groupBy", "table", "select", "sort", "head", "tail", "count", "top", "stats", "sum", "avg", "min", "max", "timeChart", "bucket", "rename",
         "drop", "lower", "upper", "in", "regex", "wildcard", "test", "default", "format", "formatTime", "eval", "case", "match", "join", "defineTable",
         "selfJoinFilter", "collect", "series", "ipLocation", "asn", "cidr", "replace", "splitString", "length", "concat", "coalesce", "fieldstats",
         "sankey", "worldMap", "readFile", "transpose", "session", "window", "partition", "percentile", "range", "selectLast", "selectFromMax",
         "selectFromMin", "fieldset", "dedup", "shannonEntropy", "base64Decode", "urlDecode", "parseUrl", "parseJson", "kvParse", "lowercase",
         "now", "unit:convert", "array:filter", "array:contains", "text:contains", "math:abs", "time:hour", "time:dayOfWeekName", "if", "createEvents",
         "rdns", "geohash", "linReg", "neighbor", "accumulate", "slidingWindow", "dropEvent", "setField", "getField", "copyEvent", "hash", "tokenHash",
         "crypto:md5", "sha256", "md5", "eventSize", "duration", "formatDuration", "parseTimestamp", "findTimestamp", "split", "groupby"} - {"groupby", "dedup"}
FILTER_FUNCS = {"in", "regex", "wildcard", "test", "cidr", "match", "text:contains", "array:contains"}


# ------------------------------------------------------------------ parser
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*|/\*.*?\*/)
  | (?P<string>"(?:\\.|[^"\\])*")
  | (?P<op>:=|=~|!=|<=|>=|=|<|>|!)
  | (?P<punct>[()\[\],])
  | (?P<word>[^\s()\[\],"=!<>|]+)
""", re.X | re.S)


def split_pipes(q):
    """Split a CQL query into its pipeline stages (respecting strings, regexes, comments and brackets)."""
    stages, cur, i, depth, n = [], [], 0, 0, len(q)
    prev = ""
    while i < n:
        ch = q[i]
        if ch == '"':
            j = i + 1
            while j < n and q[j] != '"':
                j += 2 if q[j] == "\\" else 1
            if j >= n:
                raise CqlError('a string "…" is not closed')
            cur.append(q[i:j + 1])
            i, prev = j + 1, '"'
            continue
        if ch == "/" and i + 1 < n and q[i + 1] == "/" and (not prev.strip() or prev in "|"):
            j = q.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and q[i + 1] == "*":
            j = q.find("*/", i + 2)
            if j < 0:
                raise CqlError("a /* comment */ is not closed")
            i = j + 2
            continue
        if ch == "/" and (prev in "=(,[!~" or not prev.strip() or prev == "|") and not (i + 1 < n and q[i + 1] in " \t\n"):
            j = i + 1
            while j < n and q[j] != "/":
                if q[j] == "\n":
                    break
                j += 2 if q[j] == "\\" else 1
            if j >= n or q[j] != "/":
                raise CqlError("a /regex/ is not closed")
            j += 1
            while j < n and q[j] in "gimsx":
                j += 1
            cur.append(q[i:j])
            i, prev = j, "/"
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                raise CqlError(f"unbalanced '{ch}'")
        if ch == "|" and depth == 0:
            stages.append("".join(cur).strip())
            cur, i, prev = [], i + 1, "|"
            continue
        cur.append(ch)
        if not ch.isspace():
            prev = ch
        elif prev not in "=(,[!|":
            prev = " "
        i += 1
    if depth != 0:
        raise CqlError("unbalanced brackets: a '(' or '[' is not closed")
    stages.append("".join(cur).strip())
    return [s for s in stages if s]


def _tokens(stage):
    out, i = [], 0
    while i < len(stage):
        ch = stage[i]
        if ch == "/" and (not out or out[-1][0] in ("op", "punct") or out[-1][1] in ("or", "and", "not", "OR", "AND", "NOT")):
            m = re.match(r"/((?:\\.|[^/\\])*)/([gimsx]*)", stage[i:])
            if m:
                out.append(("regex", (m.group(1), m.group(2))))
                i += m.end()
                continue
        m = _TOKEN.match(stage, i)
        if not m:
            raise CqlError(f"cannot read the query near: {stage[i:i + 20]!r}")
        kind = m.lastgroup
        if kind not in ("ws", "comment"):
            val = m.group(kind)
            if kind == "string":
                val = json.loads(val) if "\\" not in val else val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            out.append((kind, val))
        i = m.end()
    return out


class _P:
    """Recursive-descent parser over one stage's tokens."""

    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect(self, kind, val=None):
        tok = self.take()
        if tok[0] != kind or (val is not None and tok[1] != val):
            raise CqlError(f"expected {val or kind} but found {tok[1]!r}")
        return tok

    # filters
    def expr(self):
        left = self.and_expr()
        while self.peek()[0] == "word" and self.peek()[1].lower() == "or":
            self.take()
            left = ("or", left, self.and_expr())
        return left

    def and_expr(self):
        left = self.unary()
        while True:
            k, v = self.peek()
            if k is None or (k == "punct" and v in ")],") or (k == "word" and v.lower() == "or"):
                return left
            if k == "word" and v.lower() == "and":
                self.take()
            left = ("and", left, self.unary())

    def unary(self):
        k, v = self.peek()
        if (k == "word" and v.lower() == "not") or (k == "op" and v == "!"):
            self.take()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        k, v = self.peek()
        if k == "punct" and v == "(":
            self.take()
            e = self.expr()
            self.expect("punct", ")")
            return e
        if k == "word" and self.peek(1) == ("punct", "("):
            call = self.call()
            return ("call", call)
        if k in ("word", "string") and self.peek(1)[0] == "op" and self.peek(1)[1] in ("=", "!=", "<", ">", "<=", ">=", "=~"):
            self.take()
            op = self.take()[1]
            if op == "=~":
                op = "="
            if self.peek()[0] == "word" and self.peek(1) == ("punct", "("):
                c = self.call()
                c["kw"].setdefault("field", ("word", v))
                return ("call", c)
            vk, vv = self.take()
            if vk not in ("word", "string", "regex"):
                raise CqlError(f"expected a value after {v}{op}")
            return ("cmp", v, op, vk, vv)
        if k in ("word", "string", "regex"):
            self.take()
            return ("text", k, v)
        raise CqlError(f"unexpected {v!r}")

    # function calls
    def call(self):
        name = self.take()[1]
        self.expect("punct", "(")
        pos, kw = [], {}
        while self.peek() != ("punct", ")"):
            if self.peek()[0] is None:
                raise CqlError(f"{name}( is not closed")
            if self.peek()[0] == "word" and self.peek(1) == ("op", "="):
                key = self.take()[1]
                self.take()
                kw[key] = self.value()
            else:
                pos.append(self.value())
            if self.peek() == ("punct", ","):
                self.take()
        self.expect("punct", ")")
        return {"fn": name, "pos": pos, "kw": kw}

    def value(self):
        k, v = self.peek()
        if k == "punct" and v == "[":
            self.take()
            items = []
            while self.peek() != ("punct", "]"):
                if self.peek()[0] is None:
                    raise CqlError("a [list] is not closed")
                items.append(self.value())
                if self.peek() == ("punct", ","):
                    self.take()
            self.take()
            return ("list", items)
        if k == "word" and self.peek(1) == ("punct", "("):
            return ("call", self.call())
        if k in ("word", "string", "regex"):
            self.take()
            return (k, v)
        raise CqlError(f"unexpected {v!r} in a function argument")


def parse(q, strict=False):
    """CQL text -> list of stages: {"type": "filter", "ast"} | {"type": "fn", "fn", "pos", "kw"} | {"type": "assign", "field", "expr"} |
    {"type": "raw"} for constructs this checker does not model (case / match blocks, unusual syntax) — kept, not rejected."""
    out = []
    for st in split_pipes(q or ""):
        if not strict:
            try:
                out += parse(st, strict=True)
            except CqlError as e:
                out.append({"type": "raw", "src": st, "why": str(e)})
            continue
        toks = _tokens(st)
        if not toks:
            continue
        if len(toks) >= 2 and toks[0][0] == "word" and toks[1] == ("op", ":="):
            out.append({"type": "assign", "field": toks[0][1], "text": st.split(":=", 1)[1].strip(), "src": st})
            continue
        if toks[0][0] == "word" and len(toks) > 1 and toks[1] == ("punct", "(") and toks[0][1] not in FILTER_FUNCS:
            p = _P(toks)
            call = p.call()
            if p.i != len(toks):
                raise CqlError(f"unexpected text after {call['fn']}(…): {toks[p.i][1]!r}")
            out.append({"type": "fn", **call, "src": st})
            continue
        p = _P(toks)
        ast = p.expr()
        if p.i != len(toks):
            raise CqlError(f"unexpected {toks[p.i][1]!r}")
        out.append({"type": "filter", "ast": ast, "src": st})
    return out


# ------------------------------------------------------------------ evaluator (sample-data mode)
def _sv(v):
    return "" if v is None else str(v)


def _match_value(ev, field, op, vk, vv):
    if field.startswith("#") and field not in ev:
        field = field  # tags are stored with their '#'
    have = field in ev
    val = ev.get(field)
    if vk == "regex":
        body, flags = vv
        rx = re.compile(_py_regex(body), re.I if "i" in flags else 0)
        hit = have and rx.search(_sv(val)) is not None
        return (not hit) if op == "!=" else hit
    target = vv
    if op in ("<", ">", "<=", ">="):
        try:
            a, b = float(val), float(target)
        except (TypeError, ValueError):
            return False
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
    if target == "*":
        hit = have and _sv(val) != ""
    elif "*" in target and vk == "word":
        rx = re.compile("^" + ".*".join(map(re.escape, target.split("*"))) + "$", re.I)
        hit = have and rx.match(_sv(val)) is not None
    else:
        hit = have and (_sv(val) == target or (field.startswith("#") and _sv(val).lower() == target.lower()))
    return (not hit) if op == "!=" else hit


def _py_regex(body):
    """A LogScale regex body for Python's re: \\/ -> /, named groups (?<name>…) -> (?P<name>…)."""
    return re.sub(r"\(\?<(?![=!])", "(?P<", body.replace("\\/", "/"))


def _arg(v):
    """A parsed argument value -> python value."""
    if v is None:
        return None
    k, x = v
    if k == "list":
        return [_arg(i) for i in x]
    if k == "regex":
        return x
    if k == "call":
        return x
    return x


def _flist(v):
    a = _arg(v)
    if a is None:
        return []
    return [str(x) for x in (a if isinstance(a, list) else [a])]


def _eval_filter(ev, ast):
    t = ast[0]
    if t == "and":
        return _eval_filter(ev, ast[1]) and _eval_filter(ev, ast[2])
    if t == "or":
        return _eval_filter(ev, ast[1]) or _eval_filter(ev, ast[2])
    if t == "not":
        return not _eval_filter(ev, ast[1])
    if t == "cmp":
        _, f, op, vk, vv = ast
        return _match_value(ev, f, op, vk, vv)
    if t == "text":
        _, k, v = ast
        blob = " ".join(_sv(x) for x in ev.values())
        if k == "regex":
            return re.search(_py_regex(v[0]), blob, re.I if "i" in v[1] else 0) is not None
        return v.replace("*", "").lower() in blob.lower()
    if t == "call":
        c = ast[1]
        fn, kw, pos = c["fn"], c["kw"], c["pos"]
        if fn == "in":
            f = _arg(kw.get("field")) or (_arg(pos[0]) if pos else None)
            vals = _flist(kw.get("values")) or (_flist(pos[1]) if len(pos) > 1 else [])
            ic = str(_arg(kw.get("ignoreCase")) or "false").lower() == "true"
            v = _sv(ev.get(f))
            if ic:
                return v.lower() in [x.lower() for x in vals] if f in ev else False
            return f in ev and any(v == x or ("*" in x and re.match("^" + ".*".join(map(re.escape, x.split("*"))) + "$", v)) for x in vals)
        if fn == "regex":
            rx = _arg(kw.get("regex")) or (_arg(pos[0]) if pos else "")
            rx = rx[0] if isinstance(rx, tuple) else rx
            f = _arg(kw.get("field")) or "@rawstring"
            flags = str(_arg(kw.get("flags")) or "")
            src = " ".join(_sv(x) for x in ev.values()) if f == "@rawstring" else _sv(ev.get(f))
            return re.search(_py_regex(rx), src, re.I if "i" in flags else 0) is not None
        if fn == "wildcard":
            pat = str(_arg(kw.get("pattern")) or "")
            f = _arg(kw.get("field")) or "@rawstring"
            ic = str(_arg(kw.get("ignoreCase")) or "false").lower() == "true"
            return re.match("^" + ".*".join(map(re.escape, pat.split("*"))) + "$", _sv(ev.get(f)), re.I if ic else 0) is not None
        if fn == "cidr":
            import ipaddress
            f = _arg(kw.get("field")) or (_arg(pos[0]) if pos else "")
            subs = _flist(kw.get("subnet"))
            try:
                ip = ipaddress.ip_address(_sv(ev.get(f)))
                return any(ip in ipaddress.ip_network(s, strict=False) for s in subs)
            except ValueError:
                return False
        return True
    return True


def _agg(rows, spec):
    """One aggregate function over rows -> (name, value)."""
    fn, kw, pos = spec["fn"], spec["kw"], spec["pos"]
    as_ = _arg(kw.get("as"))
    field = _arg(kw.get("field")) or (_arg(pos[0]) if pos else None)
    if fn == "count":
        if field and str(_arg(kw.get("distinct")) or "").lower() == "true":
            return as_ or "_count", len({_sv(r.get(field)) for r in rows if field in r})
        return as_ or "_count", sum(1 for r in rows if not field or field in r)
    if fn == "collect":
        fs = _flist(kw.get("fields")) or (_flist(pos[0]) if pos else [])
        return None, {f: "\n".join(sorted({_sv(r.get(f)) for r in rows if f in r})[:20]) for f in fs}
    if fn in ("min", "max", "sum", "avg"):
        nums = []
        for r in rows:
            try:
                nums.append(float(r.get(field)))
            except (TypeError, ValueError):
                pass
        val = (min(nums) if fn == "min" else max(nums) if fn == "max" else sum(nums) if fn == "sum" else sum(nums) / len(nums)) if nums else None
        return as_ or f"_{fn}", val
    if fn == "selectLast":
        fs = _flist(kw.get("fields")) or (_flist(pos[0]) if pos else [])
        return None, {f: rows[0].get(f) for f in fs} if rows else {}
    return as_ or f"_{fn}", None


def _aggs(rows, fspec):
    specs = fspec if isinstance(fspec, list) else [fspec]
    out = {}
    for s in specs:
        if isinstance(s, dict) and "fn" in s:
            k, v = _agg(rows, s)
            if k is None:
                out.update(v)
            else:
                out[k] = v
    return out


def evaluate(q, events, start=None):
    """Run a CQL query over a list of event dicts (sample-data mode). Returns (rows, events scanned)."""
    stages = parse(q)
    rows = events
    if start:
        try:
            st = datetime.fromtimestamp(int(start) / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            rows = [e for e in rows if e.get("@timestamp", "") >= st]
        except (TypeError, ValueError):
            pass
    scanned = len(rows)
    sorted_by_fn = False
    for s in stages:
        if s["type"] == "filter":
            rows = [e for e in rows if _eval_filter(e, s["ast"])]
            continue
        if s["type"] in ("assign", "raw"):
            continue
        fn, kw, pos = s["fn"], s["kw"], s["pos"]
        if fn in FILTER_FUNCS:
            rows = [e for e in rows if _eval_filter(e, ("call", s))]
        elif fn == "groupBy":
            fields = _flist(kw.get("field")) or (_flist(pos[0]) if pos else [])
            groups = {}
            for r in rows:
                if all(f in r for f in fields):
                    groups.setdefault(tuple(_sv(r.get(f)) for f in fields), []).append(r)
            fspec = _arg(kw.get("function")) or {"fn": "count", "kw": {}, "pos": []}
            rows = [{**dict(zip(fields, k)), **_aggs(g, fspec)} for k, g in groups.items()]
            if "_count" in (rows[0] if rows else {}):
                rows.sort(key=lambda r: -(r.get("_count") or 0))
            rows = rows[:int(_arg(kw.get("limit")) or 20000) if str(_arg(kw.get("limit")) or "").isdigit() else 20000]
        elif fn == "top":
            fields = _flist(kw.get("field")) or (_flist(pos[0]) if pos else [])
            cnt = Counter(tuple(_sv(r.get(f)) for f in fields) for r in rows if all(f in r for f in fields))
            rows = [{**dict(zip(fields, k)), "_count": n} for k, n in cnt.most_common(int(_arg(kw.get("limit")) or 10))]
        elif fn in ("count", "stats", "min", "max", "sum", "avg"):
            spec = s if fn != "stats" else {"fn": "stats", "kw": {}, "pos": []}
            if fn == "stats":
                rows = [_aggs(rows, _arg(kw.get("function")) or [_arg(p) for p in pos])]
            else:
                k, v = _agg(rows, spec)
                rows = [{k: v}]
        elif fn in ("table", "select"):
            fields = _flist(kw.get("fields")) or (_flist(pos[0]) if pos else [])
            if fn == "table" and not sorted_by_fn:
                key = _arg(kw.get("sortby")) or "@timestamp"
                rev = str(_arg(kw.get("order")) or "desc").lower() != "asc"
                rows = sorted(rows, key=lambda r: _sv(r.get(key)), reverse=rev)
            rows = [{f: r.get(f) for f in fields} for r in rows]
            if fn == "table":
                rows = rows[:int(_arg(kw.get("limit")) or 200)]
        elif fn == "sort":
            fields = _flist(kw.get("field")) or (_flist(pos[0]) if pos else ["_count"])
            rev = str(_arg(kw.get("order")) or "desc").lower() != "asc"

            def key(r, fs=fields):
                out = []
                for f in fs:
                    v = r.get(f)
                    try:
                        out.append((0, float(v), ""))
                    except (TypeError, ValueError):
                        out.append((1, 0, _sv(v)))
                return out
            rows = sorted(rows, key=key, reverse=rev)[:int(_arg(kw.get("limit")) or 200)]
            sorted_by_fn = True
        elif fn in ("head", "tail"):
            n = int(_arg(kw.get("limit")) or (_arg(pos[0]) if pos else 200))
            rows = rows[:n] if fn == "head" else rows[-n:]
        elif fn in ("timeChart", "bucket"):
            span = str(_arg(kw.get("span")) or "1h")
            width = 10 if span.endswith("d") else 13
            cnt = Counter(_sv(r.get("@timestamp"))[:width] for r in rows)
            rows = [{"_bucket": k + (":00" if width == 13 else ""), "_count": v} for k, v in sorted(cnt.items())]
        elif fn == "rename":
            f = _arg(kw.get("field")) or (_arg(pos[0]) if pos else None)
            new = _arg(kw.get("as"))
            if f and new:
                rows = [{(new if k == f else k): v for k, v in r.items()} for r in rows]
        elif fn == "drop":
            fs = set(_flist(kw.get("fields")) or (_flist(pos[0]) if pos else []))
            rows = [{k: v for k, v in r.items() if k not in fs} for r in rows]
        elif fn in ("lower", "upper"):
            f = _arg(kw.get("field")) or (_arg(pos[0]) if pos else None)
            as_ = _arg(kw.get("as")) or f
            rows = [{**r, as_: (_sv(r.get(f)).lower() if fn == "lower" else _sv(r.get(f)).upper())} if f in r else r for r in rows]
        elif fn == "default":
            f, v = _arg(kw.get("field")), _arg(kw.get("value"))
            for f1 in ([f] if isinstance(f, str) else f or []):
                rows = [{**r, f1: r.get(f1, v)} for r in rows]
        # other functions (join, case, eval, formatTime…) are passed through in sample mode
    return rows, scanned


# ------------------------------------------------------------------ lint, auto-fix, explain
FIXES = [
    (r"(?<![#\w])event_simpleName\s*=", "#event_simpleName=", "event_simpleName is a tag: #event_simpleName"),
    (r"==", "=", "CQL compares with = (not ==)"),
    (r"\|\s*where\s+", "| ", "CQL has no WHERE: a filter is just a stage"),
    (r"\|\s*(?:limit|take)\s+(\d+)", r"| head(\1)", "use head(N) to limit rows"),
    (r"\|\s*sort\s+(?:by\s+)?([\w@#.]+)\s+(desc|asc)\b", r"| sort(\1, order=\2)", "sort is a function: sort(field, order=desc)"),
    (r"\|\s*sort\s+-([\w@#.]+)", r"| sort(\1, order=desc)", "sort is a function: sort(field, order=desc)"),
    (r"\|\s*stats\s+count(?:\(\))?\s+by\s+([\w@#., ]+?)\s*(?=\||$)", lambda m: "| groupBy([" + ", ".join(x.strip() for x in m.group(1).split(",")) + "])",
     "use groupBy([fields]) for counts per value"),
    (r"\|\s*(?:fields|project|table)\s+(?!\()([\w@#.]+(?:\s*,\s*[\w@#.]+)*)\s*(?=\||$)", lambda m: "| table([" + ", ".join(x.strip() for x in m.group(1).split(",")) + "])",
     "use table([fields]) to pick columns"),
    (r"\|\s*dedup\s+([\w@#.]+(?:\s*,\s*[\w@#.]+)*)", lambda m: "| groupBy([" + ", ".join(x.strip() for x in m.group(1).split(",")) + "])",
     "CQL has no dedup: groupBy([fields]) gives distinct values"),
    (r"\|\s*count\s*(?=\||$)", "| count()", "count is a function: count()"),
    (r"\bgroupby\(", "groupBy(", "the function is groupBy (capital B)"), (r"\btimechart\(", "timeChart(", "the function is timeChart"),
    (r"\b([A-Z][\w.]*)\s+(?:LIKE|like)\s+\"%?([^\"%]+)%?\"", lambda m: f"{m.group(1)}=/{re.escape(m.group(2))}/i", "CQL has no LIKE: use a /regex/i"),
    (r"\bcontains\(\s*([\w@#.]+)\s*,\s*\"([^\"]+)\"\s*\)", lambda m: f"{m.group(1)}=/{re.escape(m.group(2))}/i", "use field=/text/i for 'contains'"),
    (r"\b([A-Z][A-Za-z0-9]+):(['\"])", r"\1=\2", "CQL uses field=value (not field:value)"),
]


_HUBF = {"done": False}


def extend_functions():
    """Function names used by the imported CQL Hub queries are known CQL (the community library runs in Falcon)."""
    if _HUBF["done"]:
        return
    try:
        with db.get_conn() as c:
            c.execute("SELECT 1 FROM cql_hub LIMIT 1")
            qs = [r[0] for r in c.execute("SELECT cql FROM cql_hub")]
    except Exception:  # noqa: BLE001 - not imported yet
        return
    for q in qs:
        for m in re.finditer(r"(?:^|\|)\s*(?:[\w.\"]+\s*:=\s*)?([a-zA-Z_][\w:]*)\(", q):
            FUNCS.add(m.group(1))
    _HUBF["done"] = bool(qs)


def autofix(q):
    changes = []
    for pat, rep, why in FIXES:
        new = re.sub(pat, rep, q)
        if new != q:
            changes.append(why)
            q = new
    return q, changes


def _fields_in(stages):
    used = set()

    def walk(a):
        if not a:
            return
        if a[0] in ("and", "or"):
            walk(a[1])
            walk(a[2])
        elif a[0] == "not":
            walk(a[1])
        elif a[0] == "cmp":
            used.add(a[1])
        elif a[0] == "call":
            c = a[1]
            f = c["kw"].get("field")
            if f:
                used.update(_flist(f))
    for s in stages:
        if s["type"] == "filter":
            walk(s["ast"])
        elif s["type"] == "fn":
            if s["fn"] in FILTER_FUNCS:
                walk(("call", s))
            elif s["fn"] in ("groupBy", "table", "select", "top", "sort", "drop"):
                used.update(_flist(s["kw"].get("field") or s["kw"].get("fields")) or (_flist(s["pos"][0]) if s["pos"] else []))
    return used


def _events_in(stages):
    evs = set()

    def walk(a):
        if a[0] in ("and", "or"):
            walk(a[1])
            walk(a[2])
        elif a[0] == "cmp" and a[1] == "#event_simpleName":
            evs.add(a[4] if a[3] != "regex" else "*")
        elif a[0] == "call" and a[1]["fn"] == "in" and _arg(a[1]["kw"].get("field")) == "#event_simpleName":
            evs.update(_flist(a[1]["kw"].get("values")))
    for s in stages:
        if s["type"] == "filter":
            walk(s["ast"])
    return evs


def lint(q, fix=True):
    """Check (and optionally auto-fix) a CQL query. Returns {ok, cql, changes, errors, warnings, events}."""
    extend_functions()
    q = (q or "").strip()
    changes = []
    if fix:
        q, changes = autofix(q)
    errors, warnings = [], []
    if re.match(r"^\s*select\b", q, re.I):
        errors.append("This looks like SQL. CQL starts with filters (e.g. #event_simpleName=ProcessRollup2 FileName=cmd.exe) and pipes into functions.")
        return {"ok": False, "cql": q, "changes": changes, "errors": errors, "warnings": warnings, "events": []}
    try:
        stages = parse(q)
    except CqlError as e:
        return {"ok": False, "cql": q, "changes": changes, "errors": [str(e)], "warnings": [], "events": []}
    if not stages:
        return {"ok": False, "cql": q, "changes": changes, "errors": ["The query is empty"], "warnings": [], "events": []}
    raw = [s for s in stages if s["type"] == "raw"]
    if raw:
        warnings.append(f"{len(raw)} stage{'s' if len(raw) > 1 else ''} use syntax this checker does not model (e.g. case blocks) — not checked: "
                        + "; ".join(r["src"][:40] for r in raw[:2]))
    for s in stages:
        if s["type"] == "fn" and s["fn"] not in FUNCS and not s["fn"].startswith("$"):
            sug = difflib.get_close_matches(s["fn"], sorted(FUNCS), 1)
            errors.append(f"Unknown function {s['fn']}()" + (f" — did you mean {sug[0]}()?" if sug else ""))
        if s["type"] == "fn" and s["fn"] in ("head", "tail") and s["pos"] and not str(_arg(s["pos"][0])).isdigit():
            errors.append(f"{s['fn']}() takes a number")
    for r in [x for x in stages if x["type"] == "filter"]:
        _check_regexes(r["ast"], errors)
    evs = _events_in(stages)
    known = set(COMMON) | {a for s in stages if s["type"] == "fn" for a in [_arg(s["kw"].get("as"))] if a} | \
        {s["field"] for s in stages if s["type"] == "assign"}
    if evs and "*" not in evs:
        unknown_ev = [e for e in evs if e not in EVENTS]
        for e in unknown_ev:
            sug = difflib.get_close_matches(e, list(EVENTS), 1)
            warnings.append(f"{e} is not in the console's event dictionary" + (f" — did you mean {sug[0]}?" if sug else " (it may still exist in your tenant)"))
        for e in evs:
            known |= set(EVENTS.get(e, ("", [], []))[1])
        if not unknown_ev:
            for f in sorted(_fields_in(stages) - known):
                if f.startswith(("#", "@", "_")):
                    continue
                sug = difflib.get_close_matches(f, sorted(known), 1)
                warnings.append(f"{f} is not a field of {', '.join(sorted(evs))}" + (f" — did you mean {sug[0]}?" if sug else ""))
    elif not evs:
        warnings.append("No #event_simpleName filter: the search reads every event type (slow, noisy). Start with e.g. #event_simpleName=ProcessRollup2.")
    if not any(s["type"] == "fn" and s["fn"] in ("groupBy", "table", "select", "top", "count", "head", "tail", "stats", "timeChart", "bucket", "sort")
               for s in stages):
        warnings.append("No groupBy / table / head at the end: the search returns raw events (up to the API limit).")
    return {"ok": not errors, "cql": q, "changes": changes, "errors": errors, "warnings": warnings, "events": sorted(evs)}


def _check_regexes(a, errors):
    if a[0] in ("and", "or"):
        _check_regexes(a[1], errors)
        _check_regexes(a[2], errors)
    elif a[0] == "not":
        _check_regexes(a[1], errors)
    elif (a[0] == "cmp" and a[3] == "regex") or (a[0] == "text" and a[1] == "regex"):
        body = a[4][0] if a[0] == "cmp" else a[2][0]
        try:
            re.compile(_py_regex(body))
        except re.error as e:
            errors.append(f"Invalid regex /{body}/: {e}")


OP_WORD = {"=": "is", "!=": "is not", "<": "is below", ">": "is above", "<=": "is at most", ">=": "is at least"}


def _explain_ast(a):
    t = a[0]
    if t == "and":
        return f"{_explain_ast(a[1])} and {_explain_ast(a[2])}"
    if t == "or":
        return f"({_explain_ast(a[1])} or {_explain_ast(a[2])})"
    if t == "not":
        return f"not ({_explain_ast(a[1])})"
    if t == "cmp":
        _, f, op, vk, vv = a
        if f == "#event_simpleName":
            d = EVENTS.get(vv, ("",))[0]
            return f"the event is {vv}" + (f" ({d})" if d else "")
        if vk == "regex":
            return f"{f} {'does not match' if op == '!=' else 'matches'} /{vv[0]}/{vv[1]}" + (" (any case)" if "i" in vv[1] else "")
        if vv == "*":
            return f"{f} {'is missing' if op == '!=' else 'is present'}"
        return f"{f} {OP_WORD.get(op, op)} {vv}"
    if t == "text":
        return f"the event contains {a[2] if a[1] != 'regex' else '/' + a[2][0] + '/'}"
    if t == "call":
        c = a[1]
        if c["fn"] == "in":
            return f"{_arg(c['kw'].get('field')) or _arg(c['pos'][0])} is one of {', '.join(_flist(c['kw'].get('values')))}"
        return f"{c['fn']}(…) holds"
    return "?"


def explain(q):
    try:
        stages = parse(q)
    except CqlError as e:
        return [f"Cannot read the query: {e}"]
    out = []
    for s in stages:
        if s["type"] == "filter":
            out.append("Keep events where " + _explain_ast(s["ast"]))
        elif s["type"] == "raw":
            out.append(f"{s['src'][:90]}{'…' if len(s['src']) > 90 else ''} (not modelled by the checker)")
        elif s["type"] == "assign":
            out.append(f"Compute {s['field']} = {s['text']}")
        else:
            fn, kw, pos = s["fn"], s["kw"], s["pos"]
            fields = _flist(kw.get("field") or kw.get("fields")) or (_flist(pos[0]) if pos and pos[0][0] in ("list", "word") else [])
            if fn in FILTER_FUNCS:
                out.append("Keep events where " + _explain_ast(("call", s)))
            elif fn == "groupBy":
                f = _arg(kw.get("function"))
                agg = "count events" if not f else ", ".join(x["fn"] + "(" + ", ".join(str(_arg(p)) for p in x["pos"]) + ")" for x in (f if isinstance(f, list) else [f]) if isinstance(x, dict))
                out.append(f"Group by {', '.join(fields)} and {agg} (_count)")
            elif fn == "table":
                out.append(f"Show a table of {', '.join(fields)}" + (f" (up to {_arg(kw.get('limit'))} rows)" if kw.get("limit") else " (up to 200 rows)"))
            elif fn == "sort":
                out.append(f"Sort by {', '.join(fields) or '_count'} {str(_arg(kw.get('order')) or 'desc')}")
            elif fn in ("head", "tail"):
                out.append(f"Keep the {'first' if fn == 'head' else 'last'} {_arg(kw.get('limit')) or (_arg(pos[0]) if pos else 200)} rows")
            elif fn == "top":
                out.append(f"Most common values of {', '.join(fields)}")
            elif fn == "count":
                out.append("Count the events" + (f" (distinct {fields[0]})" if fields and kw.get("distinct") else ""))
            elif fn == "timeChart":
                out.append(f"Chart the count over time (span {_arg(kw.get('span')) or 'auto'})")
            else:
                out.append(f"{fn}({', '.join(fields)})")
    return out


# ------------------------------------------------------------------ query plan (what the model fills) -> CQL
OPS = ["equals", "not_equals", "contains", "not_contains", "regex", "not_regex", "starts_with", "ends_with", "in", "greater", "less"]
OUTPUTS = ["table", "group", "count", "top", "timechart"]


def _rx(v):
    """A literal for use inside a CQL /regex/."""
    return re.sub(r"([.^$|?*+()\[\]{}\\/])", r"\\\1", str(v))


def _canon_field(f, event):
    """The model's field name -> a real field of the event (or a common one), else None."""
    if not f:
        return None
    allowed = set(EVENTS.get(event, ("", [], []))[1]) | set(COMMON)
    if f in allowed:
        return f
    low = re.sub(r"[^a-z0-9]", "", f.lower())
    for a in allowed:
        if a.lower() == low:
            return a
    syn = SYNONYMS.get(low)
    if syn in allowed:
        return syn
    if syn == "RemoteAddressIP4" and event in ("UserLogon", "UserLogonFailed2"):
        return "RemoteAddressIP4"
    return None


def _cond(f, op, v):
    v = str(v).strip()
    num = f in NUMERIC
    if op == "in":
        vals = [x.strip().strip('"') for x in re.split(r"[,|]", v) if x.strip()]
        if num:
            vals = [x for x in vals if x.isdigit()]
        return f"in(field=\"{f}\", values=[{', '.join(json.dumps(x) for x in vals)}]" + ("" if num else ", ignoreCase=true") + ")"
    if num and op in ("equals", "not_equals", "greater", "less"):
        if not re.fullmatch(r"-?\d+(\.\d+)?", v):
            raise CqlError(f"{f} needs a number, got {v!r}")
        return f"{f}{ {'equals': '=', 'not_equals': '!=', 'greater': '>', 'less': '<'}[op] }{v}".replace(" ", "")
    if op in ("greater", "less"):
        return f"{f}{'>' if op == 'greater' else '<'}{v}"
    if f == "event_platform":
        p = {"windows": "Win", "win": "Win", "linux": "Lin", "lin": "Lin", "mac": "Mac", "macos": "Mac"}.get(v.lower(), v)
        return f"event_platform{'!=' if op == 'not_equals' else '='}{p}"
    if op in ("equals", "not_equals") and f in EXACT and re.fullmatch(r"[\w.:-]+", v):
        return f"{f}{'!=' if op == 'not_equals' else '='}{v.lower() if 'Hash' in f else v}"
    if op in ("regex", "not_regex"):
        body = v.strip("/")
        try:
            re.compile(body)
        except re.error as e:
            raise CqlError(f"invalid regex for {f}: {e}") from e
        body = re.sub(r"(?<!\\)/", r"\\/", body)
        return f"{f}{'!=' if op == 'not_regex' else '='}/{body}/i"
    esc = _rx(v)
    if op in ("equals", "not_equals"):
        body = "^" + esc.replace("\\*", ".*") + "$"
        return f"{f}{'!=' if op == 'not_equals' else '='}/{body}/i"
    if op in ("contains", "not_contains"):
        return f"{f}{'!=' if op == 'not_contains' else '='}/{esc}/i"
    if op == "starts_with":
        return f"{f}=/^{esc}/i"
    if op == "ends_with":
        return f"{f}=/{esc}$/i"
    raise CqlError(f"unknown operator {op}")


def compile_plan(p):
    """Query plan -> (cql, notes). The plan: {event, platform, filters:[{field, op, value}], output, fields, min_count, max_count, limit}."""
    notes = []
    ev = p.get("event")
    if ev not in EVENTS:
        raise CqlError(f"unknown event {ev!r}")
    parts = [f"#event_simpleName={ev}"]
    plat = (p.get("platform") or "any")
    if plat in ("Win", "Lin", "Mac"):
        parts.append(f"event_platform={plat}")
    for flt in p.get("filters") or []:
        f = _canon_field(flt.get("field"), ev)
        op = flt.get("op") if flt.get("op") in OPS else "contains"
        val = flt.get("value")
        if val in (None, "") or not f:
            notes.append(f"dropped filter {flt.get('field')} {flt.get('op')} {val!r} (not a field of {ev})" if not f else f"dropped empty filter on {f}")
            continue
        try:
            parts.append(_cond(f, op, val))
        except CqlError as e:
            notes.append(str(e))
    q = " ".join(parts)
    out = p.get("output") if p.get("output") in OUTPUTS else "table"
    fields = []
    for f in p.get("fields") or []:
        cf = _canon_field(f, ev)
        if cf and cf not in fields and cf != "_count":
            fields.append(cf)
        elif not cf:
            notes.append(f"dropped column {f} (not a field of {ev})")
    lim = max(1, min(1000, int(p.get("limit") or 200)))
    if out == "table":
        cols = fields or EVENTS[ev][2]
        if "@timestamp" not in cols:
            cols = ["@timestamp"] + cols
        if "ComputerName" not in cols:
            cols.insert(1, "ComputerName")
        q += f"\n| table([{', '.join(cols)}], limit={lim})"
    elif out == "group":
        keys = fields or ["ComputerName"]
        q += f"\n| groupBy([{', '.join(keys)}], limit=max)"
        if int(p.get("min_count") or 0) > 0:
            q += f"\n| _count >= {int(p['min_count'])}"
        if int(p.get("max_count") or 0) > 0:
            q += f"\n| _count <= {int(p['max_count'])}"
        q += f"\n| sort(_count, order=desc, limit={lim})"
    elif out == "count":
        q += "\n| count()"
    elif out == "top":
        q += f"\n| top([{', '.join(fields or ['ComputerName'])}], limit={min(lim, 100)})"
    elif out == "timechart":
        q += "\n| timeChart(span=1h)"
    return q, notes


# ------------------------------------------------------------------ hunting library (tested, MITRE-tagged)
def L(id_, title, mitre, tags, examples, event, filters, output="table", fields=None, platform=None, min_count=0, max_count=0, note=""):
    return {"id": id_, "title": title, "mitre": mitre, "tags": tags, "examples": examples,
            "plan": {"event": event, "platform": platform or "any", "filters": [{"field": f, "op": o, "value": v} for f, o, v in filters],
                     "output": output, "fields": fields or [], "min_count": min_count, "max_count": max_count, "limit": 200}, "note": note}


SHELLS = r"^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$"
LIBRARY = [
    L("encoded_powershell", "Encoded PowerShell", "T1059.001", "execution powershell obfuscation base64 encoded",
      ["encoded powershell commands", "powershell with -enc", "base64 powershell"], "ProcessRollup2",
      [("FileName", "regex", r"^(powershell|pwsh)(_ise)?\.exe$"), ("CommandLine", "regex", r"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s")],
      fields=["ComputerName", "UserName", "ParentBaseFileName", "CommandLine"], platform="Win"),
    L("powershell_download", "PowerShell download cradle", "T1105", "powershell download cradle downloadstring webclient iwr ingress tool transfer",
      ["powershell downloading files", "downloadstring or invoke-webrequest usage"], "ProcessRollup2",
      [("FileName", "regex", r"^(powershell|pwsh)\.exe$"), ("CommandLine", "regex", r"downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|start-bitstransfer")],
      fields=["ComputerName", "UserName", "CommandLine"], platform="Win"),
    L("certutil_download", "Certutil download / decode", "T1105", "certutil urlcache download decode lolbin living off the land",
      ["certutil -urlcache downloads", "certutil used to download a file"], "ProcessRollup2",
      [("FileName", "equals", "certutil.exe"), ("CommandLine", "regex", r"urlcache|verifyctl|-decode|-split")], fields=["ComputerName", "UserName", "CommandLine"]),
    L("bitsadmin_transfer", "BITSAdmin transfer", "T1197", "bitsadmin bits transfer download persistence",
      ["bitsadmin downloads", "bits jobs created"], "ProcessRollup2", [("FileName", "equals", "bitsadmin.exe"), ("CommandLine", "regex", r"/transfer|/addfile|/create")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("mshta_remote", "MSHTA running remote or inline script", "T1218.005", "mshta hta lolbin proxy execution phishing",
      ["mshta with a url", "suspicious mshta"], "ProcessRollup2", [("FileName", "equals", "mshta.exe"), ("CommandLine", "regex", r"https?://|javascript:|vbscript:")],
      fields=["ComputerName", "UserName", "ParentBaseFileName", "CommandLine"]),
    L("regsvr32_squiblydoo", "Regsvr32 remote scriptlet (Squiblydoo)", "T1218.010", "regsvr32 scrobj squiblydoo lolbin",
      ["regsvr32 loading a remote sct", "squiblydoo"], "ProcessRollup2", [("FileName", "equals", "regsvr32.exe"), ("CommandLine", "regex", r"/i:\s*https?://|scrobj")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("lsass_dump", "LSASS memory dump", "T1003.001", "credential access dumping lsass minidump comsvcs procdump",
      ["lsass dumping", "credential dumping with comsvcs minidump", "procdump lsass"], "ProcessRollup2",
      [("CommandLine", "regex", r"comsvcs(\.dll)?[, ]+#?\s*minidump|procdump.*lsass|lsass\.dmp|sqldumper.*0x01100")],
      fields=["ComputerName", "UserName", "FileName", "CommandLine"]),
    L("mimikatz", "Mimikatz command lines", "T1003", "credential access mimikatz sekurlsa lsadump kerberos",
      ["mimikatz usage", "sekurlsa logonpasswords"], "ProcessRollup2",
      [("CommandLine", "regex", r"sekurlsa|lsadump::|kerberos::|privilege::debug|mimikatz|invoke-mimikatz")], fields=["ComputerName", "UserName", "FileName", "CommandLine"]),
    L("office_child_shell", "Office application spawning a shell", "T1566.001", "phishing macro office word winword excel powerpoint outlook onenote child process spawning initial access",
      ["office spawning powershell", "word macro launching cmd", "outlook starting a script"], "ProcessRollup2",
      [("ParentBaseFileName", "regex", r"^(winword|excel|powerpnt|outlook|onenote|msaccess|mspub)\.exe$"), ("FileName", "regex", SHELLS)],
      fields=["ComputerName", "UserName", "ParentBaseFileName", "FileName", "CommandLine"], platform="Win"),
    L("webshell_child", "Web server spawning a shell (web shell)", "T1505.003", "webshell w3wp iis tomcat java nginx httpd persistence",
      ["web shell activity", "iis w3wp spawning cmd"], "ProcessRollup2",
      [("ParentBaseFileName", "regex", r"^(w3wp|httpd|nginx|tomcat\d*|php-cgi|java)(\.exe)?$"),
       ("FileName", "regex", r"^(cmd|powershell|pwsh|sh|bash|whoami|net|net1|certutil|curl|wget)(\.exe)?$")],
      fields=["ComputerName", "ParentBaseFileName", "FileName", "CommandLine"]),
    L("psexec", "PsExec / PAExec remote execution", "T1569.002", "lateral movement psexec paexec remote service execution",
      ["psexec usage", "where did psexec run", "lateral movement with psexec"], "ProcessRollup2",
      [("FileName", "regex", r"^(psexec(64)?|psexesvc|paexec(svc)?)\.exe$")], fields=["ComputerName", "UserName", "ParentBaseFileName", "CommandLine"]),
    L("wmic_remote", "WMIC remote process creation", "T1047", "lateral movement wmi wmic remote process call create",
      ["wmic remote execution", "wmi process call create on another host"], "ProcessRollup2",
      [("FileName", "equals", "wmic.exe"), ("CommandLine", "regex", r"/node:.*process\s+call\s+create")], fields=["ComputerName", "UserName", "CommandLine"]),
    L("smb_outbound", "SMB / RPC connections between hosts", "T1021.002", "lateral movement smb 445 135 admin shares",
      ["which hosts connect to other hosts over smb", "lateral movement over port 445"], "NetworkConnectIP4",
      [("RemotePort", "in", "445,135")], "group", ["ComputerName", "RemoteAddressIP4", "RemotePort"]),
    L("rdp_outbound", "Outbound RDP", "T1021.001", "lateral movement rdp 3389 remote desktop",
      ["outbound rdp connections", "who is using rdp to other machines"], "NetworkConnectIP4", [("RemotePort", "equals", "3389")], "group",
      ["ComputerName", "RemoteAddressIP4"]),
    L("rdp_logons", "RDP logons", "T1021.001", "rdp remote interactive logon type 10 valid accounts",
      ["rdp logons", "who logged in over remote desktop"], "UserLogon", [("LogonType", "equals", "10")], "group", ["ComputerName", "UserName", "RemoteAddressIP4"]),
    L("service_account_interactive", "Service accounts logging on interactively", "T1078", "valid accounts service account svc interactive logon",
      ["service accounts with interactive logons", "svc accounts logging in over rdp"], "UserLogon",
      [("UserName", "regex", r"^svc[_.-]"), ("LogonType", "in", "2,10")], "group", ["ComputerName", "UserName", "LogonType"]),
    L("failed_logons_bruteforce", "Brute force: many failed logons per account", "T1110.001", "brute force failed logon password guessing credential access",
      ["brute force attempts", "accounts with many failed logons", "more than 10 failed logons"], "UserLogonFailed2", [], "group",
      ["ComputerName", "UserName"], min_count=10),
    L("password_spray", "Password spraying: many failed logons from one source", "T1110.003", "password spray failed logon source ip credential access",
      ["password spraying", "one ip failing logons on many accounts"], "UserLogonFailed2", [], "group", ["RemoteAddressIP4"], min_count=20),
    L("shadow_copy_delete", "Shadow copies / backups deleted", "T1490", "ransomware impact inhibit recovery vssadmin wbadmin bcdedit shadow copies",
      ["ransomware precursors", "shadow copy deletion", "vssadmin delete shadows"], "ProcessRollup2",
      [("CommandLine", "regex", r"vssadmin.*delete\s+shadows|shadowcopy\s+delete|wbadmin.*delete\s+(catalog|systemstatebackup)|bcdedit.*recoveryenabled\s+no")],
      fields=["ComputerName", "UserName", "FileName", "CommandLine"]),
    L("defender_tamper", "Defender tampering", "T1562.001", "defense evasion disable defender exclusion mppreference windefend",
      ["defender being disabled", "antivirus exclusions added"], "ProcessRollup2",
      [("CommandLine", "regex", r"set-mppreference.*-disable|add-mppreference.*-exclusion|sc(\.exe)?\s+(stop|delete|config)\s+windefend")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("clear_logs", "Event logs cleared", "T1070.001", "defense evasion clear event logs wevtutil indicator removal",
      ["event log clearing", "wevtutil cl"], "ProcessRollup2", [("CommandLine", "regex", r"wevtutil(\.exe)?\s+(cl|clear-log)|clear-eventlog|remove-eventlog")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("domain_discovery", "Domain / admin group discovery", "T1087.002", "discovery recon domain admins nltest adfind dsquery net group trusts",
      ["domain admin enumeration", "nltest domain trusts", "active directory reconnaissance"], "ProcessRollup2",
      [("CommandLine", "regex", r"nltest.*(domain_trusts|dclist)|net1?(\.exe)?\s+group\s+\"?domain admins|net1?(\.exe)?\s+user\s+/domain|adfind|dsquery")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("whoami_recon", "whoami executions", "T1033", "discovery recon whoami owner user discovery",
      ["who ran whoami", "whoami usage per host"], "ProcessRollup2", [("FileName", "equals", "whoami.exe")], "group", ["ComputerName", "UserName", "ParentBaseFileName"]),
    L("new_local_admin", "Local user created or added to administrators", "T1136.001", "persistence create account net user add local administrators",
      ["new local accounts", "users added to administrators"], "ProcessRollup2",
      [("CommandLine", "regex", r"net1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add|net1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("scheduled_tasks", "Scheduled tasks created", "T1053.005", "persistence scheduled task schtasks",
      ["new scheduled tasks", "schtasks persistence"], "ScheduledTaskRegistered", [], fields=["ComputerName", "TaskName", "TaskExecCommand", "TaskAuthor"]),
    L("schtasks_cmdline", "schtasks /create command lines", "T1053.005", "persistence scheduled task schtasks create",
      ["schtasks create commands"], "ProcessRollup2", [("FileName", "equals", "schtasks.exe"), ("CommandLine", "contains", "/create")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("run_keys", "Run-key persistence", "T1547.001", "persistence registry run key autostart asep",
      ["registry run key persistence", "autostart registry changes"], "AsepValueUpdate", [("RegObjectName", "regex", r"\\CurrentVersion\\Run")],
      fields=["ComputerName", "RegObjectName", "RegValueName", "RegStringValue"]),
    L("service_create", "Services created with sc.exe", "T1543.003", "persistence windows service sc create",
      ["new services created", "sc create usage"], "ProcessRollup2", [("FileName", "equals", "sc.exe"), ("CommandLine", "regex", r"\screate\s")],
      fields=["ComputerName", "UserName", "CommandLine"]),
    L("rclone_exfil", "Rclone / MEGA / restic (exfiltration tools)", "T1567.002", "exfiltration cloud storage rclone mega restic upload",
      ["rclone usage", "data exfiltration to cloud storage", "where did rclone run"], "ProcessRollup2",
      [("FileName", "regex", r"^(rclone|megasync|megacmd\w*|restic)(\.exe)?$")], fields=["ComputerName", "UserName", "CommandLine"]),
    L("rmm_tools", "Remote access tools (AnyDesk, TeamViewer…)", "T1219", "remote access software rmm anydesk teamviewer screenconnect ngrok command and control",
      ["remote access tools", "anydesk or teamviewer running", "rmm tools"], "ProcessRollup2",
      [("FileName", "regex", r"^(anydesk|teamviewer\w*|screenconnect\.\w+|atera\w*|splashtop\w*|rustdesk|ngrok|logmein\w*)(\.exe)?$")], "group",
      ["ComputerName", "FileName", "UserName"]),
    L("exe_from_user_dirs", "Executables running from Temp / Downloads / Public", "T1204.002", "user execution temp downloads appdata public malware",
      ["programs running from temp folders", "executables from downloads"], "ProcessRollup2",
      [("ImageFileName", "regex", r"\\(temp|downloads|users\\public|programdata|appdata\\local\\temp)\\[^\\]+\.exe$")], "group",
      ["ComputerName", "FileName", "ImageFileName"], platform="Win"),
    L("svchost_masquerade", "svchost.exe outside System32 (masquerading)", "T1036.005", "defense evasion masquerading svchost wrong path",
      ["fake svchost", "masquerading processes"], "ProcessRollup2",
      [("FileName", "equals", "svchost.exe"), ("ImageFileName", "not_regex", r"\\windows\\(system32|syswow64)\\svchost\.exe$")], fields=["ComputerName", "ImageFileName", "ParentBaseFileName"],
      platform="Win"),
    L("rare_processes", "Rare processes (seen on few hosts)", "T1204", "rare uncommon processes stacking long tail anomaly",
      ["rare processes", "least common programs", "stack processes"], "ProcessRollup2", [], "group", ["FileName"], max_count=2),
    L("rare_tld_dns", "DNS lookups to suspicious TLDs", "T1071.004", "command and control dns suspicious tld xyz top",
      ["dns to suspicious tlds", "lookups of .xyz domains"], "DnsRequest",
      [("DomainName", "regex", r"\.(xyz|top|tk|ml|ga|cf|gq|zip|mov|click|country|kim|work|rest|cam)$")], "group", ["ComputerName", "DomainName"]),
    L("dga_dns", "Long random-looking domains (DGA)", "T1568.002", "command and control dga domain generation algorithm dns",
      ["dga domains", "random looking dns lookups"], "DnsRequest", [("DomainName", "regex", r"^[a-z0-9]{20,}\.")], "group", ["ComputerName", "DomainName"]),
    L("tor_ports", "Connections to Tor ports", "T1090.003", "command and control tor proxy 9001 9050",
      ["tor connections", "traffic to tor ports"], "NetworkConnectIP4", [("RemotePort", "in", "9001,9030,9050,9150")], "group",
      ["ComputerName", "RemoteAddressIP4", "RemotePort"]),
    L("c2_ports", "Connections to common C2 / reverse-shell ports", "T1571", "command and control non standard port 4444 1337 reverse shell beacon",
      ["connections on port 4444", "beaconing to unusual ports", "c2 traffic"], "NetworkConnectIP4", [("RemotePort", "in", "4444,4445,1337,31337,6666,6667,8888")],
      "group", ["ComputerName", "RemoteAddressIP4", "RemotePort"]),
    L("listen_unusual", "Processes listening on unusual ports", "T1571", "bind shell listener backdoor unusual port",
      ["hosts listening on odd ports", "bind shells"], "NetworkListenIP4", [("LocalPort", "in", "4444,1337,31337,5555,8888,9999")], "group", ["ComputerName", "LocalPort"]),
    L("linux_curl_pipe", "Linux: curl / wget piped to a shell", "T1059.004", "linux execution curl wget pipe bash download",
      ["curl piped to bash", "wget | sh on linux"], "ProcessRollup2", [("CommandLine", "regex", r"(curl|wget)\s.*\|\s*(ba|z)?sh")], fields=["ComputerName", "UserName", "CommandLine"],
      platform="Lin"),
    L("linux_tmp_exec", "Linux: binaries running from /tmp or /dev/shm", "T1059.004", "linux execution tmp dev shm malware",
      ["processes running from tmp on linux", "dev shm execution"], "ProcessRollup2", [("ImageFileName", "regex", r"^/(tmp|dev/shm|var/tmp)/")], "group",
      ["ComputerName", "ImageFileName", "UserName"], platform="Lin"),
    L("linux_reverse_shell", "Linux: reverse shell command lines", "T1059.004", "linux reverse shell dev tcp netcat socat",
      ["reverse shells on linux", "netcat -e"], "ProcessRollup2", [("CommandLine", "regex", r"/dev/tcp/|\bnc(at)?\s.*-e\s|bash\s+-i\s*>&|socat\s.*exec")],
      fields=["ComputerName", "UserName", "CommandLine"], platform="Lin"),
    L("linux_cron", "Linux: crontab changes", "T1053.003", "linux persistence cron crontab",
      ["crontab modifications", "cron persistence"], "ProcessRollup2", [("CommandLine", "regex", r"crontab\s+-|/etc/cron")], fields=["ComputerName", "UserName", "CommandLine"],
      platform="Lin"),
    L("mac_osascript", "macOS: osascript execution", "T1059.002", "mac applescript osascript execution",
      ["osascript on macs", "applescript execution"], "ProcessRollup2", [("FileName", "equals", "osascript")], fields=["ComputerName", "UserName", "CommandLine"],
      platform="Mac"),
    L("top_processes", "Most common processes", "", "baseline top processes count",
      ["top processes", "most common programs"], "ProcessRollup2", [], "top", ["FileName"]),
    L("process_timechart", "Process starts over time", "", "timeline chart volume",
      ["process activity over time"], "ProcessRollup2", [], "timechart"),
]
LIB = {x["id"]: x for x in LIBRARY}
for _x in LIBRARY:
    _x["cql"] = compile_plan(_x["plan"])[0]


# ------------------------------------------------------------------ retrieval (question -> closest library / saved queries)
STOP = {"the", "and", "for", "with", "show", "find", "list", "which", "what", "where", "who", "any", "all", "from", "that", "this", "are", "was",
        "were", "have", "has", "hosts", "host", "machines", "endpoints", "query", "queries", "cql", "write", "give", "get", "last", "days", "day",
        "week", "month", "hours", "today", "please", "can", "you", "me", "our", "used", "using", "run", "ran", "did", "does", "into", "over",
        "in", "on", "of", "to", "by", "or", "is", "it", "at", "an", "be", "as", "do", "my", "we", "us", "past", "hunt", "hunting", "threat", "look", "search", "find", "activity", "check", "recent", "recently", "being", "been", "there"}
EXPAND = {"lateral": "psexec wmic smb rdp remote", "persistence": "schtasks scheduled run key service autostart cron", "exfil": "rclone mega exfiltration",
          "exfiltration": "rclone mega", "ransomware": "shadow vssadmin wbadmin impact", "credential": "lsass mimikatz dump", "dumping": "lsass mimikatz",
          "c2": "command control beacon tor port dns", "beacon": "c2 port", "brute": "failed logon", "spray": "password failed logon", "spraying": "password failed",
          "download": "certutil bitsadmin downloadstring curl", "phishing": "office macro winword outlook", "macro": "office winword",
          "webshell": "w3wp web shell", "recon": "discovery whoami nltest", "discovery": "nltest whoami adfind", "remote": "rdp anydesk teamviewer",
          "obfuscated": "encoded base64", "base64": "encoded", "dga": "random domains", "rdp": "3389 remote desktop", "tamper": "defender disable",
          "antivirus": "defender", "logs": "wevtutil clear", "admin": "administrators domain admins", "masquerade": "masquerading svchost",
          "rare": "rare uncommon", "uncommon": "rare", "anydesk": "remote access rmm", "teamviewer": "remote access rmm", "logon": "logon logons",
          "login": "logon", "logins": "logon", "logged": "logon", "failed": "failed logon", "linux": "linux", "mac": "mac osascript", "tor": "tor"}


def _words(text, expand=True):
    toks = [w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) > 1 and w not in STOP]
    out = []
    for w in toks:
        stem = w[:-3] if w.endswith("ing") and len(w) > 6 else w[:-2] if w.endswith("ed") and len(w) > 5 else w[:-1] if w.endswith("s") and len(w) > 4 else w
        out += [w] + ([stem] if stem != w else [])
        if expand:
            out += EXPAND.get(w, "").split() + (EXPAND.get(stem, "").split() if stem != w else [])
    return out


def _doc(e):
    return " ".join([e["title"], e.get("mitre") or "", e.get("tags") or "", " ".join(e.get("examples") or []), e.get("cql") or ""])


def _doc_weights(e):
    """Token weights of a library entry: title and example questions count most, the query text least."""
    w = Counter()
    for text, k in ((e["title"], 2.0), (" ".join(e.get("examples") or []), 2.0), (e.get("tags") or "", 1.0), (e.get("mitre") or "", 1.0),
                    (re.sub(r"[^a-z0-9]+", " ", (e.get("cql") or "").lower()), 0.4)):
        for t in set(_words(text, expand=False)):
            w[t] += k
    return w


def saved_queries():
    with db.get_conn() as c:
        _ensure(c)
        return db.rows(c, "SELECT * FROM cql_saved ORDER BY uses DESC, id DESC LIMIT 500")


_HUBC = {"gen": None, "rows": []}


def hub_queries():
    if _HUBC["gen"] == db.GEN[0]:
        return _HUBC["rows"]
    try:
        with db.get_conn() as c:
            rows = db.rows(c, "SELECT id, name, description, cql, mitre, tags, log_sources, author FROM cql_hub")
    except Exception:  # noqa: BLE001
        rows = []
    _HUBC.update(gen=db.GEN[0], rows=rows)
    return rows


def retrieve(question, k=5):
    docs = [dict(e, source="library") for e in LIBRARY]
    for h in hub_queries():
        docs.append({"id": f"hub:{h['id']}", "title": h["name"], "mitre": h.get("mitre") or "", "tags": f"{h.get('tags') or ''} {h.get('log_sources') or ''}",
                     "examples": [re.split(r"(?<=[.!?])\s", h.get("description") or "")[0][:200]], "cql": h["cql"], "plan": None, "source": "cqlhub",
                     "author": h.get("author"), "url": "https://www.byteray.com/cql-hub"})
    for s in saved_queries():
        docs.append({"id": f"saved:{s['id']}", "title": s["title"], "mitre": s.get("mitre") or "", "tags": s.get("tags") or "", "examples": [s.get("question") or ""],
                     "cql": s["cql"], "plan": db.jloads(s.get("plan"), None), "source": "saved"})
    tok_docs = [_doc_weights(d) for d in docs]
    n = len(docs)
    df = Counter(w for t in tok_docs for w in t)
    groups = []  # one group per word of the question: its forms, then what it expands to
    for w in [w for w in re.findall(r"[a-z0-9]+", (question or "").lower()) if len(w) > 1 and w not in STOP and not w.isdigit()]:
        forms = set(_words(w, expand=False))
        groups.append((forms, set(_words(w)) - forms))
    scored = []
    for d, t in zip(docs, tok_docs):
        s, covered = 0.0, 0
        for forms, extra in groups:
            hit = max((math.log(1 + n / df[f]) * t[f] for f in forms if t.get(f)), default=0)
            s += hit + 0.4 * max((math.log(1 + n / df[f]) * t[f] for f in extra if t.get(f)), default=0)
            covered += 1 if hit else 0
        cov = covered / len(groups) if groups else 0
        s *= 0.5 + cov
        if s > 0:
            scored.append((round(s, 2), {**d, "coverage": round(cov, 2)}))
    scored.sort(key=lambda x: -x[0])
    return [{**d, "score": s} for s, d in scored[:k]]


# ------------------------------------------------------------------ generation
def _plan_schema():
    return {"type": "object", "properties": {
        "event": {"type": "string", "enum": list(EVENTS)},
        "platform": {"type": "string", "enum": ["any", "Win", "Lin", "Mac"]},
        "filters": {"type": "array", "items": {"type": "object", "properties": {
            "field": {"type": "string", "enum": ALL_FIELDS}, "op": {"type": "string", "enum": OPS}, "value": {"type": "string"}},
            "required": ["field", "op", "value"]}},
        "output": {"type": "string", "enum": OUTPUTS},
        "fields": {"type": "array", "items": {"type": "string", "enum": ALL_FIELDS}},
        "min_count": {"type": "integer"}, "max_count": {"type": "integer"}},
        "required": ["event", "platform", "filters", "output", "fields"]}


def _plan_prompt(events):
    ev_lines = "\n".join(f"- {e}: {EVENTS[e][0]}. fields: {', '.join(EVENTS[e][1])}" for e in events)
    return ("You write CrowdStrike Falcon threat-hunting searches as a JSON query plan; code turns it into CQL. Reply with JSON only.\n"
            "Rules:\n"
            "1. Pick ONE event. Use only that event's fields plus ComputerName, aid, event_platform, LocalAddressIP4.\n"
            "2. filters: op is one of equals, not_equals, contains, not_contains, regex, not_regex, starts_with, ends_with, in (comma list), greater, less. "
            "Values are plain text, not quoted. Use regex only for alternatives like (a|b). Copy IPs, hashes, domains, users and hostnames exactly.\n"
            "3. output: table = list matching events (fields = columns); group = which hosts / values and how often (fields = group-by keys); "
            "count = one number; top = most common values; timechart = activity over time.\n"
            "4. min_count / max_count only for thresholds like 'more than 10 failed logons' (min_count 10) or 'rare' (max_count 2); else 0.\n"
            "5. platform: Win, Lin or Mac when the question names one, else any.\n"
            "6. group fields follow the question: 'which hosts' -> ComputerName; 'which accounts / users' -> UserName (and ComputerName); "
            "'which IPs / sources' -> RemoteAddressIP4.\n"
            f"Events:\n{ev_lines}\n"
            "LogonType: 2 interactive, 3 network, 10 RDP.")


def _pick_events(question, matches, ents):
    evs = []
    for m in matches:
        e = (m.get("plan") or {}).get("event")
        if e and e not in evs:
            evs.append(e)
    for key, e in (("hash", "ProcessRollup2"), ("ip", "NetworkConnectIP4"), ("domain", "DnsRequest"), ("user", "UserLogon"), ("process", "ProcessRollup2")):
        if ents.get(key) and e not in evs:
            evs.append(e)
    for e in ("ProcessRollup2", "NetworkConnectIP4", "DnsRequest", "UserLogon", "UserLogonFailed2"):
        if e not in evs:
            evs.append(e)
    return evs[:5]


def _model_plan(question, matches, ents):
    from .ai_hunt import _llm
    evs = _pick_events(question, matches, ents)
    msgs = [{"role": "system", "content": _plan_prompt(evs)}]
    shots = [m for m in matches if m.get("plan")][:3]
    if len(shots) < 2:
        shots += [dict(LIB[i]) for i in ("encoded_powershell", "failed_logons_bruteforce", "c2_ports") if i not in {s["id"] for s in shots}][:3 - len(shots)]
    for s in reversed(shots):
        ex = (s.get("examples") or [s["title"]])[0]
        p = {k: v for k, v in s["plan"].items() if k != "limit"}
        msgs += [{"role": "user", "content": ex}, {"role": "assistant", "content": json.dumps(p)}]
    msgs.append({"role": "user", "content": question})
    raw = _llm(msgs, _plan_schema(), 400)
    out = json.loads(re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip())
    if out.get("event") not in EVENTS:
        raise ValueError(f"model chose an unknown event: {out.get('event')}")
    return out


def _model_cql(question, matches):
    """Free-form mode: the model writes CQL text (then auto-fix + lint)."""
    from .ai_hunt import _llm
    shots = [m for m in matches if m.get("cql") and len(m["cql"]) < 1500][:4] or [LIB["encoded_powershell"], LIB["c2_ports"]]
    ev = "\n".join(f"- {e}: {', '.join(EVENTS[e][1])}" for e in EVENTS)
    sys_ = ("You write CrowdStrike CQL (LogScale) threat-hunting queries. Reply with the query only, no explanation, no code fences.\n"
            "CQL syntax: start with filters separated by spaces (AND), e.g. #event_simpleName=ProcessRollup2 FileName=/powershell/i CommandLine=/-enc/i ; "
            "OR and NOT allowed; regex /…/i; in(field=\"F\", values=[\"a\",\"b\"]). Then pipe stages: | groupBy([ComputerName, FileName]) | sort(_count, order=desc) "
            "| table([@timestamp, ComputerName, CommandLine], limit=200) | head(50) | count() | top([FileName]). No SQL, no WHERE, no ==.\n"
            f"Events and fields:\n{ev}")
    msgs = [{"role": "system", "content": sys_}]
    for s in reversed(shots):
        msgs += [{"role": "user", "content": (s.get("examples") or [s["title"]])[0]}, {"role": "assistant", "content": s["cql"]}]
    msgs.append({"role": "user", "content": question})
    txt = re.sub(r"<think>.*?</think>", "", _llm(msgs, None, 300), flags=re.S).strip()
    return re.sub(r"^```\w*\n?|```$", "", txt.strip()).strip()


def _rules_plan(question, ents, matches):
    """No model: the question's entities, else the closest library hunt."""
    ql = question.lower()
    if ents.get("hash"):
        f = {32: "MD5HashData", 40: "SHA1HashData", 64: "SHA256HashData"}.get(len(ents["hash"]), "SHA256HashData")
        f = f if f != "SHA1HashData" else "SHA256HashData"
        return {"event": "ProcessRollup2", "platform": "any", "filters": [{"field": f, "op": "equals", "value": ents["hash"]}], "output": "group",
                "fields": ["ComputerName", "FileName", "ImageFileName"]}, "entities"
    if ents.get("ip"):
        logon = any(w in ql for w in ("logon", "login", "logged", "rdp"))
        if logon:
            ev = "UserLogonFailed2" if "fail" in ql else "UserLogon"
            return {"event": ev, "platform": "any", "filters": [{"field": "RemoteAddressIP4", "op": "equals", "value": ents["ip"]}], "output": "group",
                    "fields": ["ComputerName", "UserName", "LogonType"]}, "entities"
        inbound = any(w in ql for w in ("inbound", "from ", "accepted"))
        return {"event": "NetworkReceiveAcceptIP4" if inbound else "NetworkConnectIP4", "platform": "any",
                "filters": [{"field": "RemoteAddressIP4", "op": "equals", "value": ents["ip"]}], "output": "group",
                "fields": ["ComputerName", "RemotePort" if not inbound else "LocalPort"]}, "entities"
    if ents.get("domain") and not ents.get("process"):
        return {"event": "DnsRequest", "platform": "any", "filters": [{"field": "DomainName", "op": "ends_with", "value": ents["domain"]}], "output": "group",
                "fields": ["ComputerName", "DomainName"]}, "entities"
    if ents.get("user") or re.search(r"\b(user|account)\s+[\w.@\\$-]+", ql):
        m = re.search(r"\b(?:user|account)\s+([\w.@\\$-]+)", question, re.I)
        u = ents.get("user") or (m.group(1) if m else None)
        if u and any(w in ql for w in ("logon", "login", "logged", "log on", "sign")):
            ev = "UserLogonFailed2" if "fail" in ql else "UserLogon"
            return {"event": ev, "platform": "any", "filters": [{"field": "UserName", "op": "equals", "value": u}], "output": "group",
                    "fields": ["ComputerName", "UserName", "LogonType", "RemoteAddressIP4"]}, "entities"
        if u:
            return {"event": "ProcessRollup2", "platform": "any", "filters": [{"field": "UserName", "op": "equals", "value": u}], "output": "group",
                    "fields": ["ComputerName", "FileName"]}, "entities"
    if ents.get("port") and any(w in ql for w in ("port", "connect", "outbound", "traffic")):
        listen = "listen" in ql
        return {"event": "NetworkListenIP4" if listen else "NetworkConnectIP4", "platform": "any",
                "filters": [{"field": "LocalPort" if listen else "RemotePort", "op": "equals", "value": str(ents["port"])}], "output": "group",
                "fields": ["ComputerName"] + ([] if listen else ["RemoteAddressIP4"])}, "entities"
    best = next((m for m in matches if m.get("plan")), None)
    if ents.get("process") and not (best and best["score"] >= 6 and ents["process"].split(".")[0].lower() in _doc(best).lower()):
        return {"event": "ProcessRollup2", "platform": "any", "filters": [{"field": "FileName", "op": "equals", "value": ents["process"]}], "output": "group",
                "fields": ["ComputerName", "UserName", "CommandLine"]}, "entities"
    if best and best["score"] >= 2.5:
        return json.loads(json.dumps(best["plan"])), f"library:{best['id']}"
    m = re.search(r"(?:command line|cmdline|commandline)s?\s+(?:with|containing|contains|like)\s+[\"']?([^\"']+?)[\"']?\s*$", question, re.I)
    if m:
        return {"event": "ProcessRollup2", "platform": "any", "filters": [{"field": "CommandLine", "op": "contains", "value": m.group(1)}], "output": "table",
                "fields": ["ComputerName", "UserName", "FileName", "CommandLine"]}, "entities"
    if best:
        return json.loads(json.dumps(best["plan"])), f"library:{best['id']}"
    return None, None


def _ground(plan, ents, question):
    """Make sure the entities in the question are in the plan (small models drop them) and fit the event."""
    notes = []
    ev = plan["event"]
    fl = plan.setdefault("filters", [])
    vals = " ".join(str(f.get("value")) for f in fl).lower()
    want = []
    if ents.get("hash") and ents["hash"] not in vals and ev in ("ProcessRollup2", "ImageHash", "PeFileWritten"):
        want.append({"field": {32: "MD5HashData"}.get(len(ents["hash"]), "SHA256HashData"), "op": "equals", "value": ents["hash"]})
    if ents.get("ip") and ents["ip"] not in vals and "RemoteAddressIP4" in EVENTS[ev][1]:
        want.append({"field": "RemoteAddressIP4", "op": "equals", "value": ents["ip"]})
    if ents.get("domain") and ents["domain"] not in vals and ev == "DnsRequest":
        want.append({"field": "DomainName", "op": "ends_with", "value": ents["domain"]})
    if ents.get("host") and ents["host"].lower() not in vals:
        want.append({"field": "ComputerName", "op": "equals", "value": ents["host"]})
    for w in want:
        fl.append(w)
        notes.append(f"added {w['field']} {w['op']} {w['value']} from the question")
    ql = question.lower()
    if plan.get("output") == "group":
        keys = plan.setdefault("fields", [])
        for words, f in ((r"\b(accounts?|users?|usernames?)\b", "UserName"), (r"\b(ips?|sources?|addresses)\b", "RemoteAddressIP4"),
                         (r"\b(hosts?|machines?|endpoints?|servers?|computers?)\b", "ComputerName")):
            if re.search(words, ql) and f in EVENTS[ev][1] + ["ComputerName"] and f not in keys:
                keys.append(f)
                notes.append(f"grouped by {f} too (the question asks about it)")
    if plan.get("platform") in (None, "", "any"):
        for word, p in (("windows", "Win"), ("linux", "Lin"), ("macos", "Mac"), (" mac ", "Mac")):
            if word in f" {ql} ":
                plan["platform"] = p
    return plan, notes


def generate(question, mode="auto", style="plan", use_cache=True):
    """Plain English -> CQL. mode: auto (model, falls back to rules) | rules | model. style: plan (model fills a JSON plan) | cql (model writes CQL)."""
    from .ai_hunt import ai_settings, entities
    q = (question or "").strip()[:600]
    if not q:
        raise HTTPException(400, "Describe what to hunt for")
    t0 = time.time()
    ck = f"{mode}|{style}|{ai_settings()['model']}|{re.sub(r'[^a-z0-9.:_/-]+', ' ', q.lower()).strip()}"
    hit = _cache_get(ck) if use_cache else None
    if hit:
        return {**hit, "cached": True, "seconds": round(time.time() - t0, 2)}
    ents = entities(q)
    matches = retrieve(q, 10)
    plan, source, err, notes, cql = None, None, None, [], None
    use_model = mode != "rules" and ai_settings()["provider"] != "off"
    best = next((m for m in matches if m.get("plan")), None)
    specific = any(ents.get(k) for k in ("ip", "hash", "domain", "port", "process", "user")) or re.search(r"\d", re.sub(r"(last|past)\s+\d+\s*\w+|PAY|[A-Z]+-[A-Z0-9-]+", "", q))
    if mode == "auto" and best and best["score"] >= 15 and best.get("coverage", 0) >= 0.99 and not specific:
        plan, source = json.loads(json.dumps(best["plan"])), f"library:{best['id']}"  # a tested hunt answers it exactly: no model call
        use_model = False
    if use_model:
        try:
            if style == "cql":
                cql, source = _model_cql(q, matches), "model (free-form CQL)"
            else:
                plan, source = _model_plan(q, matches, ents), "model"
        except Exception as e:  # noqa: BLE001
            err = str(e)[:300]
            if mode == "model":
                raise HTTPException(502, f"The model failed: {err}") from e
    if cql is None and plan is None:
        plan, source = _rules_plan(q, ents, matches)
        if plan is None:
            raise HTTPException(422, "Could not build a hunt for that. Name a process, command line, IP, domain, hash, user or technique.")
    if plan is not None:
        plan, gnotes = _ground(plan, ents, q)
        notes += gnotes
        try:
            cql, cnotes = compile_plan(plan)
        except CqlError as e:
            if source != "model":
                raise HTTPException(422, str(e)) from e
            err = f"model plan could not be compiled: {e}"
            plan, source = _rules_plan(q, ents, matches)
            cql, cnotes = compile_plan(plan)
        notes += cnotes
    lt = lint(cql)
    cql = lt["cql"]
    lib_id = source.split(":", 1)[1] if source and source.startswith("library:") else None
    title = LIB[lib_id]["title"] if lib_id and lib_id in LIB else None
    out = {"question": q, "cql": cql, "plan": plan, "source": source, "title": title, "mitre": LIB[lib_id]["mitre"] if lib_id in LIB else None,
           "explain": explain(cql), "lint": lt, "notes": notes, "model_error": err, "days": ents.get("days") or 7, "entities": ents,
           "seconds": round(time.time() - t0, 2),
           "alternatives": [{"id": m["id"], "title": m["title"], "mitre": m.get("mitre"), "cql": m["cql"], "score": m["score"], "source": m["source"]}
                            for m in matches if m["source"] != "cqlhub"][:4],
           "references": [{"id": m["id"], "title": m["title"], "mitre": m.get("mitre"), "cql": m["cql"], "author": m.get("author"), "url": m.get("url"),
                           "score": m["score"]} for m in matches if m["source"] == "cqlhub" and m["score"] >= 4][:3]}
    if not err and lt["ok"]:
        _cache_put(ck, out)
    return out


def _cache_get(key):
    try:
        with db.get_conn() as c:
            _ensure(c)
            r = c.execute("SELECT value FROM cql_cache WHERE key=? AND at >= datetime('now','-7 day')", (key,)).fetchone()
        return json.loads(r[0]) if r else None
    except Exception:  # noqa: BLE001
        return None


def _cache_put(key, val):
    try:
        with db.get_conn() as c:
            _ensure(c)
            c.execute("INSERT OR REPLACE INTO cql_cache(key, value, at) VALUES (?,?,datetime('now'))", (key, json.dumps(val, default=str)))
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ running a query
def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS cql_saved (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, question TEXT, cql TEXT, plan TEXT, mitre TEXT,
                 tags TEXT, created_at TEXT, uses INTEGER DEFAULT 0)""")
    c.execute("CREATE TABLE IF NOT EXISTS cql_cache (key TEXT PRIMARY KEY, value TEXT, at TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS cql_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, question TEXT, cql TEXT, source TEXT, ok INTEGER,
                 rows INTEGER, seconds REAL, error TEXT, via TEXT)""")


PREFERRED = ["@timestamp", "_bucket", "ComputerName", "UserName", "ParentBaseFileName", "FileName", "ImageFileName", "CommandLine", "DomainName",
             "RemoteAddressIP4", "RemotePort", "LocalPort", "LogonType", "TaskName", "TaskExecCommand", "RegObjectName", "RegValueName", "RegStringValue",
             "SHA256HashData", "_count"]


def columns(rows):
    seen = []
    for r in rows[:100]:
        for k in r:
            if k not in seen:
                seen.append(k)
    first = [c for c in PREFERRED if c in seen]
    return first + [c for c in seen if c not in first and c not in ("#event_simpleName", "aid", "event_platform", "@rawstring", "@id", "#repo", "#type",
                                                                     "@timezone", "@ingesttimestamp", "cid")] or seen


def run(cql_text, days=7, question=None, via=None):
    from . import cs_api
    lt = lint(cql_text)
    if not lt["ok"]:
        return {"ok": False, "error": "; ".join(lt["errors"]), "lint": lt, "rows": [], "columns": [], "total": 0}
    q = lt["cql"]
    days = max(1, min(90, int(days or 7)))
    start = datetime.now(timezone.utc) - timedelta(days=days)
    t0 = time.time()
    mode = via or cs_api.mode()
    rows, err, meta = [], None, {}
    try:
        if mode in ("sample", "direct"):
            rows, meta = cs_api.ngsiem(q, int(start.timestamp() * 1000))
        elif mode == "mcp":
            from . import falconmcp
            r = falconmcp.call("falcon_search_ngsiem", {"query_string": q, "start": start.strftime("%Y-%m-%dT%H:%M:%SZ")}, user="cql")
            if not r["ok"]:
                raise RuntimeError(r["error"] or "Falcon MCP search failed")
            d = r["data"] if isinstance(r["data"], dict) else {"results": r["data"] or []}
            rows = d.get("events") or d.get("results") or []
            meta = d.get("metadata") or d.get("job") or {}
        else:
            raise RuntimeError("No CrowdStrike connection: add API credentials (Sync & settings → Connection) or connect Falcon MCP")
    except HTTPException as e:
        err = str(e.detail)
    except Exception as e:  # noqa: BLE001
        err = str(e)[:500]
    secs = round(time.time() - t0, 2)
    with db.get_conn() as c:
        _ensure(c)
        rid = c.execute("INSERT INTO cql_runs(at, question, cql, source, ok, rows, seconds, error, via) VALUES (?,?,?,?,?,?,?,?,?)",
                        (db.now_iso(), question, q, None, 0 if err else 1, len(rows), secs, err, mode)).lastrowid
    flat = [{k: (", ".join(map(str, v)) if isinstance(v, list) else v) for k, v in r.items()} for r in rows[:2000]] if isinstance(rows, list) else []
    return {"ok": err is None, "error": err, "rows": flat[:1000], "total": len(rows) if isinstance(rows, list) else 0, "columns": columns(flat), "seconds": secs,
            "via": mode, "cql": q, "lint": lt, "days": days, "meta": {k: meta.get(k) for k in ("eventCount", "processedEvents", "timeMillis") if isinstance(meta, dict)},
            "run_id": rid}


# ------------------------------------------------------------------ evaluation: does the model write correct hunts?
# (question, the event it must use, substrings the CQL must contain (case-insensitive))
EVAL = [
    ("encoded powershell commands in the last 3 days", "ProcessRollup2", ["powershell", "enc"]),
    ("which hosts ran rclone", "ProcessRollup2", ["rclone"]),
    ("lsass memory dumping with comsvcs", "ProcessRollup2", ["minidump"]),
    ("office applications spawning powershell or cmd", "ProcessRollup2", ["winword", "parentbasefilename"]),
    ("psexec lateral movement", "ProcessRollup2", ["psexec"]),
    ("certutil downloading files", "ProcessRollup2", ["certutil"]),
    ("who connected to 203.0.113.66", "NetworkConnectIP4", ["203\\.0\\.113\\.66"]),
    ("outbound connections on port 4444", "NetworkConnectIP4", ["4444"]),
    ("which machines looked up sample-c2.example", "DnsRequest", ["sample-c2"]),
    ("dns lookups to .xyz or .top domains", "DnsRequest", ["xyz"]),
    ("accounts with more than 10 failed logons", "UserLogonFailed2", ["_count"]),
    ("rdp logons by user", "UserLogon", ["logontype"]),
    ("where did user svc_backup log on", "UserLogon", ["svc_backup"]),
    ("did b" + "b" * 63 + " execute anywhere", "ProcessRollup2", ["bbbbbbbb"]),
    ("shadow copies being deleted (ransomware)", "ProcessRollup2", ["shadow"]),
    ("new scheduled tasks", "ScheduledTaskRegistered", ["scheduledtaskregistered"]),
    ("registry run key persistence", "AsepValueUpdate", ["run"]),
    ("anydesk or teamviewer running", "ProcessRollup2", ["anydesk"]),
    ("curl piped to bash on linux", "ProcessRollup2", ["curl", "lin"]),
    ("programs running from the temp folder", "ProcessRollup2", ["temp"]),
    ("domain admins group enumeration", "ProcessRollup2", ["domain admins"]),
    ("hosts listening on port 4444", "NetworkListenIP4", ["4444"]),
    ("whoami executions per host", "ProcessRollup2", ["whoami"]),
    ("defender exclusions added with powershell", "ProcessRollup2", ["mppreference"]),
]
EVAL_STATE = {"running": False, "done": 0, "total": len(EVAL), "result": None}


def _score(res, want_ev, subs):
    cql = (res or {}).get("cql") or ""
    low = cql.lower()
    ev_ok = f"#event_simplename={want_ev.lower()}" in low
    subs_ok = all(re.search(s, low) for s in subs)
    ok = bool(res) and res["lint"]["ok"] and ev_ok and subs_ok
    return ok, ev_ok, subs_ok


def run_eval(style="plan"):
    import threading
    if EVAL_STATE["running"]:
        raise HTTPException(409, "An evaluation is already running")
    EVAL_STATE.update(running=True, done=0, result=None, total=len(EVAL))

    def work():
        from .ai_hunt import ai_settings
        rows, t0 = [], time.time()
        try:
            for q, ev, subs in EVAL:
                s = time.time()
                try:
                    m = generate(q, "model", style, use_cache=False)
                    merr = None
                except Exception as e:  # noqa: BLE001
                    m, merr = None, str(getattr(e, "detail", e))[:160]
                ms = round(time.time() - s, 2)
                r = generate(q, "rules", use_cache=False)
                mok, mev, msub = _score(m, ev, subs)
                rok, _, _ = _score(r, ev, subs)
                rows.append({"question": q, "event": ev, "model_ok": mok, "model_event_ok": mev, "model_values_ok": msub, "rules_ok": rok,
                             "model_cql": (m or {}).get("cql"), "rules_cql": r["cql"], "seconds": ms, "error": merr})
                EVAL_STATE["done"] += 1
            n = len(rows)
            res = {"at": db.now_iso(), "model": ai_settings()["model"], "style": style, "n": n,
                   "model_accuracy": round(100 * sum(r["model_ok"] for r in rows) / n), "rules_accuracy": round(100 * sum(r["rules_ok"] for r in rows) / n),
                   "model_valid": round(100 * sum(1 for r in rows if r["model_cql"]) / n),
                   "avg_seconds": round(sum(r["seconds"] for r in rows) / n, 2), "total_seconds": round(time.time() - t0, 1), "rows": rows}
            EVAL_STATE["result"] = res
            db.set_settings({"ai_cql_eval_last": json.dumps(res)})
        finally:
            EVAL_STATE["running"] = False
    threading.Thread(target=work, daemon=True).start()
    return {k: v for k, v in EVAL_STATE.items() if k != "result"}


# ------------------------------------------------------------------ knowledge-base documents (CQL / FQL references, the hunt library)
def kb_texts():
    ev = "\n\n".join(f"{e} — {d}\nFields: " + ", ".join(f"{f} ({FIELD_HELP[f]})" if f in FIELD_HELP else f for f in fs) +
                     f"\nExample: #event_simpleName={e} | table([{', '.join(cols)}], limit=50)" for e, (d, fs, cols) in EVENTS.items())
    lib = "\n\n".join(f"{x['title']} ({x['mitre'] or 'baseline'}) — tags: {x['tags']}\nExample questions: {'; '.join(x['examples'])}\n{x['cql']}" for x in LIBRARY)
    return {
        "cql_syntax": ("CQL (LogScale query language) — syntax guide", "guide", CQL_GUIDE),
        "cql_functions": ("CQL functions for hunting — reference", "guide", CQL_FUNCTIONS),
        "cql_events": ("Falcon event dictionary (events and fields for hunting)", "guide",
                       "Falcon telemetry events used in NG-SIEM / Event Search hunts. Every event also has: " + ", ".join(COMMON[:8]) + ".\n\n" + ev),
        "cql_library": ("Threat-hunting query library (CQL, MITRE-tagged)", "guide",
                        "Tested CQL hunting queries the AI SOC uses as examples. Run them from AI SOC → Hunt studio.\n\n" + lib),
        "fql_guide": ("FQL (Falcon Query Language) — API filter guide", "guide", FQL_GUIDE),
        "cql_vs_spl": ("CQL for Splunk SPL / KQL users — translation table", "guide", CQL_VS_SPL),
    }


CQL_GUIDE = """CQL is the query language of CrowdStrike Falcon NG-SIEM and Event Search (it is the LogScale query language, also called LQL / Humio query language). A query is a pipeline: filters first, then functions, separated by |.

Filters (all must match — a space means AND):
#event_simpleName=ProcessRollup2 FileName=cmd.exe
Tags start with # (#event_simpleName, #repo). Fields are case-sensitive names; values without quotes may use * wildcards: FileName=power*.
Quotes for values with spaces: CommandLine="net user".
Regex (the usual way to match text): CommandLine=/-enc(odedcommand)?\\s/i  — /…/ is a regex, the i flag makes it case-insensitive.
Not equal: FileName!=svchost.exe ; field present: UserName=* ; field missing: UserName!=*
Numbers: RemotePort=3389 ; RemotePort>1024 ; LogonType!=3
OR / NOT / brackets: (FileName=psexec.exe OR FileName=paexec.exe) NOT ComputerName=JUMP-01
Lists: in(field="FileName", values=["rclone.exe", "megasync.exe"], ignoreCase=true)
Free text: "mimikatz" searches the whole raw event (slow — prefer a field).
Platform: event_platform=Win | Lin | Mac.

Time range is not part of the query: it is set on the search (last 24h, 7d…). The AI SOC Hunt studio has a days selector.

After the filters, pipe into functions:
| groupBy([ComputerName, FileName])                  count events per host and file (_count)
| groupBy([ComputerName], function=count(UserName, distinct=true, as=users))
| _count > 10                                        filter on a computed field (a filter can follow any function)
| sort(_count, order=desc, limit=50)
| table([@timestamp, ComputerName, UserName, CommandLine], limit=200)
| head(20)  | tail(20)  | count()  | top([FileName], limit=10)
| timeChart(span=1h)                                  events over time
| x := lower(FileName)  or  | lower(FileName, as=fn)  computed fields
| case { FileName=/powershell/i | type := "ps" ; * | type := "other" }
| join({#event_simpleName=DnsRequest}, field=aid, include=[DomainName])   correlate two event types (expensive; filter first)

Good habits: always filter #event_simpleName first (fast), filter on fields not free text, end with groupBy / table / head so results are small, use /…/i regexes because Windows names vary in case, and check results on one host before widening."""

CQL_FUNCTIONS = """CQL functions most used in hunting
groupBy(field|[fields], function=count()|[functions], limit=N|max) — aggregate per value; default output _count.
count(field?, distinct=true?, as=name) — number of events (or distinct values).
table([fields], limit=N, sortby=field, order=desc) — a table of events, newest first (default 200 rows).
select([fields]) — keep only some fields (no limit).
sort(field|[fields], order=desc|asc, limit=N) — sort (default 200 rows).
head(N) / tail(N) — first / last N rows.
top([fields], limit=N) — most common values with _count.
stats([count(), min(x), max(x)]) — several aggregates at once.
min / max / sum / avg(field, as=name).
collect([fields]) — inside groupBy: list the distinct values, e.g. groupBy(ComputerName, function=collect([FileName])).
in(field="F", values=[…], ignoreCase=true) — field is one of the values.
regex("pattern", field=F, flags=i) — regex with named capture groups ((?<name>…) creates a field).
wildcard(field=F, pattern="*x*", ignoreCase=true).
cidr(field=RemoteAddressIP4, subnet=["10.0.0.0/8"]) — IP in a range; negate with !cidr(…) to find public IPs.
timeChart(span=1h, function=count()) / bucket(span=1d) — counts over time.
rename(field=F, as=G), drop([fields]), default(field=F, value="-"), lower(F) / upper(F).
formatTime("%Y-%m-%d %H:%M", field=@timestamp, as=time).
join({subquery}, field=aid, include=[fields]) / defineTable + match — correlate events (filter both sides first).
ipLocation(RemoteAddressIP4) / asn(RemoteAddressIP4) — geo / ASN enrichment.
shannonEntropy(DomainName) — randomness (DGA hunting).
case { cond | x := 1 ; * | x := 0 } — branching."""

FQL_GUIDE = """FQL (Falcon Query Language) is the filter syntax of the Falcon APIs (hosts, alerts, Spotlight, intel, IOCs) — not the same as CQL.
Form: field:'value' ; combine with + (AND) and , (OR inside the same field).
Operators: field:'x' (equals) · field:!'x' (not) · field:>'x' · field:>='x' · field:<'x' · field:*'*part*' (wildcard) · field:['a','b'] (any of).
Relative time: created_timestamp:>'now-7d' · last_seen:<'now-30d'.
Hosts: hostname, local_ip, external_ip, platform_name ('Windows','Linux','Mac'), os_version, agent_version, last_seen, first_seen, status ('normal','contained'),
reduced_functionality_mode ('yes'), tags, device_policies.prevention.policy_id. Example: platform_name:'Linux'+last_seen:<'now-7d'
Alerts (detections): created_timestamp, severity_name ('Critical','High',…), status ('new','in_progress','closed'), tactic, technique, device.hostname,
assigned_to_name, product ('epp','idp',…), filename. Example: severity_name:['Critical','High']+status:'new'
Spotlight vulnerabilities: status ('open','reopen','closed'), cve.id, cve.severity ('CRITICAL'…), cve.exprt_rating, cve.exploit_status, host_info.hostname,
apps.product_name_version. Example: status:'open'+cve.severity:'CRITICAL'
Intel indicators: indicator:'evil.example', type ('domain','ip_address','hash_sha256'…), malicious_confidence ('high','medium','low'), published_date.
Custom IOCs: value:'1.2.3.4', type ('ipv4','domain','sha256','md5'), action ('detect','prevent','no_action'), severity.
The AI SOC uses FQL for host / detection / vulnerability / intel lookups and CQL for event hunting."""

CQL_VS_SPL = """CQL for analysts who know Splunk SPL or Microsoft KQL
SPL: index=edr sourcetype=ProcessRollup2 FileName=cmd.exe        CQL: #event_simpleName=ProcessRollup2 FileName=cmd.exe
SPL: | where like(CommandLine, "%-enc%")                           CQL: CommandLine=/-enc/i
SPL: | stats count by ComputerName, FileName                      CQL: | groupBy([ComputerName, FileName])
SPL: | stats dc(UserName) as users by ComputerName                CQL: | groupBy([ComputerName], function=count(UserName, distinct=true, as=users))
SPL: | sort - count | head 20                                      CQL: | sort(_count, order=desc, limit=20)
SPL: | table _time, host, user                                     CQL: | table([@timestamp, ComputerName, UserName])
SPL: | dedup host                                                  CQL: | groupBy([ComputerName])
SPL: | eval x=lower(FileName)                                      CQL: | x := lower(FileName)
SPL: | timechart span=1h count                                     CQL: | timeChart(span=1h)
SPL: | search count>10                                             CQL: | _count > 10
KQL: DeviceProcessEvents | where FileName =~ "cmd.exe"            CQL: #event_simpleName=ProcessRollup2 FileName=/^cmd\\.exe$/i
KQL: | summarize count() by DeviceName                             CQL: | groupBy([ComputerName])
KQL: | project Timestamp, DeviceName                               CQL: | table([@timestamp, ComputerName])
KQL: | take 10                                                     CQL: | head(10)
Field names: Splunk host / KQL DeviceName → ComputerName; process / FileName → FileName; command line → CommandLine; parent → ParentBaseFileName;
user → UserName; destination IP → RemoteAddressIP4; destination port → RemotePort; DNS query → DomainName."""


# ------------------------------------------------------------------ routes
@router.post("/api/cql/generate")
def cql_generate(data: dict = Body(...)):
    return generate(data.get("question"), data.get("mode") or "auto", data.get("style") or "plan")


@router.post("/api/cql/lint")
def cql_lint(data: dict = Body(...)):
    lt = lint(str(data.get("cql") or ""), fix=data.get("fix", True))
    return {**lt, "explain": explain(lt["cql"]) if lt["ok"] else []}


@router.post("/api/cql/run")
def cql_run(data: dict = Body(...)):
    return run(str(data.get("cql") or ""), data.get("days") or 7, data.get("question"))


@router.get("/api/cql/library")
def cql_library():
    return {"rows": [{"id": x["id"], "title": x["title"], "mitre": x["mitre"], "tags": x["tags"], "examples": x["examples"], "cql": x["cql"],
                      "event": x["plan"]["event"], "platform": x["plan"]["platform"]} for x in LIBRARY],
            "saved": saved_queries()}


@router.get("/api/cql/schema")
def cql_schema():
    return {"events": [{"name": e, "description": d, "fields": [{"name": f, "help": FIELD_HELP.get(f), "numeric": f in NUMERIC} for f in fs], "columns": cols}
                       for e, (d, fs, cols) in EVENTS.items()], "common": COMMON, "functions": sorted(FUNCS)}


@router.post("/api/cql/saved")
def cql_save(data: dict = Body(...)):
    lt = lint(str(data.get("cql") or ""))
    if not lt["ok"]:
        raise HTTPException(400, "Fix the query first: " + "; ".join(lt["errors"]))
    with db.get_conn() as c:
        _ensure(c)
        sid = c.execute("INSERT INTO cql_saved(title, question, cql, plan, mitre, tags, created_at) VALUES (?,?,?,?,?,?,?)",
                        (str(data.get("title") or data.get("question") or "Saved hunt")[:160], str(data.get("question") or "")[:500], lt["cql"],
                         json.dumps(data.get("plan")) if data.get("plan") else None, str(data.get("mitre") or "")[:40], str(data.get("tags") or "")[:200],
                         db.now_iso())).lastrowid
    return {"id": sid}


@router.delete("/api/cql/saved/{sid}")
def cql_unsave(sid: int):
    with db.get_conn() as c:
        _ensure(c)
        c.execute("DELETE FROM cql_saved WHERE id=?", (sid,))
    return {"ok": True}


@router.get("/api/cql/runs")
def cql_runs(limit: int = 50):
    with db.get_conn() as c:
        _ensure(c)
        return {"rows": db.rows(c, "SELECT * FROM cql_runs ORDER BY id DESC LIMIT ?", (min(500, limit),))}


@router.post("/api/cql/eval")
def cql_eval(data: dict = Body(default={})):
    return run_eval((data or {}).get("style") or "plan")


@router.get("/api/cql/eval")
def cql_eval_status():
    last = EVAL_STATE["result"] or db.jloads(db.get_settings().get("ai_cql_eval_last"), None)
    return {"running": EVAL_STATE["running"], "done": EVAL_STATE["done"], "total": EVAL_STATE["total"], "result": last}


@router.get("/api/cql/status")
def aisoc_status():
    """One line of state for the AI SOC header: how live lookups reach CrowdStrike, the model, the knowledge."""
    from . import cs_api, falcon
    from .ai_hunt import ai_settings
    m = cs_api.mode()
    cfg = ai_settings()
    with db.get_conn() as c:
        _ensure(c)
        saved = c.execute("SELECT COUNT(*) FROM cql_saved").fetchone()[0]
        runs = c.execute("SELECT COUNT(*) FROM cql_runs").fetchone()[0]
        try:
            kb_docs = c.execute("SELECT COUNT(*) FROM kb_docs").fetchone()[0]
        except Exception:  # noqa: BLE001
            kb_docs = 0
    return {"live": m, "live_label": cs_api.describe(m), "credentials": falcon.is_configured(), "model": cfg["model"], "provider": cfg["provider"],
            "library": len(LIBRARY), "saved": saved, "runs": runs, "kb_docs": kb_docs, "events": len(EVENTS),
            "scopes": ["Hosts: Read", "Alerts: Read", "Vulnerabilities: Read", "Indicators (Falcon Intelligence): Read", "IOC Management: Read",
                       "NGSIEM (search)"]}
