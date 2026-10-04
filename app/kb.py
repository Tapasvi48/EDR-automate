"""Knowledge base for the AI SOC: documents the assistant searches and quotes (with the document named), next to the live facts
of the data fabric.

  your documents   SOPs, playbooks, escalation matrix, LOB owners, case notes / RCAs, vendor notes (paste or upload .txt / .md / .csv / .html)
  built-ins        console glossary (what "exposed", "feasible", "Spotlight only"… mean here), MITRE ATT&CK tactics and common
                   techniques, a triage / escalation playbook to adapt, and the Falcon MCP FQL / CQL guides (imported from the server)

Search is SQLite FTS5 (BM25 ranking) over ~800-character chunks: fast, offline, no model needed. The assistant gets the top
chunks as context and shows them as sources."""
import re

from fastapi import APIRouter, Body, File, HTTPException, UploadFile

from . import db

router = APIRouter()
KINDS = ("sop", "playbook", "policy", "contacts", "case", "mitre", "guide", "glossary", "note")


def ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS kb_docs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, kind TEXT, source TEXT, tags TEXT,
                 created_at TEXT, chars INTEGER, builtin TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS kb_chunks (id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id INTEGER, idx INTEGER, text TEXT)")
    c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(text, title, content='', tokenize='porter unicode61')")


def _chunks(text, size=800):
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    out, cur = [], ""
    for p in paras:
        if len(cur) + len(p) > size and cur:
            out.append(cur)
            cur = ""
        while len(p) > size * 1.5:
            out.append(p[:size])
            p = p[size:]
        cur = f"{cur}\n\n{p}" if cur else p
    if cur:
        out.append(cur)
    return out


def add(title, text, kind="note", source="", tags="", builtin=None):
    text = (text or "").strip()
    if not text:
        raise HTTPException(400, "The document is empty")
    with db.get_conn() as c:
        ensure(c)
        if builtin:
            for (old,) in c.execute("SELECT id FROM kb_docs WHERE builtin=?", (builtin,)).fetchall():
                _delete(c, old)
        did = c.execute("INSERT INTO kb_docs(title, kind, source, tags, created_at, chars, builtin) VALUES (?,?,?,?,?,?,?)",
                        (title[:200], kind if kind in KINDS else "note", source[:300], tags[:200], db.now_iso(), len(text), builtin)).lastrowid
        for i, ch in enumerate(_chunks(text)):
            cid = c.execute("INSERT INTO kb_chunks(doc_id, idx, text) VALUES (?,?,?)", (did, i, ch)).lastrowid
            c.execute("INSERT INTO kb_fts(rowid, text, title) VALUES (?,?,?)", (cid, ch, title))
    return did


def _delete(c, did):
    for (cid, txt, title) in c.execute("SELECT k.id, k.text, d.title FROM kb_chunks k JOIN kb_docs d ON d.id=k.doc_id WHERE k.doc_id=?", (did,)).fetchall():
        c.execute("INSERT INTO kb_fts(kb_fts, rowid, text, title) VALUES ('delete', ?, ?, ?)", (cid, txt, title))
    c.execute("DELETE FROM kb_chunks WHERE doc_id=?", (did,))
    c.execute("DELETE FROM kb_docs WHERE id=?", (did,))


def search(q, limit=5, kinds=None):
    words = [w for w in re.findall(r"[A-Za-z0-9]{3,}", q or "") if w.lower() not in STOP][:12]
    if not words:
        return []
    match = " OR ".join(f'"{w}"' for w in words)
    with db.get_conn() as c:
        ensure(c)
        rows = db.rows(c, f"""SELECT k.id chunk_id, k.doc_id, d.title, d.kind, d.source, k.text, bm25(kb_fts) score
                              FROM kb_fts JOIN kb_chunks k ON k.id=kb_fts.rowid JOIN kb_docs d ON d.id=k.doc_id
                              WHERE kb_fts MATCH ? {"AND d.kind IN (" + ",".join("?" * len(kinds)) + ")" if kinds else ""}
                              ORDER BY score LIMIT ?""", [match] + list(kinds or []) + [limit])
    for r in rows:
        r["snippet"] = _snippet(r["text"], words)
    return rows


STOP = {"the", "and", "for", "what", "which", "how", "our", "with", "this", "that", "are", "was", "does", "from", "have", "who", "when",
        "where", "why", "about", "show", "tell", "can", "you", "any", "all", "should", "into"}


def _snippet(text, words, width=260):
    low = text.lower()
    pos = min((low.find(w.lower()) for w in words if w.lower() in low), default=0)
    start = max(0, pos - 60)
    return ("…" if start else "") + text[start:start + width].strip() + ("…" if start + width < len(text) else "")


# ------------------------------------------------------------------ built-in documents
GLOSSARY = """Console glossary (how this console uses its words)

Internet exposed: an asset is internet exposed when there is evidence it can be reached from the internet — its own IP is public, an inventory Public / NAT IP column, the communication matrix NATs it or lets internet sources reach it, a VA scan saw it from outside, a passive (InternetDB) scan saw open ports, or someone marked it. Whitelisted and indirect (CGNAT) ranges are not counted.

EDR feasible: whether CrowdStrike can run on the node. Decided automatically from where agents already run and which OS any sensor supports, then by your marks (node type, OS, LOB, domain), the feasibility sheet and per-node decisions. "To be decided" means a node type with no agent yet.

Coverage gap: a node that is EDR feasible, live and in an LOB inventory but has no CrowdStrike agent.

Offline: an agent offline in the console, or a device that left the console (removed, auto-removed after N days offline, or only in an old EDR export). One row per device: duplicate agent IDs are merged.

Spotlight only: a vulnerability CrowdStrike Spotlight reports on a host that the VA scan does not report on the same IP.

Enterprise / non-enterprise: a mark on a public IP saying whether the address space is the organisation's own; it decides which public IPs in the matrix count as ours.

Connection IP: the IP CrowdStrike sees the agent connect from; the console uses it (not the local IP) as the agent's IP for matching and exposure.

Detection status: new, in_progress, closed (CrowdStrike Alerts). Unassigned means no analyst picked it up.

Sensor levels: N is the newest sensor release CrowdStrike tags, N-1 and N-2 the two before; older than N-2 is outdated."""

PLAYBOOK = """Detection triage playbook (template — adapt to your SOC)

1. Scope: which host, which user, which process. Check the asset: LOB and owner, internet exposure, criticality, open critical vulnerabilities, EDR state and prevention policy (detect-only policies do not block).

2. Verdict: true positive, benign true positive (expected admin activity), false positive. Use the detection history: the same detection on many hosts and always closed as benign points to a tuning need; a first-time detection on an exposed, vulnerable host needs escalation.

3. Severity and escalation: Critical or High on an internet-exposed or crown-jewel asset — escalate to L2 within 15 minutes and call the LOB owner. Ransomware behaviour, credential dumping (LSASS) or lateral movement — contain the host after L2 approval. Medium — investigate within 4 hours. Low / Informational — batch review daily.

4. Scope expansion: hunt the same hash, domain, IP and command line across all endpoints (NG-SIEM). Check other detections on the host in the last 7 days and logons by the same user.

5. Containment: network-contain the host from CrowdStrike only with approval; record who approved. Block hashes / domains as custom IOCs.

6. Close-out: record the verdict, root cause and actions in the case; if benign and recurring, propose an exclusion with justification and expiry."""

MITRE = """MITRE ATT&CK tactics (enterprise) — short reference

TA0001 Initial Access: getting in — phishing, exploiting public-facing applications (exposed web servers, VPNs), valid accounts, supply chain.
TA0002 Execution: running code — PowerShell, cmd, WMI, scheduled tasks, user execution of malicious files.
TA0003 Persistence: staying in — services, run keys, scheduled tasks, new accounts, web shells.
TA0004 Privilege Escalation: getting higher rights — exploiting vulnerabilities, token manipulation, sudo misuse.
TA0005 Defense Evasion: avoiding detection — disabling security tools, obfuscated (encoded) commands, masquerading, clearing logs.
TA0006 Credential Access: stealing credentials — LSASS memory dumping (mimikatz, procdump), brute force, password spraying, Kerberoasting.
TA0007 Discovery: learning the environment — account, network, system and share discovery (net, whoami, nltest, AdFind).
TA0008 Lateral Movement: moving between hosts — PsExec, remote services, RDP, SMB admin shares, WMI, pass-the-hash.
TA0009 Collection: gathering data — archiving files (7z, rar), screen capture, email collection.
TA0011 Command and Control: talking to the attacker — beacons over HTTPS / DNS, remote access tools (AnyDesk), proxies, Tor.
TA0010 Exfiltration: taking data out — rclone / MEGA, cloud storage, over C2, DNS tunnelling.
TA0040 Impact: damage — ransomware encryption (T1486), inhibit system recovery by deleting shadow copies (T1490), wiping, service stop.

Common techniques
T1059.001 PowerShell: look for -enc / -encodedcommand, IEX, DownloadString, bypass execution policy.
T1003.001 LSASS Memory: procdump or comsvcs.dll MiniDump against lsass.exe; mimikatz sekurlsa.
T1021.002 SMB / Admin shares and T1569.002 Service execution: PsExec style lateral movement (PSEXESVC service).
T1105 Ingress tool transfer: certutil -urlcache, bitsadmin, curl / wget downloading tools.
T1486 Data encrypted for impact: mass file renames / encryption; T1490 vssadmin delete shadows.
T1078 Valid accounts: logons from unusual hosts or at unusual times; service accounts logging on interactively.
T1190 Exploit public-facing application: exposed services with known exploited vulnerabilities (CISA KEV) are prime targets.
T1567.002 Exfiltration to cloud storage: rclone, MEGAsync, unusual uploads."""

BUILTINS = {"glossary": ("Console glossary", "glossary", GLOSSARY), "playbook": ("Detection triage playbook (template)", "playbook", PLAYBOOK),
            "mitre": ("MITRE ATT&CK quick reference", "mitre", MITRE)}


def _builtins():
    from . import cql
    return {**BUILTINS, **cql.kb_texts()}


def seed_builtins():
    """Built-in documents; a changed text (new console version) replaces the old copy."""
    import hashlib
    with db.get_conn() as c:
        ensure(c)
        have = {r[0] for r in c.execute("SELECT builtin FROM kb_docs WHERE builtin IS NOT NULL")}
    for key, (title, kind, text) in _builtins().items():
        tag = f"{key}#{hashlib.md5(text.encode()).hexdigest()[:8]}"
        if tag in have:
            continue
        with db.get_conn() as c:
            for (old,) in c.execute("SELECT id FROM kb_docs WHERE builtin=? OR builtin LIKE ?", (key, key + "#%")).fetchall():
                _delete(c, old)
        add(title, text, kind, "built-in", builtin=tag)


# ------------------------------------------------------------------ routes
@router.get("/api/kb/docs")
def kb_docs():
    seed_builtins()
    with db.get_conn() as c:
        rows = db.rows(c, "SELECT d.*, (SELECT COUNT(*) FROM kb_chunks k WHERE k.doc_id=d.id) chunks FROM kb_docs d ORDER BY d.builtin IS NOT NULL, d.id DESC")
    return {"rows": rows}


@router.get("/api/kb/docs/{doc_id}")
def kb_doc(doc_id: int):
    with db.get_conn() as c:
        d = db.one(c, "SELECT * FROM kb_docs WHERE id=?", (doc_id,))
        if not d:
            raise HTTPException(404, "Document not found")
        d["text"] = "\n\n".join(r[0] for r in c.execute("SELECT text FROM kb_chunks WHERE doc_id=? ORDER BY idx", (doc_id,)))
    return d


@router.post("/api/kb/docs")
def kb_add(data: dict = Body(...)):
    return {"id": add(str(data.get("title") or "Untitled"), str(data.get("text") or ""), str(data.get("kind") or "note"),
                      str(data.get("source") or "pasted"), str(data.get("tags") or ""))}


@router.post("/api/kb/upload")
async def kb_upload(file: UploadFile = File(...), kind: str = "sop"):
    raw = await file.read()
    name = file.filename or "upload"
    if not re.search(r"\.(txt|md|markdown|csv|html?|log|json)$", name, re.I):
        raise HTTPException(400, "Upload a .txt, .md, .csv, .html or .json file (paste other formats as text)")
    text = raw.decode("utf-8", "replace")
    if name.lower().endswith((".html", ".htm")):
        text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style).*?</\1>", " ", text, flags=re.S | re.I))
    return {"id": add(re.sub(r"\.\w+$", "", name), text, kind, f"upload: {name}")}


@router.delete("/api/kb/docs/{doc_id}")
def kb_delete(doc_id: int):
    with db.get_conn() as c:
        ensure(c)
        _delete(c, doc_id)
    return {"ok": True}


@router.get("/api/kb/search")
def kb_search(q: str, limit: int = 8):
    return {"rows": search(q, min(20, limit))}


@router.post("/api/kb/import-guides")
def kb_import_guides():
    """Import the Falcon MCP FQL / CQL guides (served by falcon-mcp) as knowledge-base documents."""
    from . import falconmcp
    falconmcp._ensure()
    from pydantic import AnyUrl
    res = falconmcp._run(lambda s: s.list_resources()).resources
    n = 0
    for r in res:
        if not re.search(r"guide|schema|example", str(r.uri)):
            continue
        txt = "".join(getattr(x, "text", "") or "" for x in falconmcp._run(lambda s, u=r.uri: s.read_resource(AnyUrl(str(u)))).contents)
        if txt.strip():
            add(f"Falcon guide: {r.name}", txt, "guide", str(r.uri), builtin=f"mcp:{r.uri}")
            n += 1
    return {"imported": n}
