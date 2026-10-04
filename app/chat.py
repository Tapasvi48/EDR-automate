"""AI SOC chat: saved conversations that hunt, explain, check IOCs and answer from the knowledge base.

Each message is routed (by rules first; the local model only fills hunts — see ai_hunt):
  ioc       a value + "check / malicious / reputation / ioc"        -> ioc.check_one (CrowdStrike intel, custom IOCs, our data)
  explain   "summarise / explain / triage / tell me about" + entity  -> briefs (detection, asset, CVE, IP, today's estate)
  knowledge "how do we / what is our / playbook / SOP / escalate"    -> knowledge base passages (+ a model answer from them)
  cql       endpoint-telemetry hunts ("hunt for lsass dumping", "write a CQL query for…", any question a library hunt answers)
                                                                     -> cql.generate (library / model query plan) + cql.run (NG-SIEM)
  hunt      anything else                                            -> ai_hunt (detections, hosts, vulnerabilities, intel, data fabric)
The session remembers the entities it talked about (host, IP, hash, domain, CVE, user, detection), so a follow-up such as
"now show its vulnerabilities" or "hunt that hash" works without repeating them. Every turn is stored with its result."""
import json
import re

from fastapi import APIRouter, Body, HTTPException

from . import ai_hunt, briefs, db, ioc, kb

router = APIRouter()
FOLLOW = re.compile(r"\b(it|its|it's|this|that|these|those|same|the host|the asset|the machine|the server|the ip|the hash|the domain|the user|them|there)\b", re.I)
EXPLAIN = re.compile(r"^\s*(summari[sz]e|explain|brief|triage|tell me about|what do we know|who is|what is going on|analy[sz]e|investigate)\b", re.I)
KNOW = re.compile(r"\b(how (do|should|can) (we|i)|what is our|what's our|playbook|sop|procedure|process for|escalat|who owns|policy for|runbook|what does .* mean|definition)\b", re.I)
IOCQ = re.compile(r"\b(check|ioc|malicious|reputation|known bad|is it bad|threat intel|intel on)\b", re.I)
PATHQ = re.compile(r"\bhow (?:is|are)\s+(.+?)\s+(?:connected|related|linked)\s+(?:to|with)\s+(.+)$", re.I)
CQLQ = re.compile(r"\b(cql|lql|logscale|ng-?siem|event search|hunting query|hunt query|write (?:a|me|the) (?:cql |hunt(?:ing)? )?query|"
                  r"query (?:for|to find)|hunt for|threat hunt|telemetry)\b", re.I)
NOT_CQL = re.compile(r"\b(detections?|alerts?|incidents?|vulnerab\w*|cves?|patch\w*|offline|stale|sensor version|contained|rfm|reduced functionality|"
                     r"actors?|adversary|custom iocs?|lob|exposed|exposure|riskiest|risk|owner|owns|timeline|posture|coverage|edr|spotlight)\b", re.I)
DET_ID = re.compile(r"\b(demo:[\w:.-]+|[a-f0-9]{32}:ind:[\w:-]+|ldt:[a-f0-9]{32}:\d+)\b", re.I)


def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS chat_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, created_at TEXT, updated_at TEXT,
                 pinned INTEGER DEFAULT 0, context TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, role TEXT, at TEXT, text TEXT,
                 kind TEXT, payload TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS ix_chat_msg ON chat_messages(session_id, id)")


def _session(c, sid):
    s = db.one(c, "SELECT * FROM chat_sessions WHERE id=?", (sid,))
    if not s:
        raise HTTPException(404, "Conversation not found")
    s["context"] = db.jloads(s["context"], {}) or {}
    return s


def _memory_text(ctx):
    order = ("detection", "host", "ip", "hash", "domain", "cve", "user")
    return ", ".join(f"{k} {ctx[k]}" for k in order if ctx.get(k))


def _remember(ctx, ents, result=None):
    for k in ("host", "ip", "hash", "domain", "cve"):
        if ents.get(k):
            ctx[k] = ents[k]
    if result:
        sl = result.get("slots") or {}
        for k in ("host", "ip", "hash", "domain", "cve", "user"):
            if sl.get(k):
                ctx[k] = sl[k]
        rows = result.get("rows") or []
        hosts = {r.get("device.hostname") or r.get("ComputerName") or r.get("hostname") or r.get("host_info.hostname") for r in rows} - {None, ""}
        if len(hosts) == 1:  # a hunt that points at one host makes it "the host"
            ctx["host"] = next(iter(hosts))
    return ctx


def route(text, ctx):
    """(kind, target, effective question)."""
    ents = ai_hunt.entities(text)
    follow = bool(FOLLOW.search(text)) and not any(ents.get(k) for k in ("host", "ip", "hash", "domain", "cve"))
    q = text
    if follow and _memory_text(ctx):
        q = f"{text} ({_memory_text(ctx)})"  # resolve "it / this host / that hash" from the conversation
        ents = ai_hunt.entities(q)
    m = PATHQ.search(text)
    if m:
        return "path", (m.group(1).strip(" ?"), m.group(2).strip(" ?")), q
    if re.search(r"\b(daily|today'?s|morning|shift|soc)\s+(brief|summary|report|status)\b|\bbrief me\b|\bwhat happened today\b", text, re.I):
        return "explain", ("overview", "today"), q
    m = DET_ID.search(text)
    value = ents.get("hash") or ents.get("ip") or ents.get("domain")
    if value and IOCQ.search(text) and not EXPLAIN.search(text):
        return "ioc", value, q
    if EXPLAIN.search(text) or (m and not IOCQ.search(text)):
        if m:
            return "explain", ("detection", m.group(1)), q
        if re.search(r"\b(today|estate|overall|daily|this morning|shift)\b", text, re.I) and not any(ents.get(k) for k in ("host", "ip", "cve")):
            return "explain", ("overview", "today"), q
        if follow and ctx.get("detection") and re.search(r"detection|alert", text, re.I):
            return "explain", ("detection", ctx["detection"]), q
        if ents.get("cve"):
            return "explain", ("cve", ents["cve"]), q
        if ents.get("host") or ents.get("ip"):
            return "explain", ("ip" if ents.get("ip") and not ents.get("host") else "asset", ents.get("host") or ents.get("ip")), q
        if follow and (ctx.get("host") or ctx.get("ip")):
            return "explain", ("asset", ctx.get("host") or ctx.get("ip")), q
        return "explain", ("overview", "today"), q
    if KNOW.search(text) and not value:
        return "knowledge", None, q
    if CQLQ.search(text):
        return "cql", None, q
    if not NOT_CQL.search(text):
        plan = ai_hunt.plan(q, use_model=False)
        if plan["tool"] == "falcon_search_ngsiem":
            return "cql", None, q
        from . import cql
        best = next(iter(cql.retrieve(q, 1)), None)
        if best and best["score"] >= 12 and best.get("coverage", 0) >= 0.66:
            return "cql", None, q
    return "hunt", None, q


def answer_path(a, b):
    """How two entities are connected in the data fabric (ontology graph)."""
    from . import ontology

    def pick(text):
        text = re.sub(r"^(the |asset |host |user |lob |cve |ip )", "", text.strip(), flags=re.I)
        r = ontology.fabric_search(text, 3)["rows"]
        exact = [x for x in r if x["label"].lower() == text.lower() or x["id"].split(":", 1)[1].lower() == text.lower()]
        return (exact or r or [None])[0]
    na, nb = pick(a), pick(b)
    if not na or not nb:
        return {"found": False, "error": f"Could not find {a if not na else b} in the data fabric", "a": na, "b": nb}
    p = ontology.fabric_path(na["id"], nb["id"])
    labels = {}
    for nid in p.get("path") or []:
        try:
            labels[nid] = ontology.node(nid)["node"]["label"]
        except HTTPException:
            labels[nid] = nid
    return {**p, "a": na, "b": nb, "labels": labels}


def answer_cql(question):
    """Generate a CQL hunt (library / model plan), run it, and keep both."""
    from . import cql
    g = cql.generate(re.sub(r"^\s*(please\s+)?(write|give|make|create|generate)\s+(me\s+)?(a|the)?\s*(cql\s+)?(hunt(ing)?\s+)?(query|search)\s+(for|to find|that finds)\s+", "", question, flags=re.I))
    r = cql.run(g["cql"], g["days"], question)
    hosts = sorted({x.get("ComputerName") for x in r["rows"] if x.get("ComputerName")})
    facts = [f"{r['total']:,} result{'s' if r['total'] != 1 else ''} in the last {g['days']} days"]
    if hosts:
        facts.append(f"{len(hosts)} host{'s' if len(hosts) != 1 else ''}: " + ", ".join(hosts[:5]) + (" …" if len(hosts) > 5 else ""))
    return {**g, "result": {k: r[k] for k in ("ok", "error", "rows", "total", "columns", "seconds", "via", "meta", "run_id")}, "facts": facts}


def answer_knowledge(question):
    hits = kb.search(question, 4)
    out = {"passages": [{"title": h["title"], "kind": h["kind"], "snippet": h["snippet"], "doc_id": h["doc_id"]} for h in hits], "answer": None}
    if not hits:
        out["answer"] = "Nothing in the knowledge base matches. Add your SOP / playbook under Knowledge base."
        return out
    try:
        from .ai_hunt import _llm, ai_settings
        if ai_settings()["provider"] != "off":
            ctx = "\n\n".join(f"[{i + 1}] {h['title']}:\n{h['text'][:900]}" for i, h in enumerate(hits))
            txt = _llm([{"role": "system", "content": "Answer the SOC analyst's question using ONLY the numbered passages; cite them like [1]. "
                                                      "If they do not answer it, say so. 2-5 sentences."},
                        {"role": "user", "content": f"Question: {question}\n\nPassages:\n{ctx}"}], None, 260, timeout=90)
            out["answer"] = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip()
    except Exception as e:  # noqa: BLE001 - passages only
        out["model_error"] = str(e)[:160]
    return out


def respond(sid, text):
    text = (text or "").strip()[:800]
    if not text:
        raise HTTPException(400, "Type a question")
    from . import learn
    with db.get_conn() as c:
        _ensure(c)
        s = _session(c, sid)
        prev_q = c.execute("SELECT text FROM chat_messages WHERE session_id=? AND role='user' ORDER BY id DESC LIMIT 1", (sid,)).fetchone()
        prev_a = db.one(c, "SELECT kind, text FROM chat_messages WHERE session_id=? AND role='assistant' ORDER BY id DESC LIMIT 1", (sid,))
        c.execute("INSERT INTO chat_messages(session_id, role, at, text, kind) VALUES (?,?,?,?,?)", (sid, "user", db.now_iso(), text, "question"))
    ctx = s["context"]
    if learn.REMEMBER.search(text) and not text.rstrip().endswith("?"):  # a standing preference, not a question
        flag = learn.add_pref(text)
        summary = f"Noted. I'll remember: “{text.strip()}”" + (" (applied to detection lists and counts)" if flag else "")
        with db.get_conn() as c:
            mid = c.execute("INSERT INTO chat_messages(session_id, role, at, text, kind, payload) VALUES (?,?,?,?,?,?)",
                            (sid, "assistant", db.now_iso(), summary, "learned", json.dumps({"pref": text, "flag": flag}))).lastrowid
            c.execute("UPDATE chat_sessions SET updated_at=? WHERE id=?", (db.now_iso(), sid))
        return {"id": mid, "role": "assistant", "kind": "learned", "text": summary, "payload": {"pref": text, "flag": flag}, "context": ctx}
    asked, correction, applied = text, None, None
    if prev_q and prev_a and learn.CORRECTION.search(text):  # "no, I want …": answer the corrected question and learn from it
        asked = learn.corrected_question(text, prev_q[0])
        correction = (prev_q[0], prev_a["kind"], prev_a["text"])
    else:
        lesson = learn.lesson_for(text)
        if lesson and lesson["right_question"].strip().lower() != text.strip().lower():
            asked, applied = lesson["right_question"], lesson
    kind, target, q = route(asked, ctx)
    if kind == "ioc":
        r = ioc.check_one(target)
        payload, summary = r, f"{r['value']}: {r['verdict']} — {'; '.join(r.get('why') or [])}"
        _remember(ctx, ai_hunt.entities(target))
    elif kind == "explain":
        k, ident = target
        r = briefs.brief(k, ident)
        if k == "detection":
            ctx["detection"] = ident
        elif k in ("asset", "ip"):
            ctx["host" if k == "asset" else "ip"] = ident
        elif k == "cve":
            ctx["cve"] = ident
        payload, summary = r, f"{r['title']}: {r['level']}"
    elif kind == "path":
        payload = answer_path(*target)
        if payload.get("found"):
            lb = payload["labels"]
            summary = " → ".join(f"{lb.get(h['from'], h['from'])} ({h['rel']})" for h in payload["hops"]) + f" → {lb.get(payload['path'][-1])}"
        else:
            summary = payload.get("error") or "No connection found within 6 hops"
    elif kind == "cql":
        payload = answer_cql(q)
        res = payload["result"]
        ctx = _remember(ctx, payload.get("entities") or {}, {"rows": res["rows"]})
        payload = {k: v for k, v in payload.items() if k != "entities"}
        summary = (f"{payload.get('title') or 'CQL hunt'}: {res['total']} results" if res["ok"] else f"CQL hunt: {res['error']}")
    elif kind == "knowledge":
        payload = answer_knowledge(q)
        summary = payload.get("answer") or f"{len(payload['passages'])} passages"
    else:
        payload = ai_hunt.ask(q, summarize_it=False, use_model="auto")
        ctx = _remember(ctx, payload.get("entities") or {}, payload)
        summary = f"{payload.get('title')}: {payload.get('total', 0)} results" if payload.get("ok") else (payload.get("error") or "needs more input")
        payload = {k: v for k, v in payload.items() if k != "entities"}
    if correction and isinstance(payload, dict):
        lid = learn.add_lesson(correction[0], correction[1], correction[2], asked, kind, text)
        payload["learned"] = {"id": lid, "question": correction[0], "right_question": asked}
    if applied and isinstance(payload, dict):
        payload["applied_lesson"] = {"id": applied["id"], "question": applied["question"], "right_question": applied["right_question"], "note": applied["note"]}
    with db.get_conn() as c:
        mid = c.execute("INSERT INTO chat_messages(session_id, role, at, text, kind, payload) VALUES (?,?,?,?,?,?)",
                        (sid, "assistant", db.now_iso(), summary[:1000], kind, json.dumps(payload, default=str)[:600_000])).lastrowid
        title = s["title"] if s["title"] and s["title"] != "New conversation" else text[:60]
        c.execute("UPDATE chat_sessions SET updated_at=?, context=?, title=? WHERE id=?", (db.now_iso(), json.dumps(ctx), title, sid))
    return {"id": mid, "role": "assistant", "kind": kind, "text": summary, "payload": payload, "context": ctx, "effective_question": q if q != text else None}


# ------------------------------------------------------------------ routes
@router.get("/api/chat/sessions")
def sessions(q: str = ""):
    with db.get_conn() as c:
        _ensure(c)
        rows = db.rows(c, """SELECT s.id, s.title, s.created_at, s.updated_at, s.pinned, (SELECT COUNT(*) FROM chat_messages m WHERE m.session_id=s.id) messages
                             FROM chat_sessions s WHERE ? = '' OR s.title LIKE ? OR EXISTS (SELECT 1 FROM chat_messages m WHERE m.session_id=s.id AND m.text LIKE ?)
                             ORDER BY s.pinned DESC, s.updated_at DESC LIMIT 200""", (q, f"%{q}%", f"%{q}%"))
    return {"rows": rows}


@router.post("/api/chat/sessions")
def new_session(data: dict = Body(default={})):
    with db.get_conn() as c:
        _ensure(c)
        ctx = data.get("context") or {}
        sid = c.execute("INSERT INTO chat_sessions(title, created_at, updated_at, context) VALUES (?,?,?,?)",
                        (data.get("title") or "New conversation", db.now_iso(), db.now_iso(), json.dumps(ctx))).lastrowid
    return {"id": sid}


@router.get("/api/chat/sessions/{sid}")
def get_session(sid: int):
    with db.get_conn() as c:
        _ensure(c)
        s = _session(c, sid)
        msgs = db.rows(c, "SELECT id, role, at, text, kind, payload FROM chat_messages WHERE session_id=? ORDER BY id", (sid,))
    for m in msgs:
        m["payload"] = db.jloads(m["payload"], None)
    return {**s, "messages": msgs}


@router.patch("/api/chat/sessions/{sid}")
def patch_session(sid: int, data: dict = Body(...)):
    with db.get_conn() as c:
        _ensure(c)
        _session(c, sid)
        if "title" in data:
            c.execute("UPDATE chat_sessions SET title=? WHERE id=?", (str(data["title"])[:120], sid))
        if "pinned" in data:
            c.execute("UPDATE chat_sessions SET pinned=? WHERE id=?", (1 if data["pinned"] else 0, sid))
    return {"ok": True}


@router.delete("/api/chat/sessions/{sid}")
def delete_session(sid: int):
    with db.get_conn() as c:
        _ensure(c)
        c.execute("DELETE FROM chat_messages WHERE session_id=?", (sid,))
        c.execute("DELETE FROM chat_sessions WHERE id=?", (sid,))
    return {"ok": True}


@router.post("/api/chat/sessions/{sid}/message")
def message(sid: int, data: dict = Body(...)):
    return respond(sid, data.get("text"))


@router.post("/api/chat/sessions/{sid}/attach")
def attach(sid: int, data: dict = Body(...)):
    """Put a brief / IOC result / hunt that was opened elsewhere into the conversation (e.g. "Continue in chat")."""
    with db.get_conn() as c:
        _ensure(c)
        s = _session(c, sid)
        kind, payload = data.get("kind") or "explain", data.get("payload") or {}
        c.execute("INSERT INTO chat_messages(session_id, role, at, text, kind, payload) VALUES (?,?,?,?,?,?)",
                  (sid, "assistant", db.now_iso(), str(data.get("text") or payload.get("title") or "")[:1000], kind, json.dumps(payload, default=str)))
        ctx = s["context"]
        for k in ("detection", "host", "ip", "cve", "hash", "domain"):
            if (data.get("context") or {}).get(k):
                ctx[k] = data["context"][k]
        c.execute("UPDATE chat_sessions SET updated_at=?, context=?, title=CASE WHEN title='New conversation' THEN ? ELSE title END WHERE id=?",
                  (db.now_iso(), json.dumps(ctx), str(data.get("text") or "Investigation")[:60], sid))
    return {"ok": True}
