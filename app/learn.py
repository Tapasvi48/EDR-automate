"""What the AI SOC learns from its analysts, so it does not repeat a mistake.

  lessons       a correction in chat ("no, I want all exposed hosts, not only the ones without EDR") is answered right away and
                stored as: the original question -> the corrected question. The next time a similar question is asked (same
                words, Jaccard >= 0.6 after dropping filler words) the corrected question is answered instead, and the answer
                says so. Every lesson can be removed (Settings → AI model → What the AI learned).
  preferences   "remember …", "always …", "never …", "from now on …" are stored as standing preferences. Known ones change
                behaviour directly (e.g. include / leave out informational detections); every preference is also passed to
                the local model with each request.
Nothing here leaves the machine; lessons and preferences live in the console database."""
import re

from fastapi import APIRouter

from . import db

router = APIRouter()
CORRECTION = re.compile(r"^\s*(no\b|nope\b|wrong\b|not (this|that|what i)|that'?s not|this is not|this isn'?t|i (want|wanted|meant|asked for|said|need)\b|"
                        r"instead\b|rather\b|actually\b|you (showed|gave)|i didn'?t (ask|want))", re.I)
REMEMBER = re.compile(r"^\s*(please\s+)?(remember|always|never|from now on|going forward|in (the )?future|next time|don'?t ever|do not ever|keep in mind)\b", re.I)
STOP = {"the", "and", "for", "with", "show", "me", "list", "give", "all", "any", "please", "which", "what", "are", "is", "of", "in", "on", "to", "a", "an",
        "that", "this", "those", "these", "can", "you", "i", "my", "our", "us", "get", "find", "tell", "about", "how", "many", "do", "we", "have", "there"}
FLAGS = [("include_informational", re.compile(r"(show|include|keep|want).{0,30}informational|informational.{0,20}(too|also|as well)", re.I)),
         ("exclude_informational", re.compile(r"(no|never|without|exclude|hide|don'?t (show|include)).{0,30}informational", re.I))]


def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS ai_lessons (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, question TEXT, wrong_kind TEXT, wrong_summary TEXT,
                 right_question TEXT, right_kind TEXT, note TEXT, uses INTEGER DEFAULT 0, last_used TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS ai_prefs (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, text TEXT, flag TEXT)")


def words(q):
    return {w for w in re.findall(r"[a-z0-9][a-z0-9._-]*", (q or "").lower()) if w not in STOP and len(w) > 1}


def similar(a, b):
    wa, wb = words(a), words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def corrected_question(text, previous):
    """The question a correction really asks. 'no, I want all exposed hosts not only without edr' -> 'all exposed hosts'."""
    t = CORRECTION.sub("", text, count=1).strip(" ,.:;!-")
    for _ in range(4):  # peel "what I asked, I want to see …"
        t2 = re.sub(r"^(what\s+i\s+(asked|meant|wanted|said)( for)?|(i\s+)?(want|wanted|meant|need|asked for|said)|to see|to get|it to show|"
                    r"you to show|is|was|the)\b[\s,.:;-]*", "", t, flags=re.I).strip()
        if t2 == t:
            break
        t = t2
    # drop the part that says what it should NOT be ("not only the ones without EDR", "instead of …")
    t = re.sub(r"[,;]?\s*\b(not (only|just)|instead of|rather than|but not|and not|not the ones?)\b.*$", "", t, flags=re.I).strip(" ,.")
    refine = re.match(r"(include|also|add|plus|only|just|with|without|for|in|and|but|show|exclude)\b", t, re.I) and not re.search(
        r"\b(hosts?|assets?|detections?|alerts?|vulnerabilit\w*|cves?|users?|ips?|servers?)\b", t, re.I)
    if previous and (not words(t) or refine):  # a refinement ("include informational too"): apply it to the previous question
        t = f"{previous} {t}".strip()
    return t or previous


def lesson_for(question):
    with db.get_conn() as c:
        _ensure(c)
        rows = db.rows(c, "SELECT * FROM ai_lessons ORDER BY id DESC LIMIT 500")
    best, score = None, 0.0
    for r in rows:
        s = similar(question, r["question"])
        if s > score:
            best, score = r, s
    if best and score >= 0.6:
        with db.get_conn() as c:
            c.execute("UPDATE ai_lessons SET uses=uses+1, last_used=? WHERE id=?", (db.now_iso(), best["id"]))
        return {**best, "similarity": round(score, 2)}
    return None


def add_lesson(question, wrong_kind, wrong_summary, right_question, right_kind, note):
    with db.get_conn() as c:
        _ensure(c)
        for r in db.rows(c, "SELECT id, question FROM ai_lessons"):  # one lesson per question: the newest correction wins
            if similar(r["question"], question) >= 0.9:
                c.execute("DELETE FROM ai_lessons WHERE id=?", (r["id"],))
        return c.execute("""INSERT INTO ai_lessons(at, question, wrong_kind, wrong_summary, right_question, right_kind, note) VALUES (?,?,?,?,?,?,?)""",
                         (db.now_iso(), question[:500], wrong_kind, (wrong_summary or "")[:300], right_question[:500], right_kind, note[:500])).lastrowid


def add_pref(text):
    flag = next((f for f, rx in FLAGS if rx.search(text)), None)
    with db.get_conn() as c:
        _ensure(c)
        if flag in ("include_informational", "exclude_informational"):
            c.execute("DELETE FROM ai_prefs WHERE flag IN ('include_informational','exclude_informational')")
        c.execute("INSERT INTO ai_prefs(at, text, flag) VALUES (?,?,?)", (db.now_iso(), text.strip()[:400], flag))
    return flag


def pref_flag(name):
    try:
        with db.get_conn() as c:
            _ensure(c)
            return bool(c.execute("SELECT 1 FROM ai_prefs WHERE flag=?", (name,)).fetchone())
    except Exception:  # noqa: BLE001
        return False


def prefs_text():
    try:
        with db.get_conn() as c:
            _ensure(c)
            return [r[0] for r in c.execute("SELECT text FROM ai_prefs ORDER BY id")]
    except Exception:  # noqa: BLE001
        return []


@router.get("/api/ai/learned")
def learned():
    with db.get_conn() as c:
        _ensure(c)
        return {"lessons": db.rows(c, "SELECT * FROM ai_lessons ORDER BY id DESC"), "prefs": db.rows(c, "SELECT * FROM ai_prefs ORDER BY id DESC")}


@router.delete("/api/ai/learned/{kind}/{item_id}")
def forget(kind: str, item_id: int):
    with db.get_conn() as c:
        _ensure(c)
        c.execute(f"DELETE FROM {'ai_lessons' if kind == 'lesson' else 'ai_prefs'} WHERE id=?", (item_id,))
    return {"ok": True}
