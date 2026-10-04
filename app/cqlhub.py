"""CQL Hub (ByteRay, https://www.byteray.com/cql-hub): an open, community-maintained library of CrowdStrike Next-Gen SIEM /
LogScale hunting and detection queries (MIT licence, source: github.com/ByteRay-Labs/Query-Hub).

Imported on request (AI SOC → Hunt studio → Import CQL Hub, or Knowledge → Import): one download of the repository archive,
each query's YAML (name, description, MITRE IDs, tags, log sources, required modules, author, CQL) stored in cql_hub. Nothing
is bundled with the console. The queries then:
  * appear in the Hunt studio library (with author and a link back to the CQL Hub),
  * are retrieved as reference examples when the AI writes a hunt (and as alternatives next to the generated query),
  * are searchable in the knowledge base (one document, attributed), so the assistant can quote them.
Re-importing replaces the previous copy."""
import io
import re
import tarfile

import requests
import yaml
from fastapi import APIRouter, HTTPException

from . import db

router = APIRouter()
ARCHIVE = "https://codeload.github.com/ByteRay-Labs/Query-Hub/tar.gz/refs/heads/main"
SITE = "https://www.byteray.com/cql-hub"
REPO = "https://github.com/ByteRay-Labs/Query-Hub"


def _ensure(c):
    c.execute("""CREATE TABLE IF NOT EXISTS cql_hub (id TEXT PRIMARY KEY, name TEXT, description TEXT, cql TEXT, mitre TEXT, tags TEXT,
                 log_sources TEXT, modules TEXT, author TEXT, file TEXT, imported_at TEXT)""")


def _list(v):
    if not v:
        return []
    return [str(x).strip() for x in (v if isinstance(v, list) else re.split(r"[,\s]+", str(v))) if str(x).strip()]


def import_hub(timeout=60):
    try:
        r = requests.get(ARCHIVE, timeout=timeout)
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Could not download the CQL Hub from GitHub: {str(e)[:200]}") from e
    rows = []
    with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
        for m in tar.getmembers():
            if not m.isfile() or "/queries/" not in m.name or not m.name.endswith((".yml", ".yaml")):
                continue
            try:
                d = yaml.safe_load(tar.extractfile(m).read().decode("utf-8", "replace")) or {}
            except yaml.YAMLError:
                continue
            cql = str(d.get("cql") or "").strip()
            if not cql or not d.get("name"):
                continue
            fid = m.name.rsplit("/", 1)[1].rsplit(".", 1)[0]
            rows.append((fid, str(d["name"])[:200], str(d.get("description") or "").strip()[:4000], cql[:20000],
                         ", ".join(_list(d.get("mitre_ids"))), ", ".join(_list(d.get("tags"))), ", ".join(_list(d.get("log_sources"))),
                         ", ".join(_list(d.get("cs_required_modules"))), str(d.get("author") or "")[:120], m.name.split("/", 1)[1], db.now_iso()))
    if not rows:
        raise HTTPException(502, "The CQL Hub archive had no queries")
    with db.get_conn() as c:
        _ensure(c)
        c.execute("DELETE FROM cql_hub")
        c.executemany("INSERT OR REPLACE INTO cql_hub VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    _to_kb(rows)
    from . import cql
    cql.extend_functions()
    return {"imported": len(rows), "source": SITE}


def _to_kb(rows):
    from . import kb
    text = (f"CQL Hub by ByteRay — open community library of CrowdStrike Next-Gen SIEM / LogScale queries ({SITE}, MIT licence, "
            f"source {REPO}). {len(rows)} queries imported; each lists its MITRE techniques, log sources and author.\n\n" +
            "\n\n".join(f"{r[1]} — {r[2][:600]}\nMITRE: {r[4] or '-'} · type: {r[5] or '-'} · log source: {r[6] or '-'} · author: {r[8] or '-'}\n{r[3][:1500]}"
                        for r in rows))
    kb.add("CQL Hub — community hunting & detection queries (ByteRay, MIT)", text, "guide", SITE, builtin="cqlhub")


def rows(q=""):
    with db.get_conn() as c:
        _ensure(c)
        if q:
            like = f"%{q}%"
            return db.rows(c, """SELECT * FROM cql_hub WHERE name LIKE ? OR description LIKE ? OR mitre LIKE ? OR tags LIKE ? OR log_sources LIKE ?
                                 ORDER BY name""", (like, like, like, like, like))
        return db.rows(c, "SELECT * FROM cql_hub ORDER BY name")


@router.post("/api/cql/hub/import")
def hub_import():
    return import_hub()


@router.get("/api/cql/hub")
def hub_list(q: str = ""):
    rs = rows(q.strip())
    with db.get_conn() as c:
        _ensure(c)
        at = c.execute("SELECT MAX(imported_at) FROM cql_hub").fetchone()[0]
    return {"rows": rs, "imported_at": at, "site": SITE, "repo": REPO, "licence": "MIT"}
