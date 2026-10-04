"""CrowdStrike Falcon MCP connector (the official server: https://developer.crowdstrike.com/falcon-mcp/).

The console runs falcon-mcp itself ("managed": a local process on 127.0.0.1, streamable HTTP, protected by a random API key,
started with the CrowdStrike API client saved under Sync & settings) or connects to one you run ("external": URL + API key).
Every tool the server offers — hosts, detections, Spotlight, NG-SIEM CQL, intel, IOCs, RTR audit, cases, cloud, identity… —
is listed with its input schema, can be run from the Falcon MCP page, and every call is recorded (who / what / when / result).

Safety: the managed server starts read-only (`--read-only`: tools that change the tenant are not even registered). Write tools
appear only when "Allow write tools" is switched on, and each write call still needs an explicit confirmation. Secrets
(client secret, API keys) never reach the browser. In sample-data mode the real falcon-mcp server runs against the sample
database (app.mcp_sample_server)."""
import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request

from . import config, db

router = APIRouter()
SETTING_KEYS = ("mcp_mode", "mcp_url", "mcp_api_key", "mcp_modules", "mcp_read_only", "mcp_port")
STATE = {"proc": None, "url": None, "key": None, "started_at": None, "error": None, "cfg": None, "tools": None, "info": None}
LOG = deque(maxlen=200)
_lock = threading.Lock()
WRITE_WORDS = ("create", "update", "delete", "remove", "contain", "release", "hide", "unhide", "add_", "assign", "enable", "disable",
               "set_", "suppress", "run_", "execute_rtr", "attach", "tag_", "apply_")


def _cfg():
    s = db.get_settings()
    return {"mode": s.get("mcp_mode") or "managed", "url": (s.get("mcp_url") or "").strip(), "api_key": s.get("mcp_api_key") or "",
            "modules": [m for m in (s.get("mcp_modules") or "").split(",") if m], "read_only": (s.get("mcp_read_only") or "1") != "0",
            "port": int(s.get("mcp_port") or 8781)}


def _free(port):
    with socket.socket() as so:
        return so.connect_ex(("127.0.0.1", port)) != 0


def _log_reader(proc, secret_values):
    for line in iter(proc.stdout.readline, b""):
        text = line.decode("utf-8", "replace").rstrip()
        for v in secret_values:
            if v:
                text = text.replace(v, "•••")
        if "Processing request of type" in text or '"POST /mcp' in text or '"DELETE /mcp' in text or '"GET /mcp' in text:
            continue  # per-request noise
        LOG.append(text[:500])


def start():
    """Start the managed falcon-mcp process (no-op when it already runs with the same settings)."""
    cfg = _cfg()
    if cfg["mode"] == "external":
        if not cfg["url"]:
            raise HTTPException(400, "Enter the URL of your falcon-mcp server (…/mcp)")
        STATE.update(url=cfg["url"], key=cfg["api_key"], cfg=cfg, error=None, tools=None)
        return status()
    if cfg["mode"] == "off":
        raise HTTPException(400, "The Falcon MCP connector is switched off")
    with _lock:
        p = STATE["proc"]
        if p and p.poll() is None and STATE["cfg"] == cfg:
            return status()
        _stop_locked()
        from .falcon import credentials
        cr = credentials()
        cid, secret, base, member = cr["client_id"], cr["client_secret"], cr["base_url"], cr["member_cid"]
        if not config.DEMO and not (cid and secret):
            raise HTTPException(400, "Add the CrowdStrike API client under Sync & settings first: falcon-mcp uses the same credentials")
        port = cfg["port"]
        while not _free(port):
            port += 1
        key = secrets.token_urlsafe(24)
        env = {**os.environ, "FALCON_CLIENT_ID": cid or "sample", "FALCON_CLIENT_SECRET": secret or "sample",
               "FALCON_BASE_URL": _base_url(base), "FALCON_MCP_API_KEY": key, "PYTHONUNBUFFERED": "1"}
        if member:
            env["FALCON_MEMBER_CID"] = member
        if config.DEMO:
            env["DEMO"] = "1"
            cmd = [sys.executable, "-m", "app.mcp_sample_server"]
        else:
            exe = Path(sys.executable).with_name("falcon-mcp")
            cmd = [str(exe)] if exe.exists() else [sys.executable, "-m", "falcon_mcp.server"]
        cmd += ["-t", "streamable-http", "--host", "127.0.0.1", "--port", str(port)]
        if cfg["read_only"]:
            cmd.append("--read-only")
        if cfg["modules"]:
            cmd += ["--modules", ",".join(cfg["modules"])]
        LOG.clear()
        LOG.append(f"$ falcon-mcp -t streamable-http --port {port}{' --read-only' if cfg['read_only'] else ''}"
                   + (f" --modules {','.join(cfg['modules'])}" if cfg["modules"] else "") + (" (sample data)" if config.DEMO else ""))
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(config.BASE_DIR))
        threading.Thread(target=_log_reader, args=(proc, [secret, key]), daemon=True).start()
        STATE.update(proc=proc, url=f"http://127.0.0.1:{port}/mcp", key=key, started_at=db.now_iso(), error=None, cfg=cfg, tools=None, info=None)
    # wait until it listens (it authenticates with CrowdStrike first), then load the tool list
    for _ in range(120):
        if proc.poll() is not None:
            STATE["error"] = _last_error() or "falcon-mcp stopped while starting"
            raise HTTPException(400, STATE["error"])
        if not _free(port):
            try:
                _run(_list_tools, timeout=20)
                return status()
            except Exception as e:  # noqa: BLE001
                STATE["error"] = f"falcon-mcp is up but did not answer: {e}"
                raise HTTPException(502, STATE["error"])
        time.sleep(0.25)
    STATE["error"] = "falcon-mcp did not answer within 30 s"
    raise HTTPException(504, STATE["error"])


def _base_url(base):
    base = (base or "us-1").strip()
    if base.startswith("http"):
        return base
    return {"us-1": "https://api.crowdstrike.com", "us-2": "https://api.us-2.crowdstrike.com", "eu-1": "https://api.eu-1.crowdstrike.com",
            "us-gov-1": "https://api.laggar.gcw.crowdstrike.com", "us-gov-2": "https://api.us-gov-2.crowdstrike.mil"}.get(base.lower(), "https://api.crowdstrike.com")


def _last_error():
    for line in reversed(LOG):
        if "ERROR" in line or "Error" in line or "error" in line:
            return line.split(" - ")[-1][:400]
    return None


def _stop_locked():
    if _conn is not None:
        _conn.close()
    p = STATE["proc"]
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
    STATE.update(proc=None, tools=None, info=None)


def stop():
    with _lock:
        _stop_locked()
        STATE.update(url=None, key=None, cfg=None)


def _running():
    if STATE["cfg"] and STATE["cfg"]["mode"] == "external":
        return bool(STATE["url"])
    p = STATE["proc"]
    return bool(p and p.poll() is None)


# ------------------------------------------------------------------ MCP client calls
class _Conn:
    """One long-lived MCP session on a background event loop. Opening a session per request costs a handshake and the
    client's 30 s wait for the event stream to close; one shared session answers in milliseconds. Reconnects on failure."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True, name="falcon-mcp-client").start()
        self.session, self.closing, self.target = None, None, None

    async def _holder(self, url, key, ready):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        self.closing = asyncio.Event()
        try:
            async with streamablehttp_client(url, headers={"x-api-key": key} if key else {}, timeout=15, sse_read_timeout=900) as (r, w, _):
                async with ClientSession(r, w) as sess:
                    init = await sess.initialize()
                    STATE["info"] = {"name": init.serverInfo.name, "version": init.serverInfo.version}
                    self.session = sess
                    ready.set_result(True)
                    await self.closing.wait()
        except BaseException as e:  # noqa: BLE001
            if not ready.done():
                ready.set_exception(e if isinstance(e, Exception) else RuntimeError(str(e)))
        finally:
            self.session = None

    async def _open(self):
        if self.session is not None and self.target == (STATE["url"], STATE["key"]):
            return
        await self._close()
        self.target = (STATE["url"], STATE["key"])
        ready = self.loop.create_future()
        self.loop.create_task(self._holder(STATE["url"], STATE["key"], ready))
        await asyncio.wait_for(ready, 20)

    async def _close(self):
        if self.closing is not None:
            self.closing.set()  # the holder task leaves its contexts in its own task
        self.session, self.target = None, None

    async def _do(self, fn):
        await self._open()
        try:
            return await fn(self.session)
        except Exception:  # noqa: BLE001 - the server may have restarted: reconnect once
            await self._close()
            await self._open()
            return await fn(self.session)

    def run(self, fn, timeout):
        return asyncio.run_coroutine_threadsafe(self._do(fn), self.loop).result(timeout)

    def close(self):
        asyncio.run_coroutine_threadsafe(self._close(), self.loop)


_conn = None


def _run(fn, timeout=180):
    global _conn
    if _conn is None:
        _conn = _Conn()
    return _conn.run(fn, timeout)


async def _list_tools(s):
    tools = (await s.list_tools()).tools
    STATE["tools"] = [_tool(t) for t in tools]
    return STATE["tools"]


def _tool(t):
    ann = t.annotations
    read_only = bool(ann.readOnlyHint) if ann and ann.readOnlyHint is not None else not any(w in t.name for w in WRITE_WORDS)
    return {"name": t.name, "title": (t.name.replace("falcon_", "").replace("_", " ")).capitalize(), "description": t.description or "",
            "summary": (t.description or "").strip().split("\n")[0][:200], "schema": t.inputSchema or {}, "module": _module(t.name),
            "read_only": read_only, "destructive": bool(ann.destructiveHint) if ann and ann.destructiveHint is not None else not read_only}


_MODMAP = {}


def _module(name):
    if not _MODMAP:
        try:
            from falcon_mcp import registry
            _MODMAP.update(registry.get_tool_module_map())  # builds every module once: cached for the process
        except Exception:  # noqa: BLE001
            _MODMAP["_"] = ""
    m = _MODMAP.get(name)
    if m:
        return m
    return "core" if name in ("falcon_check_connectivity", "falcon_list_enabled_modules", "falcon_list_enabled_tools") else "other"


def _ensure():
    if not _running():
        start()


def tools(refresh=False):
    _ensure()
    if refresh or not STATE["tools"]:
        _run(_list_tools)
    return STATE["tools"]


def call(tool, arguments, user="", confirm=False):
    """Run one tool; refused for write tools unless allowed + confirmed. Recorded in mcp_runs."""
    meta = next((t for t in tools() if t["name"] == tool), None)
    if not meta:
        raise HTTPException(404, f"{tool} is not offered by the server (module off, or read-only mode)")
    if not meta["read_only"] and not confirm:
        raise HTTPException(409, f"{tool} changes your CrowdStrike tenant: confirm to run it")
    args = {k: v for k, v in (arguments or {}).items() if v not in (None, "", [])}
    t0 = time.time()
    ok, text, err = True, "", None
    try:
        res = _run(lambda s: s.call_tool(tool, args))
        text = "".join(getattr(c, "text", "") or "" for c in res.content)
        if res.isError:
            ok, err = False, text[:2000]
    except Exception as e:  # noqa: BLE001
        ok, err = False, str(e)[:2000]
    secs = round(time.time() - t0, 2)
    parsed = None
    if text:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    with db.get_conn() as c:
        rid = c.execute("""INSERT INTO mcp_runs(at, tool, args, ok, error, seconds, result, size, user, read_only)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""", (db.now_iso(), tool, json.dumps(args), 1 if ok else 0, err, secs,
                                                             text[:400_000], len(text), user, 1 if meta["read_only"] else 0)).lastrowid
    return {"id": rid, "ok": ok, "error": err, "seconds": secs, "text": text if parsed is None else None, "data": parsed,
            "size": len(text), "tool": tool, "args": args}


def status():
    cfg = STATE["cfg"] or _cfg()
    n = None
    if STATE["tools"] is not None:
        n = {"tools": len(STATE["tools"]), "write": sum(1 for t in STATE["tools"] if not t["read_only"]),
             "modules": len({t["module"] for t in STATE["tools"]})}
    p = STATE["proc"]
    return {"running": _running(), "mode": cfg["mode"], "url": STATE["url"] if cfg["mode"] == "external" else ("local" if STATE["url"] else None),
            "pid": p.pid if p and p.poll() is None else None, "started_at": STATE["started_at"], "error": STATE["error"],
            "read_only": cfg["read_only"], "modules": cfg["modules"], "port": cfg["port"], "counts": n, "server": STATE["info"],
            "log": list(LOG)[-60:], "demo": config.DEMO, "external_url": _cfg()["url"], "external_key_set": bool(_cfg()["api_key"]),
            "available_modules": _available_modules()}


def _available_modules():
    try:
        from falcon_mcp import registry
        return sorted(registry.get_module_names())
    except Exception:  # noqa: BLE001
        return []


# ------------------------------------------------------------------ routes
@router.get("/api/mcp/status")
def mcp_status():
    return status()


@router.post("/api/mcp/start")
def mcp_start():
    return start()


@router.post("/api/mcp/stop")
def mcp_stop():
    stop()
    return status()


@router.put("/api/mcp/config")
def mcp_config(data: dict = Body(...)):
    """{mode: managed | external | off, url, api_key, modules: [..], read_only: bool, port}. Restarts the managed server."""
    vals = {}
    if "mode" in data:
        if data["mode"] not in ("managed", "external", "off"):
            raise HTTPException(400, "mode must be managed, external or off")
        vals["mcp_mode"] = data["mode"]
    if "url" in data:
        vals["mcp_url"] = str(data["url"] or "").strip()
    if data.get("api_key"):
        vals["mcp_api_key"] = str(data["api_key"]).strip()
    if "modules" in data:
        bad = [m for m in data["modules"] if m not in _available_modules()]
        if bad:
            raise HTTPException(400, "Unknown modules: " + ", ".join(bad))
        vals["mcp_modules"] = ",".join(data["modules"])
    if "read_only" in data:
        vals["mcp_read_only"] = "1" if data["read_only"] else "0"
    if "port" in data:
        vals["mcp_port"] = str(int(data["port"]))
    db.set_settings(vals)
    stop()
    return status()


@router.get("/api/mcp/tools")
def mcp_tools(refresh: int = 0):
    return {"rows": tools(bool(refresh)), **status()}


@router.get("/api/mcp/resources")
def mcp_resources():
    _ensure()
    res = _run(lambda s: s.list_resources()).resources
    return {"rows": [{"uri": str(r.uri), "name": r.name, "description": r.description or ""} for r in res]}


@router.get("/api/mcp/resource")
def mcp_resource(uri: str):
    _ensure()
    from pydantic import AnyUrl
    rr = _run(lambda s: s.read_resource(AnyUrl(uri)))
    return {"uri": uri, "text": "".join(getattr(c, "text", "") or "" for c in rr.contents)}


@router.post("/api/mcp/call")
def mcp_call(request: Request, data: dict = Body(...)):
    user = request.headers.get("x-user") or ""
    return call(str(data.get("tool") or ""), data.get("arguments") or {}, user, bool(data.get("confirm")))


@router.get("/api/mcp/runs")
def mcp_runs(tool: str = "", limit: int = 100):
    w, p = ("WHERE tool=?", [tool]) if tool else ("", [])
    with db.get_conn() as c:
        rows = db.rows(c, f"SELECT id, at, tool, args, ok, error, seconds, size, user, read_only FROM mcp_runs {w} ORDER BY id DESC LIMIT ?",
                       p + [min(500, limit)])
    for r in rows:
        r["args"] = db.jloads(r["args"], {})
    return {"rows": rows}


@router.get("/api/mcp/runs/{run_id}")
def mcp_run(run_id: int):
    with db.get_conn() as c:
        r = db.one(c, "SELECT * FROM mcp_runs WHERE id=?", (run_id,))
    if not r:
        raise HTTPException(404, "Run not found")
    r["args"] = db.jloads(r["args"], {})
    try:
        r["data"], r["text"] = json.loads(r.pop("result") or "null"), None
    except ValueError:
        r["data"], r["text"] = None, r.pop("result", "")
    return r


def shutdown():
    stop()
