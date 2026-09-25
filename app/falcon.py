"""Thin wrapper around FalconPy's Hosts service collection.

Only READ operations are used (Hosts: Read scope):
  QueryDevicesByFilterScroll, PostDeviceDetailsV2, GetOnlineState_V1,
  QueryHiddenDevices, QueryGetNetworkAddressHistoryV1
"""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, db

log = logging.getLogger("falcon")

DETAILS_BATCH = 5000        # PostDeviceDetailsV2 max
ONLINE_BATCH = 100          # GetOnlineState_V1 (GET query string - keep it short)
NIC_BATCH = 100
WORKERS = 6

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}


class FalconError(RuntimeError):
    pass


def friendly(code, msg, what):
    if code == 401:
        return f"{what}: authentication failed (HTTP 401). Check the client ID / secret and that the cloud region matches your tenant."
    if code == 403:
        return f"{what}: access denied (HTTP 403). The API client needs the 'Hosts: Read' scope."
    if code == 429:
        return f"{what}: rate limited by CrowdStrike (HTTP 429)."
    if code in (0, None):
        return f"{what}: could not reach the CrowdStrike API ({msg or 'network error'}). Check the cloud region / proxy / firewall."
    return f"{what}: {msg or 'HTTP ' + str(code)}"


def _chunks(seq, n):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def credentials():
    """Credentials saved in Settings, falling back to .env."""
    s = db.get_settings()
    cid = s.get("falcon_client_id") or config.FALCON_CLIENT_ID
    secret = s.get("falcon_client_secret") or config.FALCON_CLIENT_SECRET
    base = s.get("falcon_base_url") or config.FALCON_BASE_URL or "us-1"
    member = s.get("falcon_member_cid") or config.FALCON_MEMBER_CID
    return {"client_id": cid, "client_secret": secret, "base_url": base, "member_cid": member,
            "source": "settings" if s.get("falcon_client_id") else ("env" if config.FALCON_CLIENT_ID else None)}


def is_configured():
    c = credentials()
    return bool(c["client_id"] and c["client_secret"])


class FalconClient:
    def __init__(self, client_id, client_secret, base_url="us-1", member_cid=""):
        from falconpy import Hosts

        if not client_id or not client_secret:
            raise FalconError("CrowdStrike API credentials are not configured (Sync & settings → Connection).")
        kwargs = dict(client_id=client_id.strip(), client_secret=client_secret.strip(),
                      base_url=CLOUDS.get((base_url or "us-1").strip().lower(), (base_url or "us-1").strip()), timeout=120)
        if member_cid:
            kwargs["member_cid"] = member_cid.strip()
        self.hosts = Hosts(**kwargs)

    # -- low level -------------------------------------------------------
    def login(self):
        self.hosts.login()
        if not self.hosts.token_valid:
            code = self.hosts.token_status
            reason = (self.hosts.token_fail_reason or "").rstrip(".")
            if code in (0, None) or "connect" in reason.lower() or "resolve" in reason.lower():
                raise FalconError(friendly(0, reason, "Authentication"))
            raise FalconError(f"Authentication failed ({reason or 'HTTP ' + str(code)}). Check the client ID and secret, "
                              f"and that the cloud region ({self.hosts.base_url}) is the one your Falcon tenant uses.")

    def _call(self, fn, what, retries=5, **kw):
        for attempt in range(retries):
            try:
                r = fn(**kw)
            except Exception as e:  # noqa: BLE001 - network errors from requests
                if attempt == retries - 1:
                    raise FalconError(friendly(0, str(e), what)) from e
                time.sleep(2 ** attempt)
                continue
            code = r.get("status_code", 0)
            if code == 429 or code >= 500:
                wait = 2 ** attempt
                try:
                    retry_after = (r.get("headers") or {}).get("X-Ratelimit-Retryafter")
                    if retry_after:
                        wait = max(1, int(retry_after) - int(time.time()))
                except (TypeError, ValueError):
                    pass
                log.warning("Falcon %s -> %s, retrying in %ss", what, code, wait)
                time.sleep(min(wait, 60))
                continue
            if code >= 400 or code == 0:
                errs = (r.get("body") or {}).get("errors") or []
                msg = "; ".join(str(e.get("message", e)) for e in errs)
                raise FalconError(friendly(code, msg, what))
            return r.get("body", {})
        raise FalconError(f"{what}: gave up after {retries} retries")

    def _parallel(self, fn, batches, what, progress=None):
        batches = list(batches)
        done, lock, out = [0], threading.Lock(), []
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = [ex.submit(fn, b) for b in batches]
            for f in as_completed(futs):
                res, n = f.result()
                out.append(res)
                with lock:
                    done[0] += n
                    if progress:
                        progress(done[0])
        return out

    # -- queries ---------------------------------------------------------
    def list_all_aids(self, progress=None):
        aids, offset = [], None
        while True:
            kw = {"limit": 5000}
            if offset:
                kw["offset"] = offset
            body = self._call(self.hosts.query_devices_by_filter_scroll, "List hosts", **kw)
            res = body.get("resources") or []
            aids.extend(res)
            pag = (body.get("meta") or {}).get("pagination") or {}
            offset = pag.get("offset")
            if progress:
                progress(len(aids), pag.get("total", len(aids)))
            if not res or not offset or len(aids) >= pag.get("total", 0):
                break
        return aids

    def list_hidden_aids(self):
        aids, offset = [], 0
        while True:
            body = self._call(self.hosts.query_hidden_devices, "List hidden hosts", limit=5000, offset=offset)
            res = body.get("resources") or []
            aids.extend(res)
            total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
            offset += len(res)
            if not res or offset >= total:
                break
        return aids

    def get_details(self, aids, progress=None):
        def fetch(batch):
            return self._call(self.hosts.get_device_details, "Host details", ids=batch).get("resources") or [], len(batch)
        out = []
        for res in self._parallel(fetch, _chunks(aids, DETAILS_BATCH), "details", progress):
            out.extend(res)
        return out

    def get_online_states(self, aids, progress=None):
        def fetch(batch):
            return self._call(self.hosts.get_online_state, "Online state", ids=batch).get("resources") or [], len(batch)
        states = {}
        for res in self._parallel(fetch, _chunks(aids, ONLINE_BATCH), "online", progress):
            for r in res:
                states[r.get("id")] = r.get("state", "unknown")
        return states

    def get_nic_history(self, aids, progress=None):
        """Returns {aid: [{ip_address, mac_address, timestamp}, ...]}"""
        def fetch(batch):
            return self._call(self.hosts.query_network_address_history, "NIC history", ids=batch).get("resources") or [], len(batch)
        out = {}
        for res in self._parallel(fetch, _chunks(aids, NIC_BATCH), "nic", progress):
            for r in res:
                out[r.get("device_id")] = r.get("history") or []
        return out


def get_client():
    c = credentials()
    return FalconClient(c["client_id"], c["client_secret"], c["base_url"], c["member_cid"])


def test_connection(client_id, client_secret, base_url, member_cid=""):
    """Checks authentication and each API permission the sync needs. Returns a list of check results."""
    checks = []

    def run(name, fn, required=True):
        t = time.time()
        try:
            detail = fn()
            checks.append({"name": name, "ok": True, "detail": detail, "ms": int((time.time() - t) * 1000), "required": required})
            return True
        except Exception as e:  # noqa: BLE001
            checks.append({"name": name, "ok": False, "detail": str(e), "ms": int((time.time() - t) * 1000), "required": required})
            return False

    state = {}

    def auth():
        state["c"] = FalconClient(client_id, client_secret, base_url, member_cid)
        state["c"].login()
        return f"Token issued by {state['c'].hosts.base_url}"

    def hosts():
        body = state["c"]._call(state["c"].hosts.query_devices_by_filter_scroll, "List hosts", limit=1)
        state["aid"] = (body.get("resources") or [None])[0]
        total = ((body.get("meta") or {}).get("pagination") or {}).get("total", 0)
        return f"{total:,} hosts in the console"

    def details():
        if not state.get("aid"):
            return "No hosts to read yet"
        r = state["c"].get_details([state["aid"]])
        return f"Read host {r[0].get('hostname', state['aid'])}" if r else "OK"

    def online():
        if not state.get("aid"):
            return "No hosts to read yet"
        s = state["c"].get_online_states([state["aid"]])
        return f"State: {s.get(state['aid'], 'unknown')}"

    def hidden():
        n = len(state["c"].list_hidden_aids())
        return f"{n:,} hidden hosts"

    def nic():
        if not state.get("aid"):
            return "No hosts to read yet"
        h = state["c"].get_nic_history([state["aid"]])
        return f"{len(h.get(state['aid'], []))} address records for one host"

    if run("Authenticate", auth) and run("Hosts: list", hosts):
        run("Hosts: details", details)
        run("Hosts: online state", online)
        run("Hosts: hidden hosts", hidden, required=False)
        run("Hosts: NIC / IP history", nic, required=False)
    ok = all(c["ok"] for c in checks if c["required"]) and len(checks) >= 2
    return {"ok": ok, "checks": checks}
