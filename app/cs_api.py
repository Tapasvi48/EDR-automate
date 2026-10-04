"""Live CrowdStrike API calls for the AI SOC without Falcon MCP: the same API client (FalconPy) and credentials the sync uses.

  mode()     which path live lookups take: "sample" (sample-data mode) · "direct" (API credentials saved in Sync & settings) ·
             "mcp" (only a Falcon MCP connection) · None
  command()  one Falcon API operation by its operation ID (FalconPy Uber class), e.g. QueryIntelIndicatorEntities
  ngsiem()   run a CQL search in NG-SIEM (StartSearchV1, then poll GetSearchStatusV1) and return its events

Extra API scopes for the AI SOC (all read-only in effect): Indicators (Falcon Intelligence): Read · IOC Management: Read ·
NGSIEM search (read; starting a search job also needs the NGSIEM write scope in some tenants). Missing scopes only disable
that lookup; the error says which one."""
import threading
import time

from . import config, falcon, sample_api

_H = {"key": None, "h": None}
_LOCK = threading.Lock()


def mode():
    if config.DEMO:
        return "sample"
    if falcon.is_configured():
        return "direct"
    from . import falconmcp
    cfg = falconmcp._cfg()
    return "mcp" if cfg.get("mode") == "remote" and cfg.get("url") else None


def describe(m=None):
    return {"sample": "sample data", "direct": "CrowdStrike API (direct)", "mcp": "Falcon MCP", None: "not connected"}[m if m is not None else mode()]


def _harness():
    from falconpy import APIHarnessV2
    cr = falcon.credentials()
    key = (cr["client_id"], cr["client_secret"], cr["base_url"], cr["member_cid"])
    with _LOCK:
        if _H["key"] != key:
            kw = dict(client_id=cr["client_id"].strip(), client_secret=cr["client_secret"].strip(),
                      base_url=falcon.CLOUDS.get((cr["base_url"] or "us-1").strip().lower(), cr["base_url"]), timeout=60)
            if cr["member_cid"]:
                kw["member_cid"] = cr["member_cid"].strip()
            _H.update(key=key, h=APIHarnessV2(**kw))
        return _H["h"]


def command(operation, **kw):
    if config.DEMO:
        return sample_api.command(operation, **kw)
    return _harness().command(operation, **kw)


SCOPE = {"QueryIntelIndicatorEntities": "Indicators (Falcon Intelligence): Read", "indicator_combined_v1": "IOC Management: Read",
         "StartSearchV1": "NGSIEM (search)", "GetSearchStatusV1": "NGSIEM (search)"}


def call(operation, what, **kw):
    """One operation; returns the response body or raises falcon.FalconError with a readable message (403 names the scope)."""
    r = command(operation, **kw)
    code = r.get("status_code", 0)
    if code >= 400 or code == 0:
        errs = (r.get("body") or {}).get("errors") or []
        msg = "; ".join(str(e.get("message", e)) for e in errs) if isinstance(errs, list) else str(errs)
        if code == 403:
            raise falcon.FalconError(f"{what}: access denied (HTTP 403). The API client needs the '{SCOPE.get(operation, operation)}' scope.")
        raise falcon.FalconError(falcon.friendly(code, msg, what))
    return r.get("body") or {}


def ngsiem(query, start_ms, repository="search-all", timeout=120):
    """Run a CQL search; returns (events, metaData)."""
    body = call("StartSearchV1", "NG-SIEM search", repository=repository, body={"queryString": query, "start": start_ms, "isLive": False})
    sid = body.get("id")
    if not sid:
        raise falcon.FalconError("NG-SIEM search: no job ID returned")
    t0, wait = time.time(), 0.3
    while time.time() - t0 < timeout:
        st = call("GetSearchStatusV1", "NG-SIEM search status", repository=repository, search_id=sid)
        if st.get("done"):
            return st.get("events") or [], st.get("metaData") or {}
        time.sleep(wait)
        wait = min(2.0, wait * 1.6)
    try:
        command("StopSearchV1", repository=repository, id=sid)
    except Exception:  # noqa: BLE001
        pass
    raise falcon.FalconError(f"NG-SIEM search did not finish in {timeout}s — narrow the time range or add filters")
