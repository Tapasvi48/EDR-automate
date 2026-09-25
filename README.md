# EDR Asset Console (CrowdStrike Falcon)

Asset dashboard for CrowdStrike Falcon: fleet health, offline/stale hosts, duplicates, reinstalls, NIC/IP history search,
and LOB inventory reconciliation with full version control. Everything exports to Excel.

- **Backend:** FastAPI + SQLite (WAL, indexed) + [FalconPy](https://github.com/CrowdStrike/falconpy) `Hosts` service class
- **Frontend:** Next.js 16 (static export) + React 19 + Tailwind v4 + TanStack Query + Recharts + Radix + cmdk

## Run with Docker

```bash
docker run -d --name edr-asset-console --restart unless-stopped \
  -p 8765:8765 -v edr-data:/data \
  -e APP_USERNAME=admin -e APP_PASSWORD='choose-a-strong-password' \
  <registry>/<user>/edr-asset-console:latest
```

Open http://<host>:8765 → **Sync & settings** → enter the CrowdStrike API client.
- `/data` holds the SQLite database (hosts, history, LOB inventories, API credentials) and uploaded files. Keep it on a volume.
- Set `APP_USERNAME` / `APP_PASSWORD` to protect the dashboard with a login. Without them, anyone who can reach the port can see the data.
- The container runs as a non-root user and only needs outbound HTTPS to your CrowdStrike cloud (e.g. api.crowdstrike.com).
- `docker compose up -d --build` builds and runs it from source with the included `docker-compose.yml`.

## Quick start (without Docker)

```bash
./run.sh            # creates .venv, builds the UI once, starts http://127.0.0.1:8765
```

### Connect to Falcon
1. In Falcon go to **Support and resources → API clients and keys**. Create a client with the **Hosts: Read** scope.
2. Open **Sync & settings** in the app. Paste the client ID and secret, and pick your cloud region. Click **Test connection**.
   It checks authentication plus each permission the sync uses, and shows the exact error if something fails.
3. Click **Save & sync now**. The first full sync runs with live step-by-step progress. After that, the app syncs automatically
   (every hour by default, configurable). A sync that was due while the app was stopped runs shortly after it starts again.
4. Every sync writes a log of what it fetched. You can see it under **Sync history & logs**.

Credentials and all synced data are stored in `data/edr_assets.db` (file mode 600). The secret is never sent back to the browser.
`.env` values (`FALCON_CLIENT_ID`, …) are used only when nothing is saved in the app.

### Frontend development
```bash
.venv/bin/uvicorn app.main:app --port 8765     # API
cd frontend && npm run dev                      # UI on :3000, /api proxied to :8765
npm run build                                   # rebuild the static UI served by FastAPI
```

## What a sync does
| Step | Falcon API (FalconPy) |
|---|---|
| All AIDs in console | `query_devices_by_filter_scroll` (5,000 per page) |
| Hidden hosts | `query_hidden_devices` |
| Full host details | `get_device_details` (PostDeviceDetailsV2, 5,000 per call, parallel) |
| Real online state | `get_online_state` (100 per call, parallel) |
| NIC / IP history | `query_network_address_history` (new + IP-changed hosts) |

Rate limits (429) are retried using Falcon's `X-RateLimit-RetryAfter` header. As a safety guard, a sync aborts if Falcon suddenly returns
fewer than half of the previously active hosts, so an API or scope problem can't mark the whole fleet as removed.

## Detection logic
- **Removed hosts are never deleted locally.** If an AID disappears from the console, it is kept and classified:
  - **auto_inactive**: its last_seen was already older than the auto-removal window (`auto_remove_days`, default 45).
  - **deleted**: it was removed while still recently active.
  - **hidden**: it appears in the hidden-hosts list.

  If an AID comes back, it is marked **restored**.
- **Online · stale last seen**: Falcon's online-state API says *online*, but `last_seen` is older than `stale_online_hours`.
- **Duplicate**: two or more *active* AIDs share a local IP (or hostname or serial). Agents that share an IP count as **one device**. The device is online if any of its agents is online. All fleet counts and the All assets / Offline lists use devices, so duplicates never inflate the online or offline numbers. Shared ranges such as NAT, VPN and loopback can be excluded in Settings.
- **Reinstall**: a new AID where an *older* AID had the same IP (including NIC history) and/or hostname. The confidence is shown as `ip+hostname` › `hostname` › `ip`.
- **Went offline on day X**: the host is currently offline and its last_seen date is X.
- **Outdated sensor**: older than the three newest sensor versions seen per platform (N-2).
- Every change between syncs is written to the **Activity log**: new, removed, hidden, restored, IP change, hostname change, sensor update, reinstall.

## LOB → MSP model and coverage
- Each **LOB** has one or more **MSPs**. MSPs are created manually or automatically from the inventory's MSP column.
  An inventory upload can cover the whole LOB, using the MSP column, or **a single MSP**. A single-MSP upload replaces only that MSP's rows
  and carries every other MSP's rows into the new version unchanged.
- Every inventory node gets one **EDR status**:
  - **Non Live** / **Not Feasible**: the node is not applicable and is excluded from coverage.
  - **Online** / **Offline**: the node is *installed*.
  - **Hidden** / **Removed**: the node's agent left the console.
  - **Not Installed**: no matching agent was found.
- **Applicable** = Live and EDR feasible. **Coverage** = Installed ÷ Applicable. **Pending** = Not Installed + Hidden + Removed.
- **Not in inventory** means agents tagged to a LOB/MSP but missing from its inventory. To tag agents, upload a sheet with an Agent ID column
  (hostname or IP also work) and an MSP column from the LOB page. **Unmapped agents** are agents that no LOB inventory or tag claims.
- **IPs in >1 MSP**: the same IP is listed by two MSPs of one LOB. **Dup IPs (EDR)**: installed nodes whose IP is shared by several active agents.

## LOB inventory
- **Templates** map the LOB spreadsheet's columns to the standard fields: IP, Node Name, Node Type, Domain, Live/Non Live, OS, EDR Feasible,
  EDR Installed, Remarks. Without a template, columns are auto-detected. At upload you can still change every mapping, pick the sheet or header row,
  and save the result as a template or as the LOB's default. Unmapped columns are kept as extra fields.
- **Versioning**: every upload creates an immutable snapshot. Rows are matched to the previous version by the key field (IP, Node Name,
  or IP + Node Name). New rows are tagged `NEW`. Missing rows are logged as removed. Changed fields are logged with old → new values. You can
  preview the diff before committing, compare any two versions, view any old snapshot, or restore an old version (the restore becomes a new version).
- **EDR verification**: each current row is matched to Falcon in this order: IP + hostname › hostname › IP › NIC history. If only the IP
  matches and the machine name differs, the row is *not* counted as installed. The inventory's "EDR Installed" value is treated as a claim and
  compared with reality:
  `Verified`, `Installed - Inactive`, `Claimed - Not Found`, `Claimed - Removed from Console`, `Installed - Marked No`,
  `Installed - Marked Not Feasible`, `Pending Install`, `Not Feasible`.
- The inventory fields (LOB, node type, live, feasible, installed, remarks) also appear as columns in the host views.

## Pages
Overview · All assets · IP & NIC search (exact, prefix, CIDR, hostname) · Bulk lookup (paste IPs/hostnames) · Offline & stale ·
Duplicates · New installs (per day/week/custom range, reinstall tag) · Activity log · LOB inventory · Coverage gaps · Templates ·
Reports (one-click executive workbook plus 14 exports) · Sync & settings. Press **⌘K / Ctrl+K** anywhere to jump to a host, IP or page.
