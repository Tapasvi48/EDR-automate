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
./run.sh --demo     # same, with sample data in data/demo.db (real database untouched, syncing off)
```

**Sample data:** `--demo` (or `-e DEMO=1` with Docker) fills its own database file with three LOBs, MSPs, two inventory
versions each, ~450 agents (online / offline / removed > 90 days / deleted / hidden / duplicates / reinstalls), an old EDR
import, two Nessus scans per LOB and a NIAM dump, so every page has something to show. Restart without the flag to go
back to your own data.

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
- **Duplicate agents**: two or more *active* AIDs with the same **connection IP and local IP**, where at most one of them is online
  (the same machine re-imaged, cloned or reinstalled). They count as **one device**; the online (else most recently seen) agent is the primary.
- **Routing conflict**: two or more agents with the same connection IP and local IP that are **online at the same time**, i.e. different
  live machines that look identical on the network. Listed under *Routing conflicts*; each agent counts as its own device. The device is online if any of its agents is online. All fleet counts and the All assets / Offline lists use devices, so duplicates never inflate the online or offline numbers. Shared ranges such as NAT, VPN and loopback can be excluded in Settings.
- **Reinstall**: a new AID where an *older* AID had the same **connection IP** (its current one or any connection IP recorded in earlier syncs). Hostname and local IP are not used.
- **Went offline on day X**: the host is currently offline and its last_seen date is X.
- **Sensor level**: versions are grouped by release (major.minor, e.g. 7.40.19206.0 → 7.40). Per platform the newest release in the console is N; N-1 and N-2 are the release numbers right before it (7.39, 7.38 when N is 7.40), whether or not they are installed anywhere; anything older is **outdated**.
- Every change between syncs is written to the **Activity log**: new, removed, hidden, restored, IP change, hostname change, sensor update, reinstall.

## LOB → MSP model and coverage
- Each **LOB** has one or more **MSPs**. MSPs are created manually or automatically from the inventory's MSP column.
  An inventory upload can cover the whole LOB, using the MSP column, or **a single MSP**. A single-MSP upload replaces only that MSP's rows
  and carries every other MSP's rows into the new version unchanged.
- A LOB can also have **inventory types** (e.g. Servers, Network devices). Each type has its **own inventory file and version history**
  (v1, v2 …). A type upload sets the node type of every row to the type name and replaces only that type's rows; the main inventory
  and other types stay unchanged. The LOB's current inventory is the main inventory plus the current version of every type.
- Every inventory node gets one **EDR status**:
  - **Non Live** / **Not Feasible**: the node is not applicable and is excluded from coverage.
  - **Online** / **Offline**: the node is *installed*.
  - **Hidden** / **Removed**: the node's agent left the console.
  - **Not Installed**: no matching agent was found.
- **Applicable** = Live and EDR feasible. **Coverage** = Installed ÷ Applicable. **Pending** = Not Installed + Hidden + Removed.
- **Not in inventory** means agents tagged to a LOB/MSP but missing from its inventory. To tag agents, upload a sheet with an Agent ID column
  (hostname or IP also work) and an MSP column from the LOB page. **Unmapped agents** are agents that no LOB inventory or tag claims.
- **Duplicate IPs**: an IP on several inventory rows of one LOB. **IPs in other LOBs**: the same IP is also listed by another LOB. **Dup IPs (EDR)**: installed nodes whose agent has duplicate agents.

## Vulnerabilities, old EDR inventory and Asset 360
- **Vulnerability scans (per LOB):** upload a Nessus-format export (S.No., IP Address, Vulnerability Name, Severity, Protocol, Port,
  Synopsis, Description, Steps to Remediate, Plugin Text, See Also, CVE, Exploit Ease, Plugin ID, First Discovered, Last Observed,
  Vuln / Patch Publication Date, Remarks) from **Upload center** or the LOB's **Vulnerabilities** tab.
  - A finding is identified by IP + plugin + port + protocol.
  - For every IP in a new scan, findings that are gone are marked **fixed**, and findings that come back are marked **reopened**.
    IPs that are not in the file keep their findings, so partial scans are safe.
  - Each IP keeps its **last scan date**.
  - Scanned IPs are matched to the LOB inventory (MSP, node type) and to CrowdStrike (EDR status). This powers the highest-risk
    view: *critical/high findings on hosts without active EDR*.
- **Old EDR inventory:** upload an older CrowdStrike host export. Agents that are no longer in the live console are stored as
  **Old EDR import**.
  - They appear in **EDR history** next to agents that were auto-removed (> N days), deleted manually, or hidden.
  - They are used for inventory, vulnerability and search matching.
  - If one reports again, the next sync restores it.
- **Asset 360** (`/ip-search/`): one search for an IP, hostname or AID. It shows EDR status and agent, LOB and MSP, what the
  inventory says, open vulnerabilities, the last scan and the IP history. A prefix or CIDR lists every asset in the range.
  The same data is in the host drawer, bulk lookup and the executive report.

## Risk ranking and scan coverage

- **Risk ranking:** every inventory node and scanned IP gets a 0–100 score from EDR and vulnerabilities only: no EDR
  agent (+35), EDR offline (+8 / +15 after 7 days / +25 after 30 days; agents removed from the console count as offline),
  open critical (+12, +6 each more, max 30), high (+5, +2 each more, max 15), medium (max 5), and +10 when a critical / high
  finding has a known exploit (the scan's "Exploit Ease" column, e.g. Nessus "Exploits are available"). Non Live nodes
  count 30%. Levels: Critical ≥ 60, High ≥ 35, Medium ≥ 15. Asset 360 shows the score and its parts.
- **Scan coverage:** live inventory nodes by last-scan age (≤ 30, 31–60, 61–90, > 90 days, never) per LOB / MSP and node type.
- All three export to Excel and are included in the executive report.

## OS and EDR feasibility

**OS** is resolved for every asset in this order:
1. the CrowdStrike agent's OS;
2. the inventory's OS column;
3. the VA scan.

For the VA scan, Nessus plugin **11936 "OS Identification"** gives a line such as `Remote operating system : Microsoft Windows Server 2019 Standard`. When several guesses are listed, the first is used. An optional "Operating System" column in the scan export is used if the plugin is absent. Keep severity None/Info rows in the export so plugin 11936 is included.

**EDR feasibility** is decided by the console, not taken from the inventory sheet; Live / Non Live does not matter. Each node is Feasible, Not feasible or To be decided, in this order (page: **CrowdStrike → EDR feasibility**):
1. **Node:** a manual decision on one node.
2. **LOB / Domain:** a whole LOB or domain marked not feasible.
3. **Sheet:** the feasibility sheet. Download it (Node Type × OS pairs with node counts, agents installed and the suggested value, plus LOB and Domain sheets), set Feasible Yes/No, and upload it. Only rows that differ from the automatic decision are stored.
4. **Agent:** a CrowdStrike agent installed (online or offline) makes the node feasible.
5. **OS:** feasible when any CrowdStrike sensor release runs on it, old sensors included (the page shows the last sensor version for those). Not feasible only when no sensor supports it and no agent anywhere runs on it. OS marks on the page override this.
6. **Node type:** feasible when an agent is installed on at least one node of that type, in any LOB. A type with no agent yet is **To be decided** until you mark it.

EDR applicable = Feasible. The OS support catalog, the N / N-1 / N-2 sensor builds and the "last sensor" per old OS are on the same page. They are fetched from the Sensor update policies API on each sync (the API client needs the **Sensor update policies: Read** scope), and you can edit them.

Assets in no inventory:
- If CrowdStrike has them, they are feasible and count in the applicable total on All inventory.
- Anything found only by a VA scan or the NIAM dump is **Unidentified**. It counts in the total but not in the applicable count.

## NIAM dump and integrations

**Integrations → Upload NIAM dump** (or the Upload center) takes a sheet with **Host** (IP) and **NE ID**; other columns
(NE name, type, vendor, circle…) are kept. Each upload is a full snapshot: nodes missing from a newer dump are marked
*dropped*, not deleted. Every node shows its EDR status, LOB / MSP and open vulnerabilities, NE IDs appear in Asset 360
(you can also search by NE ID), and everything exports to Excel.

## IPv4 and IPv6

Every IP that is stored or searched is normalised first, so the same address always matches however it was typed:
IPv4 with leading zeros or a port (`010.001.001.005`, `10.1.1.5:443`), IPv6 in any case or compression
(`2001:DB8:0:0::1` = `2001:db8::1`), `[addr]:port`, `%zone` suffixes and IPv4-mapped IPv6 (`::ffff:10.0.0.1`).
Cells with several IPs use the first one. Searches accept exact IPs, IPv4 prefixes (`10.20.`) and CIDR for both versions
(`10.20.0.0/16`, `2001:db8::/48`). Existing databases are converted once on the first start after upgrading.

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
