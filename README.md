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

**Sync & settings → CrowdStrike API features** lists every feature the console takes from CrowdStrike: its API scope, what the last
sync said, and how much data is in the console. For example, Analyst workload needs Alerts: Read *and* alerts assigned to analysts.
"Check every feature now" runs a live, read-only check of each one.
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
| Detections (Alerts: Read) | `query_alerts_v2` / `get_alerts_v2`: the full window (`detections_days`) once a day, otherwise only alerts created or updated since the last sync. Windows with more than 10,000 alerts are split by time, since the API refuses offset + limit > 10,000 |
| Spotlight (Vulnerabilities: Read) | `query_vulnerabilities_combined`: every open finding once a week, otherwise only findings updated since the last sync (closed ones are removed) |
| Sensor builds, supported Linux kernels | once a day (skipped by the syncs in between) |

**Large data (1 lakh hosts / inventory rows).**
- Page answers are cached until the data changes, and the most visited pages are recomputed in the background after every
  sync, upload or re-match. Clicks on unchanged data return at once.
- Re-matching (inventory ↔ CrowdStrike, exposure, risk) runs in the background once there are more than 20,000 hosts plus
  inventory rows. Saving a LOB, tag, matrix, whitelist, scan or NIAM change returns immediately, and pages refresh when
  matching finishes (shown in the top bar).
- The full CrowdStrike device record is kept in its own table (`host_raw`), so counts over hosts do not read it.

Rate limits (429) are retried using Falcon's `X-RateLimit-RetryAfter` header. As a safety guard, a sync aborts if Falcon suddenly returns
fewer than half of the previously active hosts, so an API or scope problem can't mark the whole fleet as removed.

**Sync timing.** Every step in the sync progress shows how long it took. Full device records are read once a day; the syncs
in between fetch records only for agents that are new, came back, or changed / checked in since the last sync
(`modified_timestamp` or `last_seen` after it). The online state of every agent is still refreshed on each sync.

## AI SOC (left menu → AI SOC)
- **Assistant:** a chat that hunts CrowdStrike in CQL, answers from the data fabric, explains detections / assets / CVEs,
  checks IOCs, answers from the knowledge base, and says how two entities are connected ("how is svc_batch connected to Payments?").
  - Conversations are saved (search, pin, delete) and grouped by day; follow-ups remember the host, IP, hash, CVE or detection.
  - Each answer shows what the agent did (matched a tested hunt / planned by the model, where it ran, how long) and suggests follow-ups.
  - Open it from any page with **Ask AI SOC**, bottom right.
- **Hunt studio (CQL):** plain English → CQL → check → run → save.
  - A library of 45 tested, MITRE-tagged hunting queries (credential dumping, lateral movement, persistence, exfiltration, C2,
    ransomware precursors, Linux / macOS…) and your team's saved queries.
  - A CQL parser and linter: unknown functions / fields (with "did you mean"), broken regexes, unbalanced brackets; an auto-fixer
    rewrites SQL / SPL / KQL habits (`WHERE`, `==`, `| stats count by`, `| limit`, `| sort by`); a plain-English explanation of any query.
  - Queries run in NG-SIEM through the CrowdStrike API directly (FalconPy, the sync's credentials), else Falcon MCP; in sample-data
    mode against synthetic endpoint telemetry with planted attacks.
- **Built for small on-prem models (4B–8B):**
  - The model never writes CQL text: it fills a JSON query plan (event, filters, output) whose event / field / operator values are
    enums; code compiles it to CQL, so syntax is always valid and fields exist on the event.
  - Retrieval first: the closest library hunts are the few-shot examples. A question a tested hunt answers exactly gets it
    instantly, with no model call.
  - Grounding after: IPs, hashes, domains, users and hostnames in the question are checked against the plan and added if dropped.
  - Without a model the library + rules answer (24 / 24 on the CQL test set; 37 / 37 on hunt routing). Settings → AI model →
    Model check scores the configured model.
- **Data fabric:**
  - **Ontology:** 16 entity types (asset, CrowdStrike agent, IP, subnet, LOB, MSP, user, detection, MITRE tactic, process / file,
    CVE, policy, NDR alert, matrix rule, network block, checked IOC) and 18 relationship types, with live counts and sources.
  - **Graph explorer:** search any entity, click to expand its neighbours, see its properties and links; **Find a connection**
    shows the shortest path between two entities.
  - Sources (row counts, freshness), unified alerts (CrowdStrike + NDR, OCSF-style), entity resolution, and seven questions
    answered from the fabric itself (exposed assets without EDR, coverage gaps, KEV on exposed assets, riskiest assets, posture
    per LOB, asset owner, asset timeline).
- **Knowledge base:** your SOPs, playbooks and case notes (paste or upload), plus built-ins: CQL syntax guide, CQL functions,
  the Falcon event dictionary, the hunt library, an FQL guide, a CQL-for-SPL/KQL translation table, console glossary, MITRE ATT&CK
  and a triage playbook. Search is SQLite FTS5 (offline).
- **Explain with AI** buttons: detections ("Triage with AI"), Spotlight ("Explain CVE"), Asset 360, Overview ("Daily SOC brief").
  A brief gives a rule-based assessment, next steps and numbered facts with sources; with a model, a narrative that may only cite
  those facts.
- **IOC check** (left menu, and an Asset 360 tab): IPs, domains, URLs and hashes against CrowdStrike threat intel and custom IOCs
  (direct API — Falcon MCP is not needed), our detections / NDR / assets, and WHOIS / InternetDB / GreyNoise / VirusTotal.
  Extra API scopes: Indicators (Falcon Intelligence): Read, IOC Management: Read, and the NGSIEM search scopes for CQL hunts.
- **Full window:** AI SOC → **Full window** (no console navigation) or **New tab**; the chat's ↗ button opens a full-screen
  chat in a new tab (`/ai/?focus=chat`).
- **CQL Hub:** Hunt studio → Hunt library → CQL Hub → **Import** (or Knowledge → Import CQL Hub) downloads ByteRay's open (MIT)
  community library (~185 Next-Gen SIEM queries, github.com/ByteRay-Labs/Query-Hub) once. The queries are browsable with author
  and MITRE tags, searchable in the knowledge base, and shown as references when the AI writes a hunt.
- **Detection triage:** a brief opens instantly (rules over the evidence): command-line behaviour analysis, indicators extracted
  and checked against CrowdStrike intel, the host's ATT&CK chain within 48 h, spread across hosts, NDR alerts, a true-positive
  likelihood, response steps, and ready-to-run CQL hunts. The model's narrative arrives after (structured JSON; a sentence is
  kept only if it cites facts and every name / IP / CVE in it exists in the brief).
- **Speed:** the model is loaded at start-up and kept in memory; rules answer the hunts they are sure of and tested library
  hunts answer matching questions without a model call; generated queries are cached; result summaries are on demand.
- **Learns from you:** correct the assistant in chat ("no, I want all exposed hosts, not only the ones without EDR") and it
  answers the corrected question and stores a lesson — the next similar question is answered that way. "Remember / always /
  never …" become standing preferences (e.g. include informational detections; by default they are left out of detection
  lists and counts). Settings → AI model → What the AI learned lists and removes them.
- **Local model:** Ollama (`ollama pull qwen3:8b`, or `qwen3:4b` on machines with 8 GB RAM) or any OpenAI-compatible server
  (vLLM, LM Studio); Settings → AI model.

## Splunk SIEM (left menu → SIEM & logging)
Synced from Splunk on a schedule (default hourly; Sync & settings in the section) and matched to the asset registry:
- **Overview**: % of assets logging, EDR but no logs, exposed with no logs, silent hosts, unknown log sources (Splunk hosts in
  no inventory), EPS now / 24 h average / 7-day peak, license GB per day, open ES notables, coverage per LOB.
- **Asset coverage** (every asset with Logging / Silent / No logs), **Hosts**, **Log sources** (index · sourcetype with volume,
  hosts, EPS, stale flag), **EPS** (hourly per index), **Detections** (ES notables with status / owner), **Indexes & license**
  (size, retention, newest event, GB per day), **Forwarders** (version, last connection), **Sync** (live progress, history).
- Each sync reads only what changed: host last-event (24 h) and notables since the last fetch every sync, EPS from the last
  stored hour; per-source detail, indexes, forwarders and license once a day; Full refresh re-reads all. Steps that need
  `_internal` or ES access are skipped (not failed) when the token may not read them.
- Splunk notables appear in Unified alerts, Asset 360 and the data-fabric graph; the AI SOC answers "which assets are not
  sending logs to Splunk?". Sample-data mode simulates Splunk.

## Large data (lakhs of IPs, crores of findings)
- **Scan imports stream**: the file (CSV of any size, or Excel) is read row by row into a staging table, never held in memory.
  The check (new / still open / reopened / fixed) and the import are SQL over that table and run as background jobs with a
  progress bar, in batches of 2.5 lakh rows so the rest of the site keeps working. After a scan only what a scan changes is
  refreshed (exceptions, that LOB's scanned assets, risk scores, the registry's vulnerability counts); new IPs are added to the
  registry in the background.
- **Re-matching writes only what changed** (inventory matches, risk scores, asset registry), so a sync or an upload no longer
  rewrites every row. Large connections use a big page cache; reads use memory-mapped I/O.
- **Pages read small summary tables** (per-IP counts, per-plugin stats) instead of scanning every finding, and the findings
  list is served in index order (no sort of crores of rows).
- `scripts/scale_bench.py` fills a copy of the sample database with lakhs of hosts / nodes / findings and times the pipeline
  and the main pages (never touches your data).

## CrowdStrike sync: what is read when
Hosts: every sync (changes since the last one; a full read once a day). Detections: only alerts new or updated since the last
sync (the full window is read once, at the start). Prevention policies, sensor builds / supported OS and Spotlight: once every
30 days (Sync & settings → change the interval, or **Refresh now**).

## Communication matrix: one template for every layout
Download the template (Templates → Communication matrix) and use its **Unified matrix** sheet: one row per flow, read without
column matching. It covers published services (public / NAT IP → inside IP), outbound source NAT (inside IP → outside / public
IP), static inside ↔ outside NAT, hosts with only a public IP directly on the ISP / ILL link, partner / NNI interconnects and
internal flows. Every inside, outside and public IP of an internet-facing row is listed on **Internet exposed** — also when no
inventory, VA scan, CrowdStrike or NIAM record knows the address yet ("Only in the matrix") — with its **address type**: public IP
(own / ISP-direct), private behind a public / NAT IP, or private exposed by a rule / zone / mark. Older layouts (firewall rules,
public IP pool, NAT list, SOD NAT, exposure register) still import, and headers such as Inside IP / Outside IP / Natted IP are
recognised.

## Falcon MCP (CrowdStrike → Falcon MCP)
The official [CrowdStrike Falcon MCP server](https://developer.crowdstrike.com/falcon-mcp/) (`falcon-mcp`, installed with the
requirements) is built into the console.

- **Managed mode (default):** the console runs falcon-mcp on 127.0.0.1 over streamable HTTP, protected by a random API key,
  with the CrowdStrike API client saved under Sync & settings. Secrets never reach the browser.
- **External mode:** connect to a falcon-mcp you run yourself (URL + API key).
- **Read-only by default:** tools that change the tenant (contain host, update detections, IOCs, policies, exclusions…) are
  not even loaded. Turn on "Allow write tools" under Connection; each write call still asks for confirmation.
- **Modules:** pick which ones to load (fewer modules = fewer tools for an AI assistant to choose from).
- **Page tabs:**
  - Quick hunts (high/critical detections, find a host, RFM sensors, critical Spotlight, process hunt in NG-SIEM,
    indicator lookup, threat actor);
  - every tool with a form built from its schema;
  - an NG-SIEM CQL editor with examples;
  - History: every call, with its arguments, timing and result;
  - the server's FQL / CQL guides.
- **Sample-data mode:** the real falcon-mcp server runs with its Falcon API client answering from the sample database.
  Operations that would change a tenant are refused.

### Ask Falcon (plain-English hunting, built for 8B local models)
Type a question on the Falcon MCP page ("which hosts ran psexec this week", "is 45.83.64.1 malicious", "who has CVE-2021-44228").

- **How it works:**
  - A local model (default `qwen3:8b` on Ollama; any OpenAI-compatible server such as vLLM or LM Studio also works) picks
    one hunt from a library of about 20 tested hunts and fills its inputs.
  - The console validates the inputs, builds the FQL / CQL itself, runs it through Falcon MCP (read-only), and shows:
    - the query it sent;
    - a factual summary;
    - an optional 3–5 line model summary;
    - the results table.
  - You can change the hunt, its inputs or the time range and run it again. Thumbs up / down is stored.
- **Why an 8B model is enough:**
  - The model never writes queries. Its answer is forced into a JSON schema whose hunt field is a fixed list.
  - IPs, hashes, CVEs, domains and time ranges are extracted by code first.
  - Temperature 0, thinking off, about 1.5k tokens of context. Two short calls, no agent loop.
  - Nothing leaves the machine with a local model.
- **Without a model**, a keyword router answers (29 of the 30 test questions).
- **Settings → AI model → Evaluate routing** scores the configured model on 30 built-in questions (accuracy and seconds
  per question).
- Every question is logged in `ai_asks`: the data to grow the hunt library and to fine-tune later.
- The full tool catalog, CQL editor, call history and guides are under **Advanced**.

## Filters, detail panels and CrowdStrike pages
- **Filters:**
  - Every dropdown filter is a searchable multi-select (values are sent as `a|b`, read as "any of"). Sort, view and yes/no
    pickers stay single-choice.
  - **Filter** (on every table) filters on any field the table returns, with contains / is / does not contain / empty /
    not empty, and several values per field. It works with the Excel export too.
  - The next page of every table is fetched in the background, so paging is instant.
- **Detail panels:**
  - Click a detection (Detections, Analyst workload) for everything CrowdStrike sent: what fired (MITRE tactic / technique,
    pattern, confidence), the process tree with command lines and hashes, status and analyst, the host, other detections on
    it, and the raw record.
  - Click a Spotlight finding for the vulnerability's name and description, CVSS vector, ExPRT, exploit status, CISA KEV,
    the affected software, the fix, what the VA scan says about the same CVE, and the raw record.
- **CrowdStrike pages:**
  - **Prevention policies:** each policy's settings and the agents on it, including where the policy is not applied yet.
  - **Sensor versions & OS:** the N / N-1 / N-2 builds, agents per version, supported OS and Linux kernels.
  - **Offline:** now also holds EDR history (removed from console / old EDR import).
- **EDR feasibility → Decide by Node type + OS:** undecided combinations come first; decide one or several for all LOBs in
  one click. Nodes can be selected and set directly too.
- **Communication matrix ownership:**
  - Private IPs (10.x, 172.16-31.x, 192.168.x …) are ours.
  - A public IP is ours when a rule translates it to / from one of our private IPs, when it is in your public ranges or
    your ASNs' prefixes, when it is marked enterprise, or when inventory / VA / NIAM has it.
  - Any other public IP in our rules is listed under **To check**.

## WHOIS, enterprise marks and deleting scans
- **WHOIS** for every public IP on the Attack surface and in Internet DB scan results comes from RDAP via rdap.org (free, no
  key). rdap.org sends each IP to its registry (APNIC, RIPE NCC, ARIN, LACNIC, AFRINIC). For each IP you get the netname,
  description, registrant organisation, country and registered range.
  - One answer covers the whole registered block, so a scanned /24 usually costs one look-up.
  - It runs with **Look up prefixes & WHOIS**, and automatically after every Internet DB scan.
  - /24 subnets, advertised prefixes and your ASNs' announced prefixes show their WHOIS too.
- **Enterprise / non-enterprise:** filter by WHOIS name, WHOIS description / organisation text, search or class. Then mark
  the selected rows, or everything the filter matches, as enterprise or non-enterprise. **All others → non-enterprise**
  marks every IP outside the filter that has no mark yet. Marks are kept per IP and show in exports.
- **Deleting scans:** Internet DB scan → Scan jobs lists every scan (selections, uploads, prefix / range scans). Each one can
  be opened (Results) or deleted with the results it found. Selected result rows can be deleted too. IPs that only a deleted
  scan knew leave the Attack surface, and exposure is recalculated.

## CrowdStrike detections and Subnets & VLANs
- **CrowdStrike → Detections** (`/detections/`) lists the stored detections. You can filter by date range, severity, status,
  tactic, LOB, open, unassigned and exposed assets. It also shows a per-day chart, the most affected hosts and the command
  line / description of each detection. **Fetch detections now** pulls them without a full sync. When the last sync skipped
  detections (for example a missing *Alerts: Read* scope), the reason is shown on the page.
- **Attack surface → Subnets & VLANs** (`/subnets/`) groups every known asset in one of three ways:
  - by subnet, from /16 to /28;
  - by the default gateway CrowdStrike reports (agents behind one gateway share a layer-2 segment, i.e. a VLAN; assets
    without an agent take the gateway most agents in their /24 use);
  - by a VLAN column in an inventory (any column whose name contains "VLAN").

  For each segment it shows assets, EDR coverage, feasible assets without EDR, internet-exposed assets, critical / high vulns,
  LOBs (and segments shared by several LOBs), node types and gateways. Expand a row to see its assets. Asset 360 → Related
  shows the asset's own subnet with a link here.

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
- **Spotlight vulnerabilities** (CrowdStrike → Spotlight vulnerabilities, `/spotlight/`): what CrowdStrike's own agent reports
  (needs the *Vulnerabilities: Read* scope). It is a separate, read-only section. Spotlight findings are never added to the
  VA-scan findings, so vulnerability counts, risk scores and the Overview do not change.
  - The Findings, By CVE and By host tabs can be filtered by severity, ExPRT rating, exploit available, LOB and search.
  - The **In VA scan** column shows whether the VA scan reports the same CVE on that connection IP; "Spotlight only" lists the
    gaps. Each view can be exported to Excel.
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

## Internet exposure

An asset is internet-exposed when an inventory facing / zone / public-IP column, a VA scan of a public IP, or an inbound
Internet / ISP rule in the communication matrix says so, or its own IP is public and comes from an inventory, the NIAM dump or a scan.
**Shadow exposure** (Internet exposed → Shadow exposure tab) lists public IPv4s the communication matrix does not account for:
- ports a VA scan found open on a public IP that no inbound rule allows;
- public CrowdStrike connection IPs that no inbound rule covers at all;
- known IPs inside the **Shadow ranges** you add on that tab (e.g. your own public ranges) that no inbound rule covers.

Each row says what saw it (VA scan / CrowdStrike connection IP / shadow range). Whitelisted, CGNAT and indirect-range addresses are left out.
The same applies to exposure: a public connection IP makes the asset internet exposed unless it is whitelisted, CGNAT or in an
indirect range.

**Internet DB scan (passive)** (Vulnerability → Internet DB scan) looks public IPs up in **Shodan InternetDB**
(`internetdb.shodan.io`, free, no API key). It returns the open ports, known CVEs, software (CPE), hostnames and tags that
internet-wide scanning already recorded. Nothing is sent to the assets themselves; only the public IP is sent to Shodan.
- **Scan one IP now** on the page, or **Scan now** on Asset 360 → Exposure.
- **Scan an Excel file:** any layout; the column with the most IPs is pre-selected.
- **All inventory:** tick rows → **Passive scan**.

Private IPs are looked up through the public / NAT IP the console knows for them; without one they are skipped, with the reason. Jobs
run in the background (4 lookups at a time, with back-off when rate-limited). Open ports found count as internet-exposure evidence
("Passive scan"). Results export to Excel. The server needs outbound HTTPS to internetdb.shodan.io (a corporate proxy set in
`HTTPS_PROXY` is honoured). Sample mode simulates the answers.

**Attack surface** (left menu → Attack surface) lists every public IPv4 the console knows. Sources: inventory own / Public / NAT IP,
communication matrix, CrowdStrike public connection IPs, VA scans, passive scans and *Your ranges*. The IPs are grouped by /24 and by
the **advertised BGP prefix**.
- **Look up prefixes:** RIPEstat (free, no key) returns each IP's prefix, origin ASN and holder; GreyNoise community returns whether
  the IP is seen scanning the internet.
- **Your ASNs:** mark the ASNs that are yours, and *Advertised by your ASNs* lists every prefix they announce. The prefixes are
  fetched from RIPEstat automatically when an ASN is added and refreshed in the background once they are more than a week old;
  removing an ASN drops its prefixes. Prefixes with no known
  IP are uninventoried public space. Do not mark your ISP's ASN if your IPs are ISP-provided.
- **Scan all public IPs:** runs InternetDB on the whole surface; any advertised prefix up to /20 can be scanned to find exposed IPs
  nobody listed.
- The Internet DB scan page sits in the same menu section.

**Internet intelligence for any public IP:** Asset 360 → Internet scan, or a public IP searched in Asset 360 that no source knows. One card
combines four sources:
- **Shodan InternetDB:** ports, CVEs, software, hostnames (no key).
- **VirusTotal:** vendors flagging the IP, reputation, owner, country. Needs a free VirusTotal API key, entered under Integrations;
  free tier is 4 lookups a minute and 500 a day.
- **GreyNoise:** seen scanning the internet / benign service (no key).
- **RIPEstat:** advertised prefix, ASN, holder (no key).

Links open the IP on Shodan (`https://www.shodan.io/search?query=<ip>`), VirusTotal, Censys and GreyNoise. Answers are cached;
*Look up again* refreshes them.

**Alerts** (Leadership & SOC → Alerts) shows recent alerts in one feed, linked to the asset each one concerns (name, IP, LOB, internet
exposure), with filters and an Excel export:
- CrowdStrike (stored on sync)
- Splunk Enterprise Security notables (asked live, cached for a minute)
- Seceon NDR (webhook / uploads)

A **Sources** strip shows, per source, whether it is set up, how many alerts are stored and when they were last fetched. When a source
is empty it gives the reason: not connected, no sync yet, the last sync's error (e.g. a missing Alerts: Read scope), or no Seceon alert
received. **Fetch CrowdStrike alerts now** pulls alerts without a full sync and shows the exact error if it fails.

**Passive scan speed:** InternetDB answers in about 0.1–0.3 s per IP. Lookups now reuse one HTTPS connection per worker (no TLS
handshake per IP) and run 16 at a time. A single-IP scan returns at once while exposure is recomputed in the background.

**IPv6:** a global IPv6 address is **not** exposure evidence on its own, since IPv6 has no NAT and most addresses are global. An IPv6 asset is
exposed only when one of these says so:
- a communication-matrix row (inbound rule, NAT list, pool, register, source NAT)
- an inventory Internet Facing / Public IP column
- the Mark exposed list

The "own public IP", "VA scan of a public IP", "CrowdStrike connection IP" and "shadow port" checks apply to IPv4 only.

**NAT counts:** a host that is destination-NATed from a public IP, or source-NATed to one, is internet exposed. This holds for matrix rows
and for inventory Public / NAT IP columns, even when many hosts share the one NAT IP. Every host is linked to its public IP.

Searching a public / NAT IP in Asset 360 lists the hosts behind it:
- from the matrix and inventory NAT mappings;
- plus CrowdStrike agents whose external (egress) IP it is.

An agent's external IP is used for this lookup and for matching only, not as exposure evidence: every agent has one.

**Offline** on CrowdStrike assets (and the Overview link) is offline in the console **plus EDR history**: agents that left the console,
one per device. That is the same definition as the Offline count. A switch splits the view: All offline · In the console · EDR history.

**CrowdStrike assets are identified by their connection IP only**. This covers inventory matching (current connection IP, then earlier
connection IPs plus the same hostname), All inventory, NIAM, VA-scan linking, search, IP ranges and lookups. The local IP is shown on
the agent but not used. Old-EDR imports use their single IP as the connection IP.

**CrowdStrike assets are listed under their connection IP**: the interface the agent reaches the CrowdStrike cloud from. The local IP is
used only when there is no connection IP. An agent already matched to an inventory node stays on that node's row.
- A **public IPv4 connection IP** is exposure evidence ("CrowdStrike · connection IP").
- The **local IP** is never exposure evidence.
- The **external IP** (public egress / NAT address seen by the cloud) is never exposure evidence.

Not counted as exposed:
IPs / subnets on the **whitelist** (Internet exposed → Whitelist), and **CGNAT** addresses (100.64.0.0/10), which have their own tab.

### Communication matrix workbooks

One workbook may hold several sheets of different kinds. The upload lists every sheet. For each sheet you pick its **type**, header row and which columns map to the template fields. Every row keeps its workbook and sheet name.

| Type | Typical columns | Internet-facing when |
|---|---|---|
| Firewall rules | Name · Source Zone · Source Address · Destination Zone · Destination Address · Service/Port · Application owner | source is Internet / ISP / untrust / outside / any, or a public IP |
| Public IP pool | S.No · Public IP pool · Use · Application · Application owner | always (our public IPs) |
| Public ↔ private (NAT) | S.No · Public IP · Private IP · Application · Owner · Which firewall exposes it | a public IP is listed |
| SOD / NAT rules | SODdetails · dest_nat_ip · destination_ip · fwl · location · nat_ip · port · protocol · rule · source_ip | a public IP is listed |
| Exposure register | Public IP · Internal IP · Port · Service details · Destination IP · LOB · Domain · MS Partner · Service owner · Firewall | a public IP is listed |

The type is guessed from the headers and can be changed. A new upload replaces the earlier rows of the same workbook, or the whole matrix if chosen.

- **Template:** Communication matrix → Template downloads a workbook with one example sheet per type and a How to fill sheet (`/api/comm/template`).
- **Page tabs:**
  - Rows: one view for every sheet type; each source / public / destination / port cell is split into separate chips, and small ranges are expanded.
  - IPs: the matrix IP register.
  - Sheets: every workbook / sheet with its rows and internet-facing count. Delete a sheet or a whole workbook; exposure is recomputed.
- **Mark internet-facing by hand:** click the Internet badge on a row. The mark is stored per workbook / sheet / row and survives re-uploads; "Back to automatic" removes it.
- **Internet exposed page:**
  - "Exposed by" column: the source of each exposure (Inventory · LOB, Matrix · sheet, VA scan, Public IP, Manual · note). The full evidence is in the tooltip.
  - "Mark exposed" list: IPs, ranges or subnets you know are exposed, with a note saying where from (e.g. MP firewall export).
  - The whitelist and indirect-range lists accept the same address formats.

**Address cells** (`app/addrparse.py`):
- single IPs, and lists separated by `,` `;` `|` `/`, spaces or new lines
- ranges: `10.1.1.10-10.1.1.20` or `10.1.1.10-20`
- subnets: `10.1.0.0/24`
- last-octet shorthand: `10.1.55.194/195/200/201`
- object prefixes and suffixes: `h-10.1.1.5`, `n-10.1.0.0/24`, `10.1.1.5_nat`, `10.1.1.5_vm`
- IPv6: `2101:3900:3d5a::/48`
- host / object names, matched to inventory and CrowdStrike hostnames
- `any`

After an IPv4 address, `/N` is a prefix length when N ≤ 24, or N ≤ 32 on a network boundary. Otherwise it is last-octet shorthand.

**Port cells:** `443`, `80,443`, `8000-8100`, `tcp/443`, `443/tcp`, `tcp_8443`, `udp-53`, `dns_tcp`, `https`, `any`. Service names map to their well-known ports.

**Matching:** an internet-facing row exposes every asset whose IP is:
- its private / internal IP, or inside its subnet or range
- its public / NAT IP
- or whose host name it names

These assets get **Internet exposed = Yes** in LOB / all inventory and in CrowdStrike assets, with a filter and the evidence as a tooltip.

**Matrix IP register** (`/matrix-ips/`) lists every address in the matrix.

An address is **ours** when it is any of:
- a private / CGNAT / ULA address
- a public IP listed as a public / NAT / pool IP, or as the destination of an inbound rule
- a public IP found in inventory / scan / NIAM
- a name matching a known host

Each address has one or more roles:
- reached from internet
- public / NAT IP
- source NAT IP
- goes out to internet (source of a rule to any / internet zone / a public IP not ours)
- internet source
- internal

Views: ours & exposed, ours & talking to internet, our public IPs, exposed but not in inventory, unmatched names, external. Excel export.

### MBSS reports

Each Satellite host's latest OpenSCAP report is stored with **every** rule result (compliant / not compliant / not applicable), not only failures.
- **MBSS page:** compliance by control (fleet), failed rules, and by asset. Clicking an asset opens its report.
- **Report contents:** compliance ring, compliance per control, and a rule list filtered by result. Failed rules expand to their fix. Downloadable as Excel (summary, by control, all rules).
- Asset 360 → Patches & MBSS shows the same report.

Asset 360 tabs: Overview (status tiles only) · Inventory (records, NIAM) · Exposure · Internet scan (InternetDB, RIPEstat prefix / ASN,
GreyNoise, links to Shodan / Censys / GreyNoise / VirusTotal) · Attack path · Detections · Vulnerabilities (VA findings, CVEs seen
from the internet, SOD exceptions, scans) · Patches & MBSS · EDR & logging · Related assets (grouped by relation). The header links
every public IP of the asset to Shodan, Censys, GreyNoise and VirusTotal.

### Asset 360 layout

A compact header shows the asset, its risk score and the next action. Below it, tabs split the big features:
- Overview (status tiles, why this score, last seen by each source)
- Exposure
- Attack path
- Detections
- Vulnerabilities (+ SOD exceptions)
- Patches & MBSS
- EDR & logging
- Records (inventory, scans, NIAM, related assets)

The open tab is kept in the URL (`&view=`).

## Asset 360 and integrations

Asset 360 answers, for one IP / hostname / agent ID:
- EDR status and prevention policy;
- internet exposure: communication-matrix rules via which firewall / ISP, public IPs caught by the VA scan, and what
  CrowdStrike reports, plus a real-exposure check (ports open on a public IP that no inbound rule allows = shadow exposure);
- recent detections from CrowdStrike, Splunk (ES notables) and Seceon NDR, together or per source, with a date filter;
- SOD exceptions covering its findings and when they run out; "last known good" per source; related assets (same subnet,
  name family, public / NAT IP, matrix peers);
- vulnerabilities, each with the Satellite erratum that fixes it;
- open ports;
- Spotlight vs the VA scan, by CVE;
- Satellite packages, errata and MBSS failed rules;
- Splunk logging;
- inventory with its source.

*Evidence pack* downloads all of it as one workbook; *PDF* prints the page.

**Integrations** (System → Integrations) lists every source and what it needs:

| Integration | Needs | Feeds |
|---|---|---|
| CrowdStrike Falcon | Hosts: Read (required); Alerts: Read, Vulnerabilities: Read, Prevention policies: Read, Sensor update policies: Read (optional) | agents, detections, Spotlight, policies, sensor builds |
| Red Hat Satellite 6 | URL, read-only user + password / token with Viewer on hosts, content and compliance | packages, errata (installable = fix available), OpenSCAP MBSS |
| Splunk | management port (8089) reachable, token for a role with `search` on the host-log indexes and `index=notable` | log-source presence per host (live `tstats`), Enterprise Security notables as detections |
| ServiceNow CMDB | planned: instance URL, `cmdb_read` user, CI class | inventory records |
| Jaspersoft | planned: server URL, read-only user, report path (CSV) | inventory records |
| Seceon NDR | webhook: Seceon POSTs alerts to `/api/seceon/webhook` with the `X-Webhook-Token` generated on the page; or an alert export upload (template "Seceon NDR alerts") | network detections per IP |

**Patch & MBSS** (left menu): Satellite hosts with fixes waiting, errata across the fleet, and MBSS compliance by rule
(which assets fail each point, with the fix) and by asset (each asset's failed points by control).

**Internet exposed** has four tabs:
- *Directly exposed*.
- *Indirectly exposed*: CGNAT 100.64.0.0/10, plus the telecom ranges you add under *Indirect ranges*. Every asset inside them is listed.
- *Shadow exposure*.
- *Whitelisted*.

## Leadership & SOC

- **Top riskiest assets** (`/top-risks/`): one additive score per asset, with every point explained. The factors are:
  - internet exposure (+25) or indirect exposure (+8), and shadow ports
  - no EDR (+25) or EDR offline (+10)
  - critical, high and exploitable vulnerabilities
  - CrowdStrike detections and Seceon NDR alerts in the date range
  - failed MBSS rules and uninstalled security errata (Satellite)
  - weak internal assets it can reach through the communication matrix
  - Non Live nodes count half

  Each asset gets a next action. Filters: date range, LOB, top 10/25/50/100, exposed only. Excel export.
- **Attack paths** (`/attack-paths/`): each internet-exposed asset is an entry point. The communication matrix's active Allow rules (explicit source match) show what it can reach in 1 or 2 hops. A target is weak if it has a critical vulnerability or no EDR. Destinations wider than 4,096 addresses are listed as a note, not drawn. Three tabs:
  - **Paths**: an entry list plus a graph (Internet → entry → hop 1 → hop 2). Hover a node to trace its paths with ports; click it for details. The single "most dangerous path" is shown as numbered steps.
  - **Choke points**: internal assets that paths from many entry points pass through, with the weak assets behind them.
  - **Rules to tighten**: matrix rules ranked by the weak assets they open.
- **Asset 360 header**: the same explained risk score and next action as Top riskiest assets, then eight status tiles. Each tile jumps to its section or tab:
  - EDR, Internet, Vulnerabilities, Detections (7 days)
  - Patches, MBSS, SIEM logging, Blast radius

  A sticky section menu follows. An "Attack path & blast radius" card shows what the asset can reach and which exposed assets can reach it (`/api/asset/posture`, `/api/attack-paths/detail`).
- **Analyst workload** (`/analysts/`): alerts per analyst in a date range (and severity), with drill-down to the alerts:
  - CrowdStrike: from the Alerts API `assigned_to_name`; time to close is the median of `updated_timestamp - created_timestamp` on closed alerts.
  - Splunk ES notables: by `owner`, from the `` `notable` `` macro; average time to close uses `review_time`.

  Names are merged case-insensitively. Excel export.

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
- **EDR verification**: each current row is matched to a Falcon agent in this order:
  1. the node IP is the agent's **connection IP**: match, the IP alone is enough;
  2. the node IP is another **NIC IP** of the agent (local IP / IP history): match only if the **hostname** is the same too
     (case-insensitive; the domain part is ignored, so `HOST.corp.local` = `host`);
  3. the same hostname with no IP in common: match;
  4. **through NAT**: the node IP is a public / NAT IP, and exactly one active agent sits behind it → match (`nat ip`). "Behind" means:
     - the agent's connection / NIC IP is the private IP mapped to that public IP (matrix NAT / source-NAT rows, inventory Public / NAT IP columns);
     - or the agent reports that public IP as its external IP.

     The other direction works too: the node lists the private IP and the agent reports the public one. When several agents share
     the NAT IP, only a hostname match (step 3) links them;
  5. a NIC IP plus a hostname that is only close (`abc` ↔ `abc1`, and no other `abc<n>` exists in CrowdStrike or the inventories;
     `MNRA` vs `MNRA1` / `MNRA2` / `MNRA3` is rejected): **not** a match. It is listed on **CrowdStrike → Possible matches** for review
     and counted nowhere.
  A NIC IP on a differently named agent is shown as "IP Used by Other Host" and never counted as installed.
- **Large uploads (1 lakh rows)**: the new version is saved and confirmed in seconds. Uploads over 5,000 rows then re-match with
  CrowdStrike and recompute exposure and risk **in the background**. The top bar shows "Matching … inventory rows" and pages refresh by
  themselves when it ends.
- **Large exports**: Excel files are written with XlsxWriter. A single list of more than ~600,000 cells (e.g. 1 lakh rows × 6+ columns)
  downloads as CSV, which opens in Excel and is several times faster.
- **All inventory → select and delete**: tick rows (or a whole page) and use *Delete selected*.
  - Rows that come from a LOB inventory are removed from it (current version; logged in the item history as "deleted by hand").
  - Every selected row leaves All inventory and every count.
  - *Deleted rows* lists them, with Restore.

  The **Found in** filter shows only assets from a LOB inventory, CrowdStrike, a VA scan or NIAM.
- **Workbooks with several sheets**: the upload lists every sheet and pre-ticks the ones that look like inventory (an IP or node-name
  column is found). Tick or untick sheets, then click a sheet to set its header row and map its columns; each sheet keeps its own
  mapping. The ticked sheets become **one** new version, and every row keeps its sheet name in an extra "Sheet" column. When two sheets
  share a key, an exact copy is merged and a different row is kept.
- **Same IP on several rows**: every row is kept. The second row's key adds its node name, and all of them are tagged under Duplicates.
  Only exact copies of a row are merged.
- **NIAM Integrated / NE ID columns** (standard template): when filled, they are what the console shows and counts for the node. When
  blank, NIAM integrated = the IP is in the latest NIAM dump, and NE ID = the dump's NE ID(s) for the IP. The inventory table marks the
  source (inv / dump). A "Yes" from the inventory whose IP is not in the dump shows amber.
- **Editing values**: "EDR installed (inventory)", "Live / Non Live", "EDR feasible (inventory)" and Remarks can be changed in the
  table, or for many rows at once with *Edit a column in Excel* (download one column for the filtered rows, change it, upload it back).
  Edits are logged in the item history; the next inventory upload for the LOB replaces them.
- The inventory's "EDR Installed" value is treated as a claim and compared with reality:
  `Verified`, `Installed - Inactive`, `Claimed - Not Found`, `Claimed - Removed from Console`, `Installed - Marked No`,
  `Installed - Marked Not Feasible`, `Pending Install`, `Not Feasible`.
- The inventory fields (LOB, node type, live, feasible, installed, remarks) also appear as columns in the host views.

## Pages
Overview · All assets · IP & NIC search (exact, prefix, CIDR, hostname) · Bulk lookup (paste IPs/hostnames) · Offline & stale ·
Duplicates · New installs (per day/week/custom range, reinstall tag) · Activity log · LOB inventory · Coverage gaps · Templates ·
Reports (one-click executive workbook plus 14 exports) · Sync & settings. Press **⌘K / Ctrl+K** anywhere to jump to a host, IP or page.
