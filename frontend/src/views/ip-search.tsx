"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, ArrowUpRight, Network, Radar, RefreshCw, Copy, Crosshair, Download, FileSpreadsheet, Globe2, History, LayoutGrid, Logs, PackageCheck, Printer, Route, Search, Server, ShieldAlert, ShieldCheck, ShieldX, ClipboardCheck, Waypoints } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, Loading, PageHeader, SearchInput, Segmented, Tabs } from "@/components/ui";
import { MbssReport } from "@/components/mbss-report";
import { IocChecker } from "@/components/ai/ioc";
import { ExplainButton } from "@/components/ai/brief";

const db_is_value = (q: string) => /^[a-f0-9]{32,64}$/i.test(q) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q);
import { IntelPanel, LOOKUPS } from "@/components/intel-panel";
import { CveChips, PortChips } from "./passive-scan";
import { SimpleTable } from "@/components/data-table";
import { PathView } from "./attack-paths";
import { toast } from "sonner";
import { CoverageBadge, EdrBadge, HostLink, Live, Mono, SevCounts, SeverityBadge, When, YN, removalLabel, RiskBadge, FeasibleBadge, OsCell } from "@/components/badges";

export default function AssetSearch() {
  const [state, set] = useUrlState();
  const q = (state.q || "").trim();
  const { data: r, isFetching, error, refetch } = useQuery({ queryKey: ["asset", q], queryFn: () => api<any>("/api/asset", { params: { q } }), enabled: !!q });
  return (
    <div>
      <PageHeader title="Asset 360"
        sub="Everything about one asset: search an IP, hostname (or part of one), agent ID, prefix or CIDR. Any public IP also shows what the internet knows about it." />
      <div className="flex flex-wrap gap-2">
        <SearchInput big autoFocus className="min-w-[260px] flex-1" value={q} onChange={(v) => set({ q: v })} placeholder="10.20.34.17  ·  2001:db8::17  ·  CORP-WS-0369  ·  NE ID  ·  10.20.34.  ·  10.20.0.0/16  ·  agent ID" />
        <Button className="h-11" disabled={!q} onClick={() => downloadExcel("/api/asset/export", { q })}
          title={r?.mode === "single" ? "Everything on this page in one workbook, for audits and incident tickets" : "Download the list"}>
          {r?.mode === "single" ? <><FileSpreadsheet /> Evidence pack</> : <><Download /> Excel</>}</Button>
        {r?.mode === "single" && (publicIps(r).length > 0 || (!r.summary.found && isPublicV4(q))) && <RescanButton ips={publicIps(r).length ? publicIps(r) : [q]} />}
        {r?.mode === "single" && <Button className="h-11 print:hidden" onClick={() => window.print()} title="Print or save this page as PDF"><Printer /> PDF</Button>}
      </div>
      {!q && (
        <Card className="mt-5 p-8 text-center text-muted">
          <Search className="mx-auto mb-2 size-8 opacity-60" />
          Search combines Falcon (live, removed and old EDR imports), every LOB inventory, vulnerability scans and the NIAM dump.
        </Card>
      )}
      {q && !r && <Loading error={error} retry={() => refetch()} />}
      <div className={cn("transition-opacity", isFetching && "opacity-70")}>
        {r?.mode === "range" && <RangeView r={r} q={q} />}
        {r?.mode === "single" && <Profile r={r} />}
      </div>
    </div>
  );
}

function RangeView({ r, q }: { r: any; q: string }) {
  const [, set] = useUrlState();
  const count = (st: string) => r.rows.filter((x: any) => x.edr_status === st).length;
  return (
    <Card className="mt-5">
      <CardHeader title={r.by_nat ? `${fmtN(r.total)} hosts behind public / NAT IP ${r.by_nat}` : r.by_name ? `${fmtN(r.total)} assets whose name contains “${q}”` : `${fmtN(r.total)} assets in ${q}`}
        hint={`${fmtN(count("Online"))} online · ${fmtN(count("Offline"))} offline · ${fmtN(r.rows.filter((x: any) => !["Online", "Offline"].includes(x.edr_status)).length)} without active EDR`} />
      <SimpleTable rows={r.rows} maxHeight="calc(100vh - 320px)" empty="Nothing found in this range" onRowClick={(x: any) => set({ q: x.ip })} columns={[
        { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
        { key: "hostname", label: "Host", render: (x: any) => x.hostname || x.node_name || <span className="text-muted">–</span> },
        { key: "risk", label: "Risk", render: (x: any) => x.risk === null || x.risk === undefined ? <span className="text-muted">–</span> : <b className={x.risk >= 60 ? "text-crit-fg" : x.risk >= 35 ? "text-serious-fg" : ""}>{x.risk}</b> },
        { key: "ne_ids", label: "NE ID", render: (x: any) => x.ne_ids || <span className="text-muted">–</span> },
        { key: "edr_status", label: "EDR", render: (x: any) => <EdrBadge s={x.edr_status} /> },
        { key: "lobs", label: "LOB" }, { key: "msps", label: "MSP" },
        { key: "in_inventory", label: "Inventory", render: (x: any) => x.in_inventory ? "Yes" : <span className="text-muted">No</span> },
        { key: "v", label: "Crit / High / Med / Low", render: (x: any) => <SevCounts c={x.crit} h={x.high} m={x.med} l={x.low} /> },
        { key: "last_scan", label: "Last scan", render: (x: any) => x.last_scan ? fmtDt(x.last_scan) : <span className="text-muted">Never</span> },
        { key: "last_seen", label: "EDR last seen", render: (x: any) => x.last_seen ? <When ts={x.last_seen} /> : "–" },
      ]} />
    </Card>
  );
}

const VIEWS: { id: string; label: string; icon: React.ElementType }[] = [
  { id: "overview", label: "Overview", icon: LayoutGrid }, { id: "inventory", label: "Inventory", icon: Server },
  { id: "exposure", label: "Exposure", icon: Globe2 }, { id: "matrix", label: "Communication matrix", icon: Waypoints },
  { id: "internet", label: "Internet scan", icon: Radar },
  { id: "attack", label: "Attack path", icon: Route }, { id: "detections", label: "Detections", icon: Crosshair },
  { id: "vulns", label: "Vulnerabilities", icon: ShieldAlert }, { id: "patching", label: "Patches & MBSS", icon: PackageCheck },
  { id: "edr", label: "EDR & logging", icon: ShieldCheck }, { id: "related", label: "Related assets", icon: Network },
  { id: "ioc", label: "Threat intel (IOC)", icon: Crosshair },
];

function Profile({ r }: { r: any }) {
  const s = r.summary;
  const [state, set] = useUrlState();
  const view = VIEWS.some((v) => v.id === state.view) ? state.view : "overview";
  const go = (v: string) => { set({ view: v === "overview" ? undefined : v }); window.scrollTo({ top: 0, behavior: "smooth" }); };
  const { data: p } = usePosture(s, r);
  if (!s.found) return isPublicV4(s.query) ? (
    <div className="mt-5 space-y-3">
      <Card className="flex flex-wrap items-center gap-2 px-4 py-3 text-[13px]"><Badge tone="violet">Not a known asset</Badge>
        <span className="text-muted">{s.query} is in no inventory, CrowdStrike, VA scan, NIAM dump or communication matrix. Here is what the internet knows about it.</span></Card>
      <IntelPanel ip={s.query} showAsset />
    </div>
  ) : <Card className="mt-5 p-8 text-center text-muted">Nothing found for “{s.query}” in CrowdStrike, any inventory, vulnerability scan, the NIAM dump or the communication matrix.</Card>;
  const v = s.vulns;
  const badge: Record<string, React.ReactNode> = {
    exposure: r.internet?.verdict === "exposed" ? <Dot tone="crit" /> : null,
    matrix: r.flows?.length ? <Count n={r.flows.length} tone={r.flows.some((f: any) => f.inbound_internet) ? "crit" : "neutral"} /> : null,
    attack: p?.blast?.weak ? <Count n={p.blast.weak} tone="crit" /> : null,
    detections: p?.det && (p.det.n + (p.ndr?.n || 0)) ? <Count n={p.det.n + (p.ndr?.n || 0)} tone={p.det.high ? "crit" : "warn"} /> : null,
    vulns: v.Critical + v.High ? <Count n={v.Critical + v.High} tone={v.Critical ? "crit" : "warn"} /> : null,
    patching: p?.sat?.compliance_failed || p?.sat?.installable_security ? <Dot tone="warn" /> : null,
    edr: s.edr_status !== "Online" ? <Dot tone={s.edr_status === "Offline" ? "warn" : "crit"} /> : null,
  };
  return (
    <div className="mt-4 space-y-4">
      <Hero s={s} r={r} />
      <nav className="sticky top-13 z-10 flex gap-0.5 overflow-x-auto border-b border-border bg-bg/90 backdrop-blur scroll-thin print:hidden">
        {VIEWS.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => go(id)}
            className={cn("relative flex shrink-0 items-center gap-1.5 px-3 py-2.5 text-[13px] font-medium transition-colors",
              view === id ? "text-accent-fg after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full after:bg-accent" : "text-fg-2 hover:text-fg")}>
            <Icon className="size-4" />{label}{badge[id]}
          </button>
        ))}
      </nav>
      {view === "overview" && <PostureTiles s={s} r={r} go={go} />}
      {view === "inventory" && <InventoryView s={s} r={r} />}
      {view === "internet" && <InternetScanView s={s} r={r} />}
      {view === "exposure" && <div className="space-y-4"><InternetSection i={r.internet} />
        {r.behind_nat?.length > 0 && <RangeView r={{ rows: r.behind_nat, total: r.behind_nat.length, by_nat: s.ips[0] }} q={s.ips[0]} />}<Card><CardHeader title="Open ports" hint="from vulnerability scan findings" /><PortsTable rows={r.ports || []} /></Card></div>}
      {view === "matrix" && <MatrixFlows rows={r.flows || []} />}
      {view === "attack" && <AttackCard s={s} r={r} />}
      {view === "detections" && <DetectionsSection agents={r.agents} ips={s.ips} names={s.hostnames} />}
      {view === "vulns" && <div className="space-y-4"><Card><CardHeader title="Vulnerabilities" hint={`${v.Critical} critical · ${v.High} high · ${v.Medium} medium · ${v.Low} low open · ${fmtN(v.fixed)} fixed`} /><VulnTable rows={r.vulns} /></Card>
        <PassiveCves s={s} go={go} /><ExceptionsCard s={s} agents={r.agents} /><ScansCard rows={r.scans} /></div>}
      {view === "patching" && <Card><SatellitePanel ips={s.ips} names={s.hostnames} /></Card>}
      {view === "edr" && <EdrView s={s} r={r} />}
      {view === "related" && <RelatedView s={s} r={r} />}
      {view === "ioc" && <div className="space-y-2"><div className="text-[12.5px] text-fg-2">Checks this asset's IPs against CrowdStrike threat intelligence, custom IOCs and our data. Paste any other IP, domain or hash too.</div>
        <IocChecker key={s.ips.join(",")} initial={[...s.ips, ...(db_is_value(s.query) ? [s.query] : [])].filter((x, i, a) => a.indexOf(x) === i).join("\n")} autoRun compact /></div>}
    </div>
  );
}

const Dot = ({ tone }: { tone: string }) => <span className={cn("size-1.5 rounded-full", tone === "crit" ? "bg-crit" : "bg-warn")} />;
const Count = ({ n, tone }: { n: number; tone: string }) => (
  <span className={cn("rounded-full px-1.5 text-[10.5px] font-semibold", tone === "crit" ? "bg-crit-soft text-crit-fg" : "bg-warn-soft text-warn-fg")}>{n}</span>
);

function EdrView({ s, r }: { s: any; r: any }) {
  return (
    <div className="space-y-4">
      <Card><CardHeader title="CrowdStrike agents" hint={`${r.agents.length} agent(s) seen for this asset`} /><AgentsTable rows={r.agents} /></Card>
      <Card><CardHeader title="Prevention policy & Spotlight" hint="CrowdStrike's own view of this host" /><CrowdStrikePanel agents={r.agents} ips={s.ips} /></Card>
      <Card><CardHeader title="SIEM logging (Splunk)" hint="is this host sending logs?" /><SplunkPanel names={s.hostnames} ips={s.ips} /></Card>
    </div>
  );
}

function VulnTable({ rows }: { rows: any[] }) {
  return <SimpleTable rows={rows} maxHeight="65vh" empty="No findings for this asset" columns={[
    { key: "severity", label: "Severity", render: (x: any) => <SeverityBadge s={x.severity} /> },
    { key: "name", label: "Vulnerability", wrap: true, render: (x: any) => <Link className="font-medium hover:underline" href={`/vulnerabilities/?vtab=findings&ip=${x.ip}&status=${x.status === "fixed" ? "fixed" : ""}`}>{x.name}</Link> },
    { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
    { key: "port", label: "Port", render: (x: any) => `${x.port || ""}${x.protocol ? "/" + x.protocol : ""}` },
    { key: "cve", label: "CVE", wrap: true, render: (x: any) => <span className="text-[12px]">{x.cve}</span> },
    { key: "first_discovered", label: "First seen", render: (x: any) => fmtDt(x.first_discovered).slice(0, 10) },
    { key: "fix", label: "Fix available", render: (x: any) => x.fix?.length ? <span className="inline-flex flex-wrap gap-1">{x.fix.map((e: any) =>
      <Badge key={e.id} tone={e.installable ? "good" : "neutral"} title={e.installable ? "Installable now from Satellite" : "Erratum exists; not yet installable (content view / repo)"}>{e.id}</Badge>)}</span> : <span className="text-muted">–</span> },
    { key: "status", label: "Status", render: (x: any) => x.status === "fixed" ? <span className="text-good-fg">Fixed</span> : "Open" },
  ]} />;
}

function PortsTable({ rows }: { rows: any[] }) {
  return <SimpleTable rows={rows} maxHeight="50vh" empty="No ports seen — ports come from vulnerability scan findings" columns={[
    { key: "port", label: "Port", render: (x: any) => <b className="font-mono">{x.port}/{(x.protocol || "").toLowerCase()}</b> },
    { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
    { key: "max_severity", label: "Worst open finding", render: (x: any) => x.max_severity ? <SeverityBadge s={x.max_severity} /> : <span className="text-muted">none open</span> },
    { key: "open_findings", label: "Open findings", num: true },
    { key: "names", label: "Vulnerabilities on this port", wrap: true, render: (x: any) => <span className="text-xs text-fg-2">{x.names.slice(0, 3).join(" · ")}{x.names.length > 3 ? ` +${x.names.length - 3}` : ""}</span> },
    { key: "last_observed", label: "Last observed", render: (x: any) => fmtDt(x.last_observed).slice(0, 10) },
  ]} />;
}

function AgentsTable({ rows }: { rows: any[] }) {
  return <SimpleTable rows={rows} empty="No CrowdStrike agent found" columns={[
    { key: "hostname", label: "Hostname", render: (x: any) => <HostLink aid={x.aid}><b>{x.hostname || x.aid}</b></HostLink> },
    { key: "edr_status", label: "Status", render: (x: any) => <span className="flex items-center gap-1.5"><EdrBadge s={x.edr_status} />{x.edr_detail && x.edr_detail !== "in console" && <span className="text-xs text-muted">{x.edr_detail}</span>}</span> },
    { key: "connection_ip", label: "Connection IP", render: (x: any) => <Mono>{x.connection_ip || x.local_ip}</Mono> },
    { key: "local_ip", label: "Local IP", render: (x: any) => <Mono>{x.local_ip}</Mono> },
    { key: "os_version", label: "OS" }, { key: "agent_version", label: "Sensor", render: (x: any) => <Mono>{x.agent_version}</Mono> },
    { key: "first_seen", label: "First seen", render: (x: any) => fmtDt(x.first_seen).slice(0, 10) },
    { key: "last_seen", label: "Last seen", render: (x: any) => <When ts={x.last_seen} /> },
  ]} />;
}

/* ---------------- Internet exposed: verdict and each method ---------------- */
const VERDICT_TXT: Record<string, [string, string]> = {
  exposed: ["crit", "Internet exposed"], whitelisted: ["neutral", "Whitelisted (not counted)"], cgnat: ["warn", "CGNAT only (not directly exposed)"],
  not_exposed: ["good", "Not exposed"],
};

function Method({ title, hit, children, none }: { title: string; hit: boolean; children?: React.ReactNode; none: string }) {
  return (
    <div className={cn("rounded-xl border p-3", hit ? "border-crit/40 bg-crit-soft/30" : "border-border")}>
      <div className="mb-2 flex items-center gap-2 text-[12.5px] font-semibold">{title}
        <Badge tone={hit ? "crit" : "neutral"} className="ml-auto">{hit ? "evidence" : "none"}</Badge></div>
      {hit ? children : <div className="text-[12px] text-muted">{none}</div>}
    </div>
  );
}

function InternetSection({ i }: { i: any }) {
  if (!i) return null;
  const [tone, label] = VERDICT_TXT[i.verdict] || VERDICT_TXT.not_exposed;
  const scanHit = i.scan.some((x: any) => x.scanned && !x.cgnat);
  return (
    <Card>
      <CardHeader title={<span className="inline-flex items-center gap-2"><Globe2 className="size-4" /> Internet exposed <Badge tone={tone as any}>{label}</Badge></span>}
        hint={i.public_ips.length ? `public / NAT IP ${i.public_ips.join(", ")}` : undefined}
        right={i.internal_ip && i.verdict !== "not_exposed" ? <Link className="text-[12.5px] text-accent-fg hover:underline print:hidden" href={`/attack-paths/?ip=${encodeURIComponent(i.internal_ip)}`}>Attack path →</Link> : undefined} />
      <div className="grid gap-3 px-4 pb-4 lg:grid-cols-3">
        <Method title="Communication matrix" hit={i.matrix.length > 0} none="No internet-facing or source-NAT matrix row covers this asset.">
          <div className="space-y-2">
            {i.matrix.map((m: any) => (
              <div key={m.rule_id} className="rounded-lg bg-surface px-2.5 py-2 text-[12px] shadow-card">
                <div className="flex items-center gap-2"><b>{m.rule_id}</b><Badge tone={m.path === "Source NAT" ? "warn" : "info"}>{m.path === "Source NAT" ? `source NAT → ${m.src_nat}` : m.path === "ISP link" ? `via ISP ${m.isp}` : `via firewall ${m.firewall}`}</Badge>
                  <span className="ml-auto text-muted">{m.action}</span></div>
                <div className="mt-1 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-fg-2">
                  <span className="text-muted">From</span><span>{m.src_zone || "–"} · <Mono>{m.src || "any"}</Mono>{m.src_nat ? <> (NAT <Mono>{m.src_nat}</Mono>)</> : null}</span>
                  <span className="text-muted">To</span><span>{m.dst_zone || "–"} · <Mono>{m.dst}</Mono>{m.dst_nat ? <> via public <Mono>{m.dst_nat}</Mono></> : null}</span>
                  <span className="text-muted">Service</span><span>{(m.protocol || "any").toUpperCase()} {m.ports || "any"}{m.service ? ` · ${m.service}` : ""}</span>
                  <span className="text-muted">Path</span><span>{[m.isp && `ISP ${m.isp}`, m.firewall && `firewall ${m.firewall}`, m.fw_rule && `rule ${m.fw_rule}`].filter(Boolean).join(" → ") || "–"}</span>
                  <span className="text-muted">Change</span><span>{m.cr || "–"}{m.valid_till ? ` · valid till ${m.valid_till}` : ""}</span>
                </div>
              </div>
            ))}
          </div>
        </Method>
        <Method title="VA scan of a public IP" hit={scanHit} none="No public IP of this asset appears in a vulnerability scan.">
          <SimpleTable rows={i.scan} columns={[
            { key: "ip", label: "Public IP", render: (x: any) => <span><Mono>{x.ip}</Mono>{x.cgnat && <Badge tone="warn" className="ml-1">CGNAT</Badge>}</span> },
            { key: "last_scan", label: "Scanned", render: (x: any) => x.scanned ? fmtDt(x.last_scan).slice(0, 10) : <span className="text-muted">no</span> },
            { key: "sev", label: "Open C/H/M/L", render: (x: any) => x.scanned ? <SevCounts c={x.crit} h={x.high} m={x.med} l={x.low} /> : null },
          ]} />
        </Method>
        <Method title="EDR (CrowdStrike)" hit={i.crowdstrike.some((x: any) => x.public_on_nic)} none="No agent connects from a public IP (connection IP is private).">
          <div className="space-y-1 text-[12px]">
            {i.crowdstrike.filter((x: any) => x.public_on_nic).map((x: any) => (
              <div key={x.aid}><b>{x.hostname}</b> connects to CrowdStrike from public IP <Mono>{x.connection_ip}</Mono> (its own interface)</div>
            ))}
          </div>
        </Method>
      </div>
      {i.crowdstrike.length > 0 && (
        <div className="border-t border-border px-4 py-3 text-[12px] text-fg-2">
          <span className="font-medium">What CrowdStrike reports:</span>{" "}
          {i.crowdstrike.map((x: any) => (
            <span key={x.aid} className="mr-4 inline-flex flex-wrap gap-x-2">
              <b>{x.hostname}</b> connection <Mono>{x.connection_ip || "–"}</Mono>{x.public_on_nic && <Badge tone="crit">public</Badge>}
              · local <Mono>{x.local_ip || "–"}</Mono> · egress <Mono>{x.external_ip || "–"}</Mono>
              {x.egress_public && <span className="text-muted">(organisation NAT, not exposure on its own)</span>}
            </span>
          ))}
        </div>
      )}
      {i.inventory.length > 0 && (
        <div className="border-t border-border px-4 py-3 text-[12px] text-fg-2"><span className="font-medium">Inventory says:</span> {i.inventory.map((e: any) => e.text).join(" · ")}</div>
      )}
      {i.ports?.length > 0 && (
        <div className="border-t border-border px-4 py-3">
          <div className="mb-2 flex items-center gap-2 text-[12.5px] font-semibold">Real exposure check: ports the VA scan saw on the public IP vs the matrix
            {i.shadow > 0 ? <Badge tone="crit">{i.shadow} shadow port{i.shadow > 1 ? "s" : ""}</Badge> : <Badge tone="good">all covered by a rule</Badge>}</div>
          <SimpleTable rows={i.ports} columns={[
            { key: "ip", label: "Public IP", render: (x: any) => <Mono>{x.ip}</Mono> },
            { key: "port", label: "Port", render: (x: any) => <b className="font-mono">{x.port}/{x.protocol}</b> },
            { key: "open", label: "Open findings", num: true },
            { key: "names", label: "Findings", wrap: true, render: (x: any) => <span className="text-[12px] text-fg-2">{x.names.join(" · ")}</span> },
            { key: "rules", label: "Allowed by", render: (x: any) => x.shadow ? <Badge tone="crit" title="Reachable from the internet but no inbound rule allows it: undocumented exposure">Shadow — no rule</Badge>
              : <span className="text-[12px]">{x.rules.join(", ")}</span> },
          ]} />
        </div>
      )}
    </Card>
  );
}

/* ---------------- Recent detections with a date filter ---------------- */
const SEV_TONE: Record<string, any> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Informational: "neutral" };
const dayStr = (d: Date) => d.toISOString().slice(0, 10);

function DetectionsSection({ agents, ips, names }: { agents: any[]; ips: string[]; names: string[] }) {
  const today = React.useMemo(() => new Date(), []);
  const [range, setRange] = React.useState({ from: dayStr(new Date(today.getTime() - 7 * 864e5)), to: dayStr(today) });
  const [src, setSrc] = React.useState("all");
  const aids = agents.map((a) => a.aid).join(",");
  const hn = names.join(",");
  const ip = ips.join(",");
  const cs = useQuery({ queryKey: ["det-cs", aids, hn, range], enabled: !!(aids || hn),
    queryFn: () => api<any>("/api/asset/detections", { params: { aids, hostnames: hn, from: range.from, to: range.to } }) });
  const sp = useQuery({ queryKey: ["det-splunk", hn, ip, range], queryFn: () => api<any>("/api/asset/splunk/detections", { params: { hosts: hn, ips: ip, from: range.from, to: range.to } }) });
  const nd = useQuery({ queryKey: ["det-ndr", ip, hn, range], queryFn: () => api<any>("/api/asset/ndr", { params: { ips: ip, hosts: hn, from: range.from, to: range.to } }) });
  const norm = (rows: any[] | undefined, source: string, map: (x: any) => any) => (rows || []).map((x) => ({ source, ...map(x) }));
  const csRows = norm(cs.data?.rows, "CrowdStrike", (x) => ({ at: x.created_at, severity: x.severity, name: x.name, detail: [x.tactic, x.technique].filter(Boolean).join(" · "),
    where: x.hostname, extra: x.filename, action: x.disposition, status: x.status }));
  const spRows = norm(sp.data?.rows, "Splunk", (x) => ({ at: x.created_at, severity: x.severity, name: x.name, detail: x.category,
    where: [x.src && `src ${x.src}`, x.dest && `dest ${x.dest}`, x.host].filter(Boolean).join(" · "), extra: "", action: "notable event", status: x.status }));
  const ndRows = norm(nd.data?.rows, "Seceon NDR", (x) => ({ at: x.created_at, severity: x.severity, name: x.name, detail: x.category,
    where: `${x.src_ip || "?"} → ${x.dst_ip || "?"}`, extra: x.direction ? `this host is the ${x.direction}` : "", action: x.source === "webhook" ? "pushed by Seceon" : "uploaded", status: x.status }));
  const all = [...csRows, ...spRows, ...ndRows].sort((a, b) => String(b.at).localeCompare(String(a.at)));
  const shown = src === "all" ? all : src === "cs" ? csRows : src === "splunk" ? spRows : ndRows;
  const quick = (days: number) => setRange({ from: dayStr(new Date(today.getTime() - days * 864e5)), to: dayStr(today) });
  const input = "h-8 rounded-lg border border-border-strong bg-surface px-2 text-[12.5px]";
  const busy = cs.isFetching || sp.isFetching || nd.isFetching;
  const note: Record<string, React.ReactNode> = {
    cs: !agents.length ? "No CrowdStrike agent on this host." : cs.data?.fetched_at ? `fetched ${fmtRel(cs.data.fetched_at)} (Alerts API, every sync)` : "",
    splunk: sp.data && !sp.data.configured ? <>Splunk not connected — <Link className="text-accent-fg hover:underline" href="/connectors/">Integrations</Link></> : sp.data?.error || (sp.data?.simulated ? "sample data: simulated" : "Splunk ES notable events"),
    ndr: nd.data && !nd.data.configured ? <>No Seceon alerts received yet — <Link className="text-accent-fg hover:underline" href="/connectors/">set up the webhook or upload an export</Link></> : "Seceon NDR network detections (this host as source or destination)",
  };
  return (
    <Card>
      <CardHeader title={<span className="inline-flex items-center gap-2"><Crosshair className="size-4" /> Recent detections
        <span className="text-[12px] font-normal text-muted">{fmtN(all.length)} between {range.from} and {range.to}</span></span>}
        right={<div className="flex flex-wrap items-center gap-1.5">
          {[7, 30, 90].map((d) => <Button key={d} size="sm" variant="ghost" onClick={() => quick(d)}>{d} days</Button>)}
          <input type="date" className={input} value={range.from} max={range.to} onChange={(e) => setRange({ ...range, from: e.target.value })} />
          <span className="text-muted">–</span>
          <input type="date" className={input} value={range.to} min={range.from} onChange={(e) => setRange({ ...range, to: e.target.value })} />
        </div>} />
      <div className={cn("px-4 pb-4", busy && "opacity-70")}>
        <Tabs value={src} onChange={setSrc} tabs={[{ id: "all", label: "All sources", count: all.length }, { id: "cs", label: "CrowdStrike", count: csRows.length },
          { id: "splunk", label: "Splunk", count: spRows.length }, { id: "ndr", label: "Seceon NDR", count: ndRows.length }]} />
        {src !== "all" && note[src] && <div className="-mt-2 mb-2 text-[11.5px] text-muted">{note[src]}</div>}
        {!shown.length ? <div className="text-[13px] text-good-fg">No detections in this period.</div> : (
          <SimpleTable rows={shown} maxHeight="380px" columns={[
            { key: "at", label: "When", render: (x: any) => <When ts={x.at} /> },
            { key: "source", label: "Source", render: (x: any) => <Badge tone={x.source === "CrowdStrike" ? "crit" : x.source === "Splunk" ? "info" : "violet"}>{x.source}</Badge> },
            { key: "severity", label: "Severity", render: (x: any) => <Badge tone={SEV_TONE[x.severity] || "neutral"}>{x.severity || "–"}</Badge> },
            { key: "name", label: "Detection", wrap: true, render: (x: any) => <b className="text-[12.5px]">{x.name}</b> },
            { key: "detail", label: "Tactic / category", wrap: true, render: (x: any) => <span className="text-[12px] text-fg-2">{x.detail}</span> },
            { key: "where", label: "Host / flow", wrap: true, render: (x: any) => <span className="font-mono text-[11.5px]">{x.where}</span> },
            { key: "extra", label: "Process / role", render: (x: any) => <span className="text-[12px]">{x.extra}</span> },
            { key: "action", label: "Action", wrap: true, render: (x: any) => <span className="text-[12px]">{x.action}</span> },
            { key: "status", label: "Status", render: (x: any) => <Badge tone={/closed/i.test(x.status || "") ? "good" : /progress|investig/i.test(x.status || "") ? "info" : "warn"}>{String(x.status || "–").replace("_", " ")}</Badge> },
          ]} />
        )}
      </div>
    </Card>
  );
}

/* ---------------- SOD exceptions, last known good, related assets ---------------- */
function useAssetContext(s: any, agents: any[]) {
  return useQuery({ queryKey: ["asset-context", s.ips, s.hostnames], queryFn: () => api<any>("/api/asset/context",
    { params: { ips: s.ips.join(","), names: s.hostnames.join(","), aids: agents.map((a) => a.aid).join(",") } }) });
}

function ExceptionsCard({ s, agents }: { s: any; agents: any[] }) {
  const { data } = useAssetContext(s, agents);
  if (!data) return null;
  return (
    <Card>
      <CardHeader title="Vulnerability exceptions (SOD)" hint="exceptions covering this asset's findings, and when they run out" />
      <div className="px-4 pb-4">
        {!data.exceptions.length ? <div className="text-[13px] text-muted">No SOD exception covers this asset.</div> : (
          <SimpleTable rows={data.exceptions} columns={[
            { key: "exception_id", label: "Exception", render: (x: any) => <Link className="font-semibold hover:underline" href={`/exceptions/?q=${encodeURIComponent(x.exception_id)}`}>{x.exception_id}</Link> },
            { key: "status", label: "Status", render: (x: any) => <Badge tone={x.status === "Expired" ? "crit" : x.status === "Expiring" ? "warn" : "good"}>{x.status}</Badge> },
            { key: "days_left", label: "Runs out", render: (x: any) => x.days_left == null ? "no end date" : x.days_left < 0 ? <b className="text-crit-fg">{-x.days_left} days ago</b>
              : <span className={x.days_left <= 30 ? "font-semibold text-warn-fg" : ""}>in {x.days_left} days · {x.valid_till}</span> },
            { key: "findings", label: "Findings covered", render: (x: any) => <span>{x.findings}{x.status === "Expired" && <span className="text-crit-fg"> (reopened)</span>}</span> },
            { key: "finding_names", label: "For", wrap: true, render: (x: any) => <span className="text-[12px] text-fg-2">{x.finding_names.join(" · ")}</span> },
            { key: "approved_by", label: "Approved by" },
          ]} />
        )}
      </div>
    </Card>
  );
}

function LastGoodCard({ s, agents }: { s: any; agents: any[] }) {
  const { data } = useAssetContext(s, agents);
  return (
    <Card>
      <CardHeader title="Last seen by each source" hint="last known good" />
      <div className="space-y-1.5 px-4 pb-4">
        {!data ? <Loading /> : data.last_good.map((x: any) => (
          <div key={x.label} className="flex items-center justify-between gap-3 text-[12.5px]" title={x.hint}>
            <span className="text-fg-2">{x.label}</span>
            {x.at ? <span className="tabular"><When ts={x.at} /></span> : <span className="text-muted">never</span>}
          </div>
        ))}
        <SplunkLast names={s.hostnames} ips={s.ips} />
      </div>
    </Card>
  );
}

function SplunkLast({ names, ips }: { names: string[]; ips: string[] }) {
  const { data } = useQuery({ queryKey: ["asset-splunk", names, ips], queryFn: () => api<any>("/api/asset/splunk", { params: { hosts: names.join(","), ips: ips.join(",") } }) });
  const last = data?.rows?.[0]?.last_seen;
  return (
    <div className="flex items-center justify-between gap-3 text-[12.5px]" title="latest event in Splunk from this host">
      <span className="text-fg-2">Last Splunk event</span>
      {!data ? <span className="text-muted">…</span> : !data.configured ? <span className="text-muted">not connected</span> : last ? <When ts={last} /> : <span className="font-semibold text-crit-fg">none in {data.days || 7} days</span>}
    </div>
  );
}

function RelatedAssets({ s, agents }: { s: any; agents: any[] }) {
  const { data } = useAssetContext(s, agents);
  const [, set] = useUrlState();
  if (!data) return <Loading />;
  return (
    <SimpleTable rows={data.related} maxHeight="60vh" empty="No related assets" onRowClick={(x: any) => set({ q: x.ip, view: undefined })} columns={[
      { key: "kind", label: "Relation", render: (x: any) => <Badge tone={x.kind.startsWith("Talks") || x.kind.startsWith("It talks") ? "info" : "neutral"}>{x.kind}</Badge> },
      { key: "why", label: "Why", render: (x: any) => <span className="font-mono text-[11.5px]">{x.why}</span> },
      { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
      { key: "name", label: "Name" }, { key: "lobs", label: "LOB" },
      { key: "edr_status", label: "EDR", render: (x: any) => <EdrBadge s={x.edr_status} /> },
      { key: "sev", label: "Crit / high", render: (x: any) => (x.crit || x.high) ? <span className="font-semibold text-crit-fg">{x.crit} / {x.high}</span> : <span className="text-muted">0</span> },
      { key: "exposed", label: "Internet", render: (x: any) => x.exposed ? <Badge tone="crit">exposed</Badge> : null },
    ]} />
  );
}

/* ---------------- Satellite: packages, errata (remediation available) and MBSS compliance ---------------- */
function SatellitePanel({ ips, names }: { ips: string[]; names: string[] }) {
  const [which, setWhich] = React.useState("installable");
  const { data } = useQuery({ queryKey: ["asset-satellite", ips, names, which],
    queryFn: () => api<any>("/api/asset/satellite", { params: { ips: ips.join(","), names: names.join(","), errata: which } }) });
  if (!data) return <Loading />;
  if (!data.hosts.length) return (
    <div className="p-6 text-center text-[13px] text-muted">{data.configured ? "This host is not registered in Red Hat Satellite." :
      <>Red Hat Satellite is not connected. Add it under <Link className="text-accent-fg hover:underline" href="/settings/">Sync &amp; settings → Red Hat Satellite</Link> to see packages, errata and MBSS compliance.</>}</div>
  );
  return (
    <div className="space-y-3 p-4">
      {data.hosts.map((h: any) => (
        <div key={h.host_id} className="grid gap-3 md:grid-cols-3">
          <Stat label="Satellite host" value={h.name} sub={`${h.os || "–"} · checked in ${h.last_checkin ? fmtRel(h.last_checkin) : "–"} · ${h.subscription || ""}`} />
          <Stat label="Packages" value={`${fmtN(h.packages ?? 0)} installed`} sub={`${fmtN(h.upgradable ?? 0)} can be upgraded`} tone={h.upgradable ? "warn" : "good"} />
          <Stat label="Security errata" value={`${fmtN(h.errata_security ?? 0)} applicable`}
            sub={`${fmtN(h.installable_security ?? 0)} with a fix available now · ${fmtN(h.errata_bugfix ?? 0)} bug fix · ${fmtN(h.errata_enhancement ?? 0)} enhancement`} tone={h.installable_security ? "crit" : "good"} />
        </div>
      ))}
      {data.hosts.map((h: any) => (
        <div key={"m" + h.host_id}>
          <div className="mb-2 text-[13px] font-semibold">MBSS compliance {data.hosts.length > 1 ? `· ${h.name}` : ""}</div>
          <MbssReport hostId={h.host_id} />
        </div>
      ))}
      <div className="flex items-center gap-2 pt-2">
        <span className="text-[13px] font-semibold">Errata</span>
        {[["installable", "Remediation available now"], ["all", "All applicable"]].map(([k, l]) => (
          <Button key={k} size="sm" variant={which === k ? "soft" : "ghost"} onClick={() => setWhich(k)}>{l}</Button>
        ))}
      </div>
      <SimpleTable rows={data.errata} maxHeight="320px" empty="No errata" columns={[
        { key: "errata_id", label: "Erratum", render: (x: any) => <b className="font-mono text-[12px]">{x.errata_id}</b> },
        { key: "severity", label: "Severity", render: (x: any) => x.severity ? <Badge tone={x.severity === "Critical" ? "crit" : x.severity === "Important" ? "serious" : x.severity === "Moderate" ? "warn" : "neutral"}>{x.severity}</Badge> : <span className="text-muted">{x.type}</span> },
        { key: "title", label: "Title", wrap: true },
        { key: "cves", label: "CVEs", wrap: true, render: (x: any) => <span className="text-[12px]">{x.cves}</span> },
        { key: "installable", label: "Remediation", render: (x: any) => x.installable ? <Badge tone="good">Installable now</Badge> : <span className="text-[12px] text-muted">needs content / repo</span> },
        { key: "issued", label: "Issued", render: (x: any) => x.issued },
      ]} />
    </div>
  );
}

function Stat({ label, value, sub, tone = "neutral" }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: string }) {
  const bar: Record<string, string> = { good: "before:bg-good", warn: "before:bg-warn", crit: "before:bg-crit", neutral: "before:bg-border" };
  return (
    <div className={cn("relative overflow-hidden rounded-xl border border-border p-3 before:absolute before:inset-y-0 before:left-0 before:w-[3px]", bar[tone])}>
      <div className="text-[11.5px] font-medium text-muted">{label}</div>
      <div className="mt-0.5 truncate text-[15px] font-semibold" title={typeof value === "string" ? value : undefined}>{value}</div>
      {sub && <div className="mt-0.5 text-[11.5px] text-fg-2">{sub}</div>}
    </div>
  );
}

/* ---------------- Inventory sources ---------------- */
function InventorySources() {
  const { data } = useQuery({ queryKey: ["inventory-sources"], queryFn: () => api<any>("/api/inventory-sources") });
  if (!data) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5 text-[12px]">
      <span className="font-medium text-fg-2">Inventory sources:</span>
      {data.sources.map((x: any) => (
        <Link key={x.key} href="/inventory-sources/" title={x.how}
          className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5", x.status === "connected" ? "border-good/40 text-good-fg" : "border-border text-muted")}>
          <span className={cn("size-1.5 rounded-full", x.status === "connected" ? "bg-good" : "bg-muted")} />{x.name}
          <span className="text-muted">{x.status === "connected" ? "· connected" : x.status === "planned" ? "· not connected yet" : "· no data"}</span>
        </Link>
      ))}
    </div>
  );
}

/* ---------------- CrowdStrike: prevention policy, containment, Spotlight vs the VA scan ---------------- */
function CrowdStrikePanel({ agents, ips }: { agents: any[]; ips: string[] }) {
  const aids = agents.map((a) => a.aid).join(",");
  const { data } = useQuery({ queryKey: ["asset-cs", aids, ips], enabled: !!aids,
    queryFn: () => api<any>("/api/asset/crowdstrike", { params: { aids, ips: ips.join(",") } }) });
  if (!aids) return <div className="p-6 text-center text-[13px] text-muted">No CrowdStrike agent on this asset.</div>;
  if (!data) return <Loading />;
  const x = data.cross;
  return (
    <div className="space-y-3 p-4">
      <div className="grid gap-3 md:grid-cols-3">
        {data.posture.map((p: any) => (
          <Stat key={p.aid} label={`Prevention policy · ${p.hostname}`} value={p.policy || "Unknown"} tone={p.applied === false ? "crit" : p.policy ? "good" : "neutral"}
            sub={<>{p.applied === false ? <b className="text-crit-fg">not applied yet</b> : p.applied ? `applied ${p.applied_date ? fmtRel(p.applied_date) : ""}` : "no policy data"}
              </>} />
        ))}
        <Stat label="Spotlight vs VA scan (by CVE)" value={`${fmtN(x.both)} in both`}
          sub={<>{fmtN(x.spotlight_only)} only Spotlight sees · {fmtN(x.scanner_only)} only the scanner sees</>} tone={x.spotlight_only || x.scanner_only ? "warn" : "good"} />
      </div>
      <SimpleTable rows={data.spotlight} maxHeight="360px" empty={data.fetched_at ? "No open Spotlight vulnerabilities" : "Spotlight not fetched yet (needs the Vulnerabilities: Read scope)"} columns={[
        { key: "cve", label: "CVE", render: (v: any) => <b className="font-mono text-[12px]">{v.cve}</b> },
        { key: "severity", label: "Severity", render: (v: any) => <SeverityBadge s={v.severity.charAt(0) + v.severity.slice(1).toLowerCase()} /> },
        { key: "score", label: "CVSS", num: true },
        { key: "exprt", label: "ExPRT", render: (v: any) => <Badge tone={v.exprt === "HIGH" || v.exprt === "CRITICAL" ? "crit" : "neutral"}>{v.exprt || "–"}</Badge> },
        { key: "exploit_status", label: "Exploit" },
        { key: "product", label: "Product", wrap: true },
        { key: "remediation", label: "Remediation", wrap: true, render: (v: any) => <span className="text-[12px]">{v.remediation}</span> },
        { key: "in_scanner", label: "In VA scan", render: (v: any) => v.in_scanner ? <Badge tone="good">yes</Badge> : <Badge tone="warn">Spotlight only</Badge> },
      ]} />
      {x.scanner_only_cves.length > 0 && <div className="text-[12px] text-muted">Only the VA scan reports: {x.scanner_only_cves.join(", ")}</div>}
    </div>
  );
}

/* ---------------- SIEM: is this host logging to Splunk? ---------------- */
function SplunkPanel({ names, ips }: { names: string[]; ips: string[] }) {
  const { data } = useQuery({ queryKey: ["asset-splunk", names, ips], queryFn: () => api<any>("/api/asset/splunk", { params: { hosts: names.join(","), ips: ips.join(",") } }) });
  if (!data) return <Loading />;
  if (!data.configured) return <div className="p-6 text-center text-[13px] text-muted">Splunk is not connected. Set it up under <Link className="text-accent-fg hover:underline" href="/connectors/">Integrations → Splunk</Link>.</div>;
  if (data.error) return <div className="p-4 text-[13px] text-crit-fg">{data.error}</div>;
  return (
    <div className="space-y-2 p-4">
      <div className="flex items-center gap-2 text-[13px]">
        {data.rows.length ? <Badge tone="good">Logging</Badge> : <Badge tone="crit">No logs</Badge>}
        <span className="text-fg-2">{data.rows.length ? `${data.rows.length} index / sourcetype${data.rows.length > 1 ? "s" : ""} in the last ${data.days} days` : `Splunk has no event from this host in the last ${data.days} days — a blind spot during an incident.`}</span>
        {data.simulated && <span className="ml-auto text-[11.5px] text-muted">sample data: simulated</span>}
      </div>
      {data.rows.length > 0 && <SimpleTable rows={data.rows} columns={[
        { key: "index", label: "Index", render: (x: any) => <b>{x.index}</b> }, { key: "sourcetype", label: "Sourcetype" }, { key: "host", label: "Host value" },
        { key: "count", label: "Events", num: true, render: (x: any) => fmtN(x.count) },
        { key: "last_seen", label: "Last event", render: (x: any) => <When ts={x.last_seen} /> },
      ]} />}
    </div>
  );
}

/* ---------------- Headline: risk score, identity, one status tile per area, section menu ---------------- */
function usePosture(s: any, r: any) {
  const aids = r.agents.map((a: any) => a.aid).join(",");
  return useQuery({ queryKey: ["asset-posture", s.ips, s.hostnames, aids],
    queryFn: () => api<any>("/api/asset/posture", { params: { ips: s.ips.join(","), names: s.hostnames.join(","), aids } }) });
}

const LEVEL_COLOR: Record<string, string> = { Critical: "var(--crit)", High: "var(--serious)", Medium: "var(--warn)", Low: "var(--good)" };

function ScoreRing({ score, level }: { score: number; level: string }) {
  const r = 30, c = 2 * Math.PI * r, pct = Math.min(100, score) / 100;
  return (
    <div className="relative grid size-[76px] shrink-0 place-items-center">
      <svg viewBox="0 0 76 76" className="absolute inset-0 -rotate-90">
        <circle cx="38" cy="38" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="7" />
        <circle cx="38" cy="38" r={r} fill="none" stroke={LEVEL_COLOR[level]} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${c * pct} ${c}`} style={{ transition: "stroke-dasharray .6s ease" }} />
      </svg>
      <div className="text-center leading-none"><div className="text-[22px] font-bold">{score}</div><div className="mt-0.5 text-[9.5px] uppercase tracking-wide text-muted">points</div></div>
    </div>
  );
}

function Chip({ children, onClick, title }: { children: React.ReactNode; onClick?: () => void; title?: string }) {
  return (
    <button type="button" title={title} onClick={onClick}
      className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 px-2 py-0.5 font-mono text-[12px] text-fg-2 hover:border-border-strong">
      {children}
    </button>
  );
}

function Hero({ s, r }: { s: any; r: any }) {
  const copy = (t: string) => { navigator.clipboard?.writeText(t); toast.success(`Copied ${t}`); };
  return (
    <Card className="relative overflow-hidden">
      <span className={cn("absolute inset-y-0 left-0 w-1", s.exposure?.length ? "bg-crit" : s.edr_status === "Online" ? "bg-good" : "bg-warn")} />
      <div className="flex flex-wrap items-start gap-5 p-5 pl-6">
        <div className="min-w-[280px] flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-[22px] font-semibold tracking-tight">{s.hostnames[0] || s.query}</h2>
            {s.exposure?.length > 0 && <Link href={`/exposure/?q=${encodeURIComponent(s.ips[0] || "")}`}><Badge tone="crit" title={s.exposure.map((e: any) => "• " + e.text).join("\n")}>Internet exposed</Badge></Link>}
            <EdrBadge s={s.edr_status} />
            {s.ne_ids?.length > 0 && <Badge tone="violet" title="From the NIAM dump">NE ID {s.ne_ids.join(", ")}</Badge>}
            <span className="ml-auto print:hidden"><ExplainButton kind="asset" id={s.hostnames[0] || s.ips[0] || s.query} /></span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {s.ips.map((ip: string) => <Chip key={ip} onClick={() => copy(ip)} title="Copy"><Copy className="size-3 opacity-60" />{ip}</Chip>)}
            {s.hostnames.slice(1).map((h: string) => <Chip key={h} onClick={() => copy(h)} title="Also known as · copy">{h}</Chip>)}
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12.5px] 2xl:grid-cols-[auto_1fr_auto_1fr]">
            <dt className="text-muted">Owner</dt><dd>{s.lobs.length ? s.lobs.join(", ") : <span className="text-violet-fg">Not in any inventory</span>}{s.msps.length ? <span className="text-muted"> · MSP {s.msps.join(", ")}</span> : null}</dd>
            <dt className="text-muted">OS</dt><dd><OsCell os={s.os} src={s.os_source} /></dd>
            <dt className="text-muted">EDR feasibility</dt><dd>{s.feasibility ? <span className="inline-flex items-center gap-1.5"><FeasibleBadge v={s.feasibility} reason={s.feasibility_reason} /><span className="text-[11.5px] text-muted">{s.feasibility_reason}</span></span> : "–"}</dd>
          </dl>
        </div>
        <ExternalLookups s={s} r={r} />
      </div>
    </Card>
  );
}

type TileT = { key: string; icon: React.ElementType; label: string; value: React.ReactNode; sub?: React.ReactNode; tone: string; go: () => void };
const TILE_TONE: Record<string, string> = {
  good: "text-good-fg bg-good-soft", warn: "text-warn-fg bg-warn-soft", crit: "text-crit-fg bg-crit-soft", info: "text-accent-fg bg-accent-soft", neutral: "text-fg-2 bg-surface-3",
};

function PostureTiles({ s, r, go }: { s: any; r: any; go: (v: string) => void }) {
  const { data: p } = usePosture(s, r);
  const { data: pv } = useQuery({ queryKey: ["asset-passive", s.ips.join(",")], queryFn: () => api<any>("/api/asset/passive", { params: { ips: s.ips.join(",") } }) });
  const spl = useQuery({ queryKey: ["asset-splunk", s.hostnames, s.ips], queryFn: () => api<any>("/api/asset/splunk", { params: { hosts: s.hostnames.join(","), ips: s.ips.join(",") } }) });
  const v = s.vulns, a = s.edr_agent, i = r.internet, sat = p?.sat, det = p?.det, ndr = p?.ndr, b = p?.blast;
  const mbssTot = sat ? (sat.compliance_passed || 0) + (sat.compliance_failed || 0) : 0;
  const mbss = mbssTot ? Math.round((100 * (sat.compliance_passed || 0)) / mbssTot) : null;
  const tiles: TileT[] = [
    { key: "edr", icon: s.edr_status === "Online" ? ShieldCheck : ShieldX, label: "EDR", value: s.edr_status === "Not Installed" ? "Not installed" : s.edr_status,
      sub: a ? `sensor ${a.agent_version || "–"} · seen ${fmtRel(a.last_seen)}` : "no agent ever", tone: s.edr_status === "Online" ? "good" : s.edr_status === "Offline" ? "warn" : "crit", go: () => go("edr") },
    { key: "internet", icon: Globe2, label: "Internet", value: i?.verdict === "exposed" ? "Exposed" : i?.verdict === "cgnat" ? "Indirect" : i?.verdict === "whitelisted" ? "Whitelisted" : "Not exposed",
      sub: i?.verdict === "exposed" ? `${i.matrix.length} rule(s)${i.shadow ? ` · ${i.shadow} shadow port(s)` : ""}` : i?.public_ips?.length ? `public ${i.public_ips[0]}` : undefined,
      tone: i?.verdict === "exposed" ? "crit" : i?.verdict === "cgnat" ? "warn" : "good", go: () => go("exposure") },
    { key: "vulns", icon: ShieldAlert, label: "Vulnerabilities", value: <span className="flex items-baseline gap-1.5">{v.Critical}<span className="text-[11px] font-normal">crit</span>{v.High}<span className="text-[11px] font-normal">high</span></span>,
      sub: s.last_scan ? `scanned ${fmtRel(s.last_scan)}` : "never scanned", tone: v.Critical ? "crit" : v.High ? "warn" : s.last_scan ? "good" : "neutral", go: () => go("vulns") },
    { key: "det", icon: Activity, label: "Detections · 7 days", value: det ? `${fmtN(det.n + (ndr?.n || 0))}` : "…",
      sub: det ? `${det.n} CrowdStrike · ${ndr?.n || 0} NDR${det.high ? ` · ${det.high} crit/high` : ""}` : "", tone: det?.high || ndr?.high ? "crit" : det?.n || ndr?.n ? "warn" : "good", go: () => go("detections") },
    { key: "patch", icon: PackageCheck, label: "Patches", value: !p ? "…" : sat ? (sat.installable_security ? `${sat.installable_security} to install` : "Up to date") : "Not in Satellite",
      sub: sat ? `${sat.errata_security || 0} security errata · ${sat.upgradable || 0} upgradable` : "Linux via Red Hat Satellite", tone: !sat ? "neutral" : sat.installable_security ? "crit" : "good", go: () => go("patching") },
    { key: "mbss", icon: ClipboardCheck, label: "MBSS", value: mbss == null ? "No report" : `${mbss}%`, sub: mbss == null ? "OpenSCAP via Satellite" : `${sat.compliance_failed} failed rule(s)`,
      tone: mbss == null ? "neutral" : mbss >= 90 ? "good" : mbss >= 75 ? "warn" : "crit", go: () => go("patching") },
    { key: "siem", icon: Logs, label: "SIEM logging", value: !spl.data ? "…" : !spl.data.configured ? "Not connected" : spl.data.rows?.length ? "Logging" : "No logs",
      sub: spl.data?.rows?.[0] ? `last event ${fmtRel(spl.data.rows[0].last_seen)}` : spl.data?.configured ? `nothing in ${spl.data.days || 7} days` : "Splunk",
      tone: !spl.data?.configured ? "neutral" : spl.data.rows?.length ? "good" : "crit", go: () => go("edr") },
    { key: "inv", icon: Server, label: "Inventory", value: r.inventory?.length ? (s.lobs.join(", ") || "In inventory") : "Not in inventory",
      sub: r.inventory?.length ? `${r.inventory.length} record(s) · ${r.inventory[0].inventory_name || ""}` : "no LOB inventory lists it", tone: r.inventory?.length ? "info" : "warn", go: () => go("inventory") },
    { key: "iscan", icon: Radar, label: "Internet scan", value: !pv ? "…" : pv.rows.length ? `${pv.rows.reduce((a: number, x: any) => a + (x.ports?.length || 0), 0)} open ports` : "Not scanned",
      sub: pv?.rows?.length ? `${pv.rows.reduce((a: number, x: any) => a + (x.vulns?.length || 0), 0)} CVEs seen from the internet` : publicIps(r).length ? "public IP not looked up yet" : undefined,
      tone: pv?.rows?.some((x: any) => x.vulns?.length) ? "crit" : pv?.rows?.some((x: any) => x.ports?.length) ? "warn" : "neutral", go: () => go("internet") },
    { key: "blast", icon: Route, label: "Blast radius", value: !p ? "…" : b ? `${b.reach} reachable` : "–",
      sub: b ? `${b.weak} weak · reachable from ${b.reached_by} exposed` : "no matrix data", tone: b?.weak ? "crit" : b?.reach ? "warn" : "good", go: () => go("attack") },
  ];
  return (
    <div className="grid grid-cols-2 gap-2.5 md:grid-cols-3 xl:grid-cols-5">
      {tiles.map((t) => (
        <button key={t.key} onClick={t.go}
          className="group flex flex-col gap-1.5 rounded-xl border border-border bg-surface p-3 text-left shadow-card transition-all hover:-translate-y-px hover:border-accent">
          <div className="flex items-center gap-2">
            <span className={cn("grid size-7 place-items-center rounded-lg", TILE_TONE[t.tone])}><t.icon className="size-3.5" /></span>
            <span className="text-[11.5px] font-medium text-muted">{t.label}</span>
          </div>
          <div className={cn("text-[15px] font-semibold leading-tight", t.tone === "crit" && "text-crit-fg")}>{t.value}</div>
          <div className="line-clamp-2 text-[11px] text-muted">{t.sub}</div>
        </button>
      ))}
    </div>
  );
}

/* ---------------- Attack path / blast radius for this asset ---------------- */
function AttackCard({ s, r }: { s: any; r: any }) {
  const { data: p } = usePosture(s, r);
  const b = p?.blast;
  return (
    <Card>
      <CardHeader title={<span className="inline-flex items-center gap-2"><Route className="size-4" /> Attack path &amp; blast radius
        {b && <span className="text-[12px] font-normal text-muted">reaches {b.reach} asset(s), {b.weak} weak · reachable from {b.reached_by} internet-exposed asset(s)</span>}</span>}
        right={b && <Link className="flex items-center gap-1 text-[12.5px] text-accent-fg hover:underline print:hidden" href={`/attack-paths/?ip=${encodeURIComponent(b.ip)}&all=1`}>Open in Attack paths <ArrowUpRight className="size-3.5" /></Link>} />
      {!p ? <Loading /> : !b ? <div className="px-4 pb-4 text-[13px] text-muted">No internal IP for this asset in the registry, so no path can be traced.</div>
        : <PathView ip={b.ip} depth="2" compact />}
    </Card>
  );
}


/* ---------------- Inventory status: which LOB inventory the asset is in, and what each record says ---------------- */
function InventoryStatus({ s, r, go }: { s: any; r: any; go: (v: string) => void }) {
  const rows: any[] = r.inventory || [];
  if (!rows.length) return (
    <Card className="flex flex-wrap items-center gap-3 border-violet/30 p-4">
      <Badge tone="violet">Not in any inventory</Badge>
      <span className="text-[12.5px] text-fg-2">No LOB inventory lists this asset{s.edr_status !== "Not Installed" ? " — CrowdStrike knows it" : ""}{r.scans?.length ? ", a VA scan covered it" : ""}{r.niam?.length ? ", it is in the NIAM dump" : ""}.
        Add it to its LOB inventory so it is owned and counted.</span>
    </Card>
  );
  return (
    <Card>
      <CardHeader title={<span className="flex items-center gap-2"><Server className="size-4" /> Inventory
        <span className="text-[12px] font-normal text-muted">{rows.length} record{rows.length > 1 ? "s" : ""} · {Array.from(new Set(rows.map((x) => x.lob))).join(", ")}</span></span>}
        right={<button className="text-[12.5px] text-accent-fg hover:underline" onClick={() => go("records")}>All records →</button>} />
      <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
        {rows.map((x) => (
          <div key={`${x.lob_id}|${x.item_key}`} className="rounded-xl border border-border p-3 text-[12.5px]">
            <div className="flex flex-wrap items-center gap-2">
              <Link className="text-[13.5px] font-semibold hover:underline" href={`/lob/?id=${x.lob_id}&tab=inventory&q=${encodeURIComponent(x.ip || x.node_name)}`}>{x.lob}</Link>
              <Badge tone="info">{x.inventory_name}</Badge>
              {x.current_version && <span className="text-[11.5px] text-muted" title={x.current_version.filename}>v{x.current_version.version_no} · {fmtDt(x.current_version.uploaded_at).slice(0, 10)}</span>}
              {x.file_dups > 0 && <Badge tone="warn" title="Other rows of the upload share this IP / name">DUP</Badge>}
              <span className="ml-auto"><CoverageBadge v={x.coverage_status} /></span>
            </div>
            <dl className="mt-2 grid grid-cols-[auto_1fr_auto_1fr] gap-x-3 gap-y-1">
              <dt className="text-muted">Node</dt><dd className="truncate">{x.node_name || "–"}</dd>
              <dt className="text-muted">MSP</dt><dd>{x.msp || <span className="text-muted">Unassigned</span>}</dd>
              <dt className="text-muted">Node type</dt><dd>{x.node_type || "–"}</dd>
              <dt className="text-muted">Live</dt><dd><Live v={x.live} /></dd>
              <dt className="text-muted">EDR feasible</dt><dd>{x.feasible || "–"}</dd>
              <dt className="text-muted">Says EDR</dt><dd><YN v={x.edr_installed} /></dd>
              <dt className="text-muted">NIAM</dt><dd>{x.niam_eff}{x.ne_id ? <span className="font-mono text-[11px] text-muted"> · {x.ne_id}</span> : null}</dd>
              <dt className="text-muted">Matched agent</dt><dd className="truncate">{x.cs_hostname || <span className="text-muted">none</span>}{x.match_method ? <span className="text-[11px] text-muted"> · {x.match_method}</span> : null}</dd>
            </dl>
            {x.remarks && <div className="mt-1.5 text-[11.5px] text-fg-2">Remarks: {x.remarks}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
}


/* ---------------- Passive internet scan (Shodan InternetDB) for this asset ---------------- */
function PassiveCard({ s }: { s: any }) {
  const qc = useQueryClient();
  const ips = s.ips.join(",");
  const { data, refetch } = useQuery({ queryKey: ["asset-passive", ips], queryFn: () => api<any>("/api/asset/passive", { params: { ips } }) });
  const [busy, setBusy] = React.useState(false);
  const scan = async () => {
    setBusy(true);
    try {
      await api("/api/passive/scan-one", { method: "POST", body: { ip: s.ips[0] } });
      refetch();
      qc.invalidateQueries({ queryKey: ["asset"] });
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const rows = data?.rows || [];
  return (
    <Card>
      <CardHeader title={<span className="inline-flex items-center gap-2"><Search className="size-4" /> Internet DB scan (passive)
        <span className="text-[12px] font-normal text-muted">what the internet already sees on this asset's public IPs (Shodan InternetDB)</span></span>}
        right={<Button size="sm" loading={busy} onClick={scan}>Scan now</Button>} />
      <div className="px-4 pb-4">
        {!rows.length ? <div className="text-[13px] text-muted">Not scanned yet. Private IPs are looked up through their public / NAT IP.</div> : (
          <SimpleTable rows={rows} columns={[
            { key: "ip", label: "Public IP", render: (x: any) => <Mono>{x.ip}</Mono> },
            { key: "status", label: "Result", render: (x: any) => x.status === "none" ? <Badge>no data</Badge> : x.status === "error" ? <Badge tone="crit" title={x.error}>error</Badge>
              : x.ports.length ? <Badge tone="crit">{x.ports.length} open</Badge> : <Badge tone="good">nothing open</Badge> },
            { key: "ports", label: "Open ports", wrap: true, render: (x: any) => <PortChips ports={x.ports} /> },
            { key: "vulns", label: "CVEs", wrap: true, render: (x: any) => <CveChips vulns={x.vulns} max={8} /> },
            { key: "cpes", label: "Software", wrap: true, render: (x: any) => <span className="text-[11.5px]">{x.cpes.map((c: string) => c.replace(/^cpe:\/[aoh]:/, "")).join(", ") || "–"}</span> },
            { key: "scanned_at", label: "Looked up", render: (x: any) => <When ts={x.scanned_at} /> },
          ]} />
        )}
      </div>
    </Card>
  );
}


/* ---------------- external lookups for the asset's public IPs ---------------- */

function publicIps(r: any): string[] {
  return (r.internet?.public_ips || []).filter((x: string) => !x.includes(":"));
}
function ExternalLookups({ s, r }: { s: any; r: any }) {
  const ips = publicIps(r);
  if (!ips.length) return null;
  return (
    <div className="min-w-[260px] rounded-xl border border-border bg-surface-2/60 p-3 text-[12.5px]">
      <div className="mb-1.5 text-[11.5px] font-medium text-muted">Look up public IP{ips.length > 1 ? "s" : ""} on the internet</div>
      {ips.slice(0, 3).map((ip) => (
        <div key={ip} className="flex flex-wrap items-center gap-x-2 gap-y-1 py-0.5">
          <Mono>{ip}</Mono>
          {LOOKUPS.map(([n, url]) => <a key={n} href={url(ip)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-accent-fg hover:underline">{n}<ArrowUpRight className="size-3" /></a>)}
        </div>
      ))}
    </div>
  );
}

/* ---------------- Inventory tab ---------------- */
function InventoryView({ s, r }: { s: any; r: any }) {
  return (
    <div className="space-y-4">
      <InventoryStatus s={s} r={r} go={() => {}} />
      <Card>
        <CardHeader title="Inventory records" hint="every row of every LOB inventory for this asset" />
        <InventorySources />
        <SimpleTable rows={r.inventory} empty="Not in any LOB inventory" columns={[
          { key: "lob", label: "LOB", render: (x: any) => <Link className="font-semibold hover:underline" href={`/lob/?id=${x.lob_id}&tab=inventory&q=${encodeURIComponent(x.ip || x.node_name)}`}>{x.lob}</Link> },
          { key: "inventory_name", label: "Inventory", render: (x: any) => <span>{x.inventory_name}{x.current_version ? <span className="text-[11px] text-muted"> · v{x.current_version.version_no}</span> : null}</span> },
          { key: "msp", label: "MSP", render: (x: any) => x.msp || <span className="text-muted">Unassigned</span> },
          { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "node_name", label: "Node name" },
          { key: "node_type", label: "Node type" }, { key: "live", label: "Live", render: (x: any) => <Live v={x.live} /> },
          { key: "coverage_status", label: "EDR status", render: (x: any) => <CoverageBadge v={x.coverage_status} /> },
          { key: "niam_eff", label: "NIAM", render: (x: any) => <span>{x.niam_eff}{x.ne_id ? <span className="font-mono text-[11px] text-muted"> · {x.ne_id}</span> : null}</span> },
          { key: "source", label: "Uploaded", render: (x: any) => x.source?.uploaded_at ? <span className="text-[12px] text-muted" title={x.source.filename}>{fmtDt(x.source.uploaded_at).slice(0, 10)}{x.source.uploaded_by ? ` · ${x.source.uploaded_by}` : ""}</span> : "–" },
          { key: "remarks", label: "Remarks", wrap: true },
        ]} />
      </Card>
      {r.niam?.length > 0 && (
        <Card>
          <CardHeader title="NIAM dump" hint="network elements on this IP" />
          <SimpleTable rows={r.niam} columns={[
            { key: "ne_id", label: "NE ID", render: (x: any) => <b>{x.ne_id}</b> },
            { key: "host", label: "Host (as in NIAM)", render: (x: any) => <Mono>{x.host}</Mono> },
            { key: "present", label: "In latest dump", render: (x: any) => x.present ? <Badge tone="good">Yes</Badge> : <Badge tone="neutral">Dropped {fmtDt(x.removed_at).slice(0, 10)}</Badge> },
            { key: "extra", label: "NIAM details", wrap: true, render: (x: any) => <span className="text-xs text-fg-2">{Object.entries(x.extra || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span> },
          ]} />
        </Card>
      )}
    </div>
  );
}

/* ---------------- Internet scan tab: InternetDB, prefix / ASN, GreyNoise, external lookups ---------------- */
function InternetScanView({ s, r }: { s: any; r: any }) {
  const ips = publicIps(r);
  if (!ips.length) return (
    <Card className="p-6 text-[13px] text-muted">This asset has no known public IPv4 (own IP, or public / NAT IP in the inventory or the communication matrix).
      Search any public IP above to see what the internet knows about it.</Card>
  );
  return <div className="space-y-4">{ips.slice(0, 4).map((ip) => <IntelPanel key={ip} ip={ip} />)}</div>;
}

/* ---------------- Vulnerabilities tab: CVEs the internet sees (InternetDB) ---------------- */
function PassiveCves({ s, go }: { s: any; go: (v: string) => void }) {
  const ips = s.ips.join(",");
  const { data } = useQuery({ queryKey: ["asset-passive", ips], queryFn: () => api<any>("/api/asset/passive", { params: { ips } }) });
  const rows = (data?.rows || []).filter((x: any) => x.vulns?.length || x.ports?.length);
  if (!rows.length) return null;
  return (
    <Card>
      <CardHeader title="Seen from the internet (Internet DB scan)" hint="CVEs and open ports Shodan InternetDB records for this asset's public IPs"
        right={<button className="text-[12.5px] text-accent-fg hover:underline" onClick={() => go("internet")}>Internet scan →</button>} />
      <div className="px-4 pb-4"><SimpleTable rows={rows} columns={[
        { key: "ip", label: "Public IP", render: (x: any) => <Mono>{x.ip}</Mono> },
        { key: "vulns", label: "CVEs", wrap: true, render: (x: any) => <CveChips vulns={x.vulns} max={12} /> },
        { key: "ports", label: "Open ports", wrap: true, render: (x: any) => <PortChips ports={x.ports} /> },
        { key: "scanned_at", label: "Looked up", render: (x: any) => <When ts={x.scanned_at} /> },
      ]} /></div>
    </Card>
  );
}

function ScansCard({ rows }: { rows: any[] }) {
  return (
    <Card>
      <CardHeader title="VA scans" hint="which vulnerability scans covered this asset" />
      <SimpleTable rows={rows} empty="Never scanned" columns={[
        { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "lob", label: "LOB" },
        { key: "scanned_at", label: "Last scanned", render: (x: any) => <When ts={x.scanned_at} /> }, { key: "filename", label: "Scan file" },
      ]} />
    </Card>
  );
}

/* ---------------- Related assets tab: grouped by how they relate ---------------- */
const REL_INFO: Record<string, [string, string]> = {
  "Same public / NAT IP": ["Share a public / NAT IP", "Reach or leave the internet through the same public address"],
  "Talks to it": ["Talk to this asset", "Sources allowed to reach it by the communication matrix"],
  "It talks to": ["This asset talks to", "Destinations it is allowed to reach by the communication matrix"],
  "Same name family": ["Same name family", "Hostnames with the same stem (clusters, pairs, numbered nodes)"],
  "Same subnet": ["Same subnet", "Neighbours on the same /24"],
};
function RelatedView({ s, r }: { s: any; r: any }) {
  const { data } = useAssetContext(s, r.agents);
  const [, set] = useUrlState();
  if (!data) return <Card><Loading /></Card>;
  const groups: Record<string, any[]> = {};
  for (const x of data.related || []) (groups[x.kind] ||= []).push(x);
  const order = Object.keys(REL_INFO).filter((k) => groups[k]).concat(Object.keys(groups).filter((k) => !REL_INFO[k]));
  const sn = data.subnet;
  const subnetCard = sn && (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[12.5px]">
        <span><span className="text-muted">Subnet </span><Mono>{sn.subnet}</Mono></span>
        <span><b>{sn.assets}</b> <span className="text-muted">known assets</span></span>
        <span><b>{sn.edr}</b> <span className="text-muted">with EDR</span></span>
        {sn.gap > 0 && <span className="text-crit-fg"><b>{sn.gap}</b> feasible without EDR</span>}
        {sn.exposed > 0 && <span className="text-serious-fg"><b>{sn.exposed}</b> internet exposed</span>}
        {sn.gateways?.length > 0 && <span><span className="text-muted">Gateway </span><Mono>{sn.gateways.join(", ")}</Mono></span>}
        {sn.lobs?.length > 0 && <span><span className="text-muted">LOB </span>{sn.lobs.join(", ")}</span>}
        <Link className="ml-auto text-accent-fg hover:underline" href={`/subnets/?q=${encodeURIComponent(sn.subnet.split("/")[0])}`}>Open in Subnets &amp; VLANs →</Link>
      </div>
    </Card>
  );
  if (!order.length) return <div className="space-y-4">{subnetCard}<Card className="p-6 text-[13px] text-muted">No related assets found.</Card></div>;
  return (
    <div className="space-y-4">
      {subnetCard}
      {order.map((k) => (
        <Card key={k}>
          <CardHeader title={<span className="flex items-center gap-2">{REL_INFO[k]?.[0] || k}<Badge tone="neutral">{groups[k].length}</Badge></span>} hint={REL_INFO[k]?.[1]} />
          <SimpleTable rows={groups[k]} maxHeight="40vh" onRowClick={(x: any) => set({ q: x.ip, view: undefined })} columns={[
            { key: "name", label: "Asset", render: (x: any) => <span className="font-medium">{x.name || <span className="text-muted">–</span>}</span> },
            { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
            { key: "why", label: "Why", render: (x: any) => <span className="font-mono text-[11.5px] text-fg-2">{x.why}</span> },
            { key: "lobs", label: "LOB", render: (x: any) => x.lobs || <span className="text-muted">–</span> },
            { key: "edr_status", label: "EDR", render: (x: any) => <EdrBadge s={x.edr_status} /> },
            { key: "sev", label: "Crit / high", render: (x: any) => (x.crit || x.high) ? <span className="font-semibold text-crit-fg">{x.crit} / {x.high}</span> : <span className="text-muted">0</span> },
            { key: "exposed", label: "Internet", render: (x: any) => x.exposed ? <Badge tone="crit">exposed</Badge> : null },
          ]} />
        </Card>
      ))}
    </div>
  );
}


/** Public (internet-routable) IPv4: not private, loopback, link-local, CGNAT or multicast. */
function isPublicV4(q: string) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((q || "").trim());
  if (!m) return false;
  const [a, b] = [+m[1], +m[2]];
  if ([+m[1], +m[2], +m[3], +m[4]].some((x) => x > 255)) return false;
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
}


/** Rescan the asset's public IPs on the internet sources (InternetDB, VirusTotal, GreyNoise, RIPEstat) and refresh the page. */
function RescanButton({ ips }: { ips: string[] }) {
  const qc = useQueryClient();
  const [busy, setBusy] = React.useState(false);
  const go = async () => {
    setBusy(true);
    try {
      for (const ip of ips.slice(0, 4)) qc.setQueryData(["intel", ip], await api("/api/intel/ip/refresh", { method: "POST", body: { ip } }));
      qc.invalidateQueries({ queryKey: ["asset-passive"] });
      qc.invalidateQueries({ queryKey: ["asset-posture"] });
      toast.success(`Rescanned ${ips.slice(0, 4).join(", ")} on Shodan InternetDB, VirusTotal, GreyNoise and RIPEstat`);
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  return <Button className="h-11 print:hidden" loading={busy} onClick={go} title={`Look up ${ips.join(", ")} again on the internet sources`}><RefreshCw /> Rescan internet</Button>;
}

/* ---------------- Communication matrix rows that name this asset (source, destination, public / NAT IP) ---------------- */
function MatrixFlows({ rows }: { rows: any[] }) {
  return (
    <Card>
      <CardHeader title="Communication matrix" hint={rows.length ? `${fmtN(rows.length)} row(s) name this asset · ${fmtN(rows.filter((f) => f.inbound_internet).length)} internet-facing` : undefined}
        right={<Link href="/matrix/" className="text-[12.5px] text-accent-fg hover:underline">Open matrix</Link>} />
      {rows.length ? (
        <SimpleTable rows={rows} maxHeight="60vh" columns={[
          { key: "role", label: "This asset is", render: (f: any) => <Badge tone={f.role === "Destination" ? "info" : "outline"}>{f.role}</Badge> },
          { key: "inbound_internet", label: "Internet", render: (f: any) => f.inbound_internet ? <Badge tone="crit">inbound</Badge> : f.src_nat ? <Badge tone="warn">source NAT</Badge> : "" },
          { key: "rule_id", label: "Rule", render: (f: any) => <Mono>{f.rule_id}</Mono> },
          { key: "src", label: "Source", wrap: true, render: (f: any) => <span>{f.src_zone ? <span className="text-muted">{f.src_zone} · </span> : null}{f.src || "–"}</span> },
          { key: "src_nat", label: "Source NAT IP", wrap: true },
          { key: "dst_nat", label: "Public / NAT IP", wrap: true },
          { key: "dst", label: "Destination", wrap: true, render: (f: any) => <span>{f.dst_zone ? <span className="text-muted">{f.dst_zone} · </span> : null}{f.dst || "–"}</span> },
          { key: "ports", label: "Ports", render: (f: any) => <span>{[f.protocol, f.ports].filter(Boolean).join(" ") || "any"}</span> },
          { key: "action", label: "Action" },
          { key: "application", label: "Application", wrap: true },
          { key: "app_owner", label: "Owner", wrap: true },
          { key: "isp", label: "ISP / link" }, { key: "firewall", label: "Firewall" },
          { key: "valid_till", label: "Valid till" },
          { key: "sheet", label: "Sheet", render: (f: any) => <span className="text-[11.5px] text-muted" title={f.workbook}>{f.sheet || f.workbook || "–"}</span> },
        ]} />
      ) : <div className="p-6 text-center text-[13px] text-muted">No communication matrix row names this asset (as source, destination, public / NAT IP or source NAT IP).</div>}
    </Card>
  );
}
