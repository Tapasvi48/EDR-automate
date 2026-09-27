"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Search, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, Loading, PageHeader, SearchInput, Tabs } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { CoverageBadge, EdrBadge, HostLink, Live, Mono, SevCounts, SeverityBadge, When, YN, removalLabel, RiskBadge, FeasibleBadge, OsCell } from "@/components/badges";

export default function AssetSearch() {
  const [state, set] = useUrlState();
  const q = (state.q || "").trim();
  const { data: r, isFetching, error, refetch } = useQuery({ queryKey: ["asset", q], queryFn: () => api<any>("/api/asset", { params: { q } }), enabled: !!q });
  return (
    <div>
      <PageHeader title="Asset 360"
        sub="One answer for an IP, hostname or agent ID: is EDR installed and healthy, which LOB and MSP own it, what the inventory says, open vulnerabilities and when it was last scanned. IPv4 and IPv6 both work. A prefix (10.20.3.) or CIDR (10.20.0.0/16, 2001:db8::/48) lists every asset in the range." />
      <div className="flex gap-2">
        <SearchInput big autoFocus className="flex-1" value={q} onChange={(v) => set({ q: v })} placeholder="10.20.34.17  ·  2001:db8::17  ·  CORP-WS-0369  ·  NE ID  ·  10.20.34.  ·  10.20.0.0/16  ·  agent ID" />
        <Button className="h-11" disabled={!q} onClick={() => downloadExcel("/api/asset/export", { q })}><Download /> Excel</Button>
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
      <CardHeader title={`${fmtN(r.total)} assets in ${q}`}
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

function Verdict({ icon, label, value, sub, tone }: { icon: React.ReactNode; label: string; value: React.ReactNode; sub?: React.ReactNode; tone: string }) {
  const bg = { good: "bg-good-soft text-good-fg", warn: "bg-warn-soft text-warn-fg", crit: "bg-crit-soft text-crit-fg", info: "bg-accent-soft text-accent-fg", neutral: "bg-surface-3 text-fg-2" }[tone];
  return (
    <Card className="flex items-start gap-3 p-4">
      <div className={cn("grid size-10 shrink-0 place-items-center rounded-xl", bg)}>{icon}</div>
      <div className="min-w-0">
        <div className="text-xs font-medium text-muted">{label}</div>
        <div className="text-[16px] font-semibold">{value}</div>
        {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
      </div>
    </Card>
  );
}

function Profile({ r }: { r: any }) {
  const s = r.summary;
  const [tab, setTab] = React.useState("vulns");
  React.useEffect(() => setTab(r.vulns.length ? "vulns" : r.agents.length ? "agents" : "inventory"), [r]);
  const ports = r.ports || [];
  if (!s.found) return <Card className="mt-5 p-8 text-center text-muted">Nothing found for “{s.query}” in CrowdStrike, any inventory, vulnerability scan or the NIAM dump.</Card>;
  const a = s.edr_agent;
  const edrTone = s.edr_status === "Online" ? "good" : s.edr_status === "Offline" ? "warn" : "crit";
  const v = s.vulns;
  return (
    <div className="mt-5 space-y-4">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h2 className="text-[20px] font-semibold">{s.hostnames[0] || s.query}</h2>
        <span className="font-mono text-[13px] text-fg-2">{s.ips.join(", ")}</span>
        {s.hostnames.length > 1 && <span className="text-xs text-muted">also known as {s.hostnames.slice(1).join(", ")}</span>}
        {s.risk && <Link href={`/risk/?q=${encodeURIComponent(s.risk.ip)}`}><RiskBadge score={s.risk.score} level={s.risk.level} factors={s.risk.factors} /></Link>}
        {s.exposure?.length > 0 && <Link href={`/exposure/?q=${encodeURIComponent(s.ips[0] || "")}`}><Badge tone="crit" title={s.exposure.map((e: any) => "• " + e.text).join("\n")}>Internet exposed</Badge></Link>}
        {s.ne_ids?.length > 0 && <Badge tone="violet" title="From the NIAM dump">NE ID {s.ne_ids.join(", ")}</Badge>}
      </div>
      {(s.os || s.feasibility) && (
        <div className="-mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px]">
          <span className="text-muted">OS</span><OsCell os={s.os} src={s.os_source} />
          {s.feasibility && <><span className="text-muted">EDR feasibility</span><FeasibleBadge v={s.feasibility} reason={s.feasibility_reason} /><span className="text-xs text-muted">{s.feasibility_reason}</span></>}
        </div>
      )}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Verdict tone={edrTone} icon={s.edr_status === "Online" ? <ShieldCheck className="size-5" /> : <ShieldX className="size-5" />} label="EDR (CrowdStrike)"
          value={s.edr_status === "Not Installed" ? "Not installed" : s.edr_status}
          sub={a ? <>{s.edr_detail && s.edr_detail !== "in console" && <b className="text-warn-fg">{s.edr_detail} · </b>}{a.aid ? <HostLink aid={a.aid}>{a.hostname}</HostLink> : a.hostname} · sensor {a.agent_version || "–"} · seen {fmtRel(a.last_seen)}{s.active_agents > 1 ? ` · ${s.active_agents} active agents` : ""}</> : "No agent has ever reported this asset"} />
        <Verdict tone={s.in_inventory ? "info" : "neutral"} icon={<ShieldCheck className="size-5" />} label="Owner (LOB · MSP)"
          value={s.lobs.length ? s.lobs.join(", ") : "No LOB"} sub={s.in_inventory ? <>MSP {s.msps.join(", ") || "unassigned"} · inventory says EDR {s.inventory_claim.join("/") || "–"}</> : "Not in any LOB inventory"} />
        <Verdict tone={v.Critical ? "crit" : v.High ? "warn" : r.scans.length ? "good" : "neutral"} icon={<ShieldAlert className="size-5" />} label="Open vulnerabilities"
          value={<SevCounts c={v.Critical} h={v.High} m={v.Medium} l={v.Low} />} sub={`${fmtN(v.fixed)} fixed · ${fmtN(v.Info)} info`} />
        <Verdict tone={s.last_scan ? "info" : "neutral"} icon={<Search className="size-5" />} label="Last vulnerability scan"
          value={s.last_scan ? fmtDt(s.last_scan).slice(0, 10) : "Never scanned"} sub={s.last_scan ? fmtRel(s.last_scan) : undefined} />
      </div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "vulns", label: "Vulnerabilities", count: r.vulns.length },
        { id: "ports", label: "Ports", count: ports.length },
        ...(r.flows?.length ? [{ id: "flows", label: "Flows", count: r.flows.length }] : []),
        { id: "agents", label: "EDR agents", count: r.agents.length },
        { id: "inventory", label: "Inventory", count: r.inventory.length },
        { id: "scans", label: "Scans", count: r.scans.length },
        ...(r.niam?.length ? [{ id: "niam", label: "NIAM", count: r.niam.length }] : []),
      ]} />
      <Card>
        {tab === "vulns" && <SimpleTable rows={r.vulns} maxHeight="60vh" empty="No findings for this asset" columns={[
          { key: "severity", label: "Severity", render: (x: any) => <SeverityBadge s={x.severity} /> },
          { key: "name", label: "Vulnerability", wrap: true, render: (x: any) => <Link className="font-medium hover:underline" href={`/vulnerabilities/?vtab=findings&ip=${x.ip}&status=${x.status === "fixed" ? "fixed" : ""}`}>{x.name}</Link> },
          { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "lob", label: "LOB" },
          { key: "port", label: "Port", render: (x: any) => `${x.port || ""}${x.protocol ? "/" + x.protocol : ""}` },
          { key: "plugin_id", label: "Plugin" }, { key: "cve", label: "CVE", wrap: true },
          { key: "first_discovered", label: "First discovered", render: (x: any) => fmtDt(x.first_discovered) },
          { key: "last_observed", label: "Last observed", render: (x: any) => fmtDt(x.last_observed) },
          { key: "status", label: "Status", render: (x: any) => x.status === "fixed" ? <span className="text-good-fg">Fixed</span> : "Open" },
        ]} />}
        {tab === "flows" && <SimpleTable rows={r.flows || []} maxHeight="60vh" empty="No communication-matrix rule covers this asset" columns={[
          { key: "rule_id", label: "Rule", render: (x: any) => <span className="flex items-center gap-1.5"><b>{x.rule_id}</b>{x.inbound_internet ? <Badge tone="crit">internet</Badge> : null}</span> },
          { key: "role", label: "This asset is", render: (x: any) => <Badge tone={x.role === "Destination" ? "info" : "outline"}>{x.role}</Badge> },
          { key: "src", label: "Source", wrap: true, render: (x: any) => <span className="text-[12px]"><span className="text-muted">{x.src_zone ? `${x.src_zone} · ` : ""}</span><Mono>{x.src}</Mono></span> },
          { key: "dst_nat", label: "Public / NAT IP", render: (x: any) => <Mono>{x.dst_nat}</Mono> },
          { key: "dst", label: "Destination", wrap: true, render: (x: any) => <Mono>{x.dst}</Mono> },
          { key: "svc", label: "Service", render: (x: any) => `${(x.protocol || "any").toUpperCase()} ${x.ports || "any"}` },
          { key: "firewall", label: "Firewall" }, { key: "isp", label: "ISP / link" }, { key: "action", label: "Action" }, { key: "cr", label: "CR" },
        ]} />}
        {tab === "ports" && <SimpleTable rows={ports} maxHeight="60vh" empty="No ports seen — ports come from vulnerability scan findings" columns={[
          { key: "port", label: "Port", render: (x: any) => <b className="font-mono">{x.port}</b> },
          { key: "protocol", label: "Protocol", render: (x: any) => (x.protocol || "").toUpperCase() },
          { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
          { key: "max_severity", label: "Worst open finding", render: (x: any) => x.max_severity ? <SeverityBadge s={x.max_severity} /> : <span className="text-muted">none open</span> },
          { key: "open_findings", label: "Open findings", num: true },
          { key: "names", label: "Vulnerabilities on this port", wrap: true, render: (x: any) => <span className="text-xs text-fg-2">{x.names.slice(0, 4).join(" · ")}{x.names.length > 4 ? ` +${x.names.length - 4}` : ""}</span> },
          { key: "last_observed", label: "Last observed", render: (x: any) => fmtDt(x.last_observed) },
        ]} />}
        {tab === "agents" && <SimpleTable rows={r.agents} empty="No CrowdStrike agent found" columns={[
          { key: "hostname", label: "Hostname", render: (x: any) => <HostLink aid={x.aid}><b>{x.hostname || x.aid}</b></HostLink> },
          { key: "edr_status", label: "Status", render: (x: any) => <span className="flex items-center gap-1.5"><EdrBadge s={x.edr_status} />{x.edr_detail && x.edr_detail !== "in console" && <span className="text-xs text-muted">{x.edr_detail}</span>}</span> },
          { key: "local_ip", label: "IP", render: (x: any) => <Mono>{x.local_ip}</Mono> },
          { key: "lobs", label: "LOB" }, { key: "msps", label: "MSP" },
          { key: "os_version", label: "OS" }, { key: "agent_version", label: "Sensor", render: (x: any) => <Mono>{x.agent_version}</Mono> },
          { key: "first_seen", label: "First seen", render: (x: any) => fmtDt(x.first_seen) },
          { key: "last_seen", label: "Last seen", render: (x: any) => <When ts={x.last_seen} /> },
          { key: "aid", label: "Agent ID", render: (x: any) => <Mono>{x.aid}</Mono> },
        ]} />}
        {tab === "inventory" && <SimpleTable rows={r.inventory} empty="Not in any LOB inventory" columns={[
          { key: "lob", label: "LOB", render: (x: any) => <Link className="font-semibold hover:underline" href={`/lob/?id=${x.lob_id}&tab=inventory&q=${encodeURIComponent(x.ip || x.node_name)}`}>{x.lob}</Link> },
          { key: "msp", label: "MSP", render: (x: any) => x.msp || <span className="text-muted">Unassigned</span> },
          { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "node_name", label: "Node name" },
          { key: "node_type", label: "Node type" }, { key: "live", label: "Live", render: (x: any) => <Live v={x.live} /> },
          { key: "edr_feasible", label: "EDR feasible", render: (x: any) => <YN v={x.edr_feasible} /> },
          { key: "edr_installed", label: "EDR installed (inventory)", render: (x: any) => <YN v={x.edr_installed} /> },
          { key: "coverage_status", label: "EDR status", render: (x: any) => <CoverageBadge v={x.coverage_status} /> },
          { key: "remarks", label: "Remarks", wrap: true },
        ]} />}
        {tab === "scans" && <SimpleTable rows={r.scans} empty="Never scanned" columns={[
          { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "lob", label: "LOB" },
          { key: "scanned_at", label: "Last scanned", render: (x: any) => <When ts={x.scanned_at} /> }, { key: "filename", label: "Scan file" },
        ]} />}
        {tab === "niam" && <SimpleTable rows={r.niam || []} empty="Not in the NIAM dump" columns={[
          { key: "ne_id", label: "NE ID", render: (x: any) => <b>{x.ne_id}</b> },
          { key: "host", label: "Host (as in NIAM)", render: (x: any) => <Mono>{x.host}</Mono> },
          { key: "present", label: "In latest dump", render: (x: any) => x.present ? <Badge tone="good">Yes</Badge> : <Badge tone="neutral">Dropped {fmtDt(x.removed_at).slice(0, 10)}</Badge> },
          { key: "extra", label: "NIAM details", wrap: true, render: (x: any) => <span className="text-xs text-fg-2">{Object.entries(x.extra || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span> },
          { key: "first_seen_at", label: "First in NIAM", render: (x: any) => fmtDt(x.first_seen_at) },
        ]} />}
      </Card>
    </div>
  );
}
