"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Callout, Card, CardHeader, FilterSelect, Kpi, KpiGrid, Loading, Modal, PageHeader, SearchInput, Tabs } from "@/components/ui";
import { DataTable, SimpleTable, type Column } from "@/components/data-table";
import { Mono } from "@/components/badges";
import { Bar, MbssReport } from "@/components/mbss-report";
import { fmtDt } from "@/lib/format";

/** MBSS (Minimum Baseline Security Standard) from Satellite OpenSCAP: failed rules across the fleet, grouped by control. */
export default function Mbss() {
  const [state, set, replaceAll] = useUrlState();
  const [fix, setFix] = React.useState<string | null>(null);
  const [ruleHosts, setRuleHosts] = React.useState<any>(null);
  const [host, setHost] = React.useState<any>(null);
  const tab = state.tab || "controls";
  const { data: s, error, refetch } = useQuery({ queryKey: ["satellite-summary"], queryFn: () => api<any>("/api/satellite/summary") });
  const { data: ctl } = useQuery({ queryKey: ["mbss-controls-v2"], queryFn: () => api<any>("/api/satellite/mbss/controls") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const cols: Column[] = [
    { key: "control", label: "Control", sort: false, render: (r) => <b>{r.control}</b> },
    { key: "title", label: "Rule", sort: false, wrap: true },
    { key: "severity", label: "Severity", sort: false, render: (r) => <Badge tone={r.severity === "High" ? "crit" : r.severity === "Medium" ? "warn" : "neutral"}>{r.severity || "–"}</Badge> },
    { key: "passed", label: "Compliant on", sort: false, render: (r) => <span className="text-good-fg">{fmtN(r.passed ?? 0)}</span> },
    { key: "hosts", label: "Failing on", sort: false, render: (r) => <button className="font-semibold text-accent-fg hover:underline" onClick={() => setRuleHosts(r)}>{fmtN(r.hosts)}</button> },
    { key: "fix", label: "Remediation", sort: false, wrap: true, render: (r) => (
      <button className="text-left" onClick={() => setFix(fix === r.rule_id ? null : r.rule_id)}>
        <pre className={cn("whitespace-pre-wrap font-mono text-[11.5px] text-fg-2", fix !== r.rule_id && "line-clamp-2")}>{r.fix}</pre>
      </button>) },
    { key: "rule_id", label: "Rule ID", sort: false, hidden: true },
  ];
  const assetCols: Column[] = [
    { key: "name", label: "Asset", render: (r) => <b>{r.name}</b> },
    { key: "ip", label: "IP", sort: false, render: (r) => <Mono>{r.ip}</Mono> },
    { key: "lob", label: "LOB", sort: false },
    { key: "os", label: "OS", sort: false },
    { key: "compliance", label: "MBSS compliance", render: (r) => r.compliance_pct == null ? <span className="text-muted">no report</span> : (
      <span className="inline-flex items-center gap-2"><span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-3"><span className={cn("block h-full", r.compliance_pct >= 90 ? "bg-good" : r.compliance_pct >= 75 ? "bg-warn" : "bg-crit")} style={{ width: `${r.compliance_pct}%` }} /></span>
        <b className="tabular">{r.compliance_pct}%</b></span>) },
    { key: "passed", label: "Passed", sort: false, render: (r) => fmtN(r.compliance_passed ?? 0) },
    { key: "failed", label: "Failed points", sort: false, render: (r) => r.compliance_failed ? <b className="text-crit-fg">{fmtN(r.compliance_failed)}</b> : <span className="text-good-fg">0</span> },
    { key: "policy", label: "Policy", sort: false, render: (r) => <span className="text-[12px]">{r.compliance_policy}</span> },
    { key: "compliance_at", label: "Report", sort: false, render: (r) => r.compliance_at ? fmtDt(r.compliance_at).slice(0, 10) : "–" },
  ];
  return (
    <div>
      <PageHeader title="MBSS compliance" sub="Latest OpenSCAP report of each Satellite host against the MBSS policy. Click an asset for its full report: compliant and non-compliant points, and the fix for each." />
      {!s.configured && <Callout tone="warn" className="mb-4">Red Hat Satellite is not connected. Set it up under <Link className="underline" href="/connectors/">Integrations</Link>.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
        <Kpi label="Compliance" value={s.compliance_pct == null ? "–" : `${s.compliance_pct}%`} tone="good" foot={`${fmtN(s.passed)} rule checks passed · ${fmtN(s.failed)} failed`} />
        <Kpi label="Hosts with a report" value={s.reported} tone="info" foot={`of ${fmtN(s.hosts)} Satellite hosts`} />
        <Kpi label="Hosts failing a rule" value={s.noncompliant} tone="crit" />
        <Kpi label="Controls below 90%" value={ctl ? ctl.rows.filter((c: any) => c.pct != null && c.pct < 90).length : "–"} tone="warn" foot={ctl ? `of ${ctl.rows.length} controls` : ""} onClick={() => replaceAll({ tab: "controls" })} />
      </KpiGrid>
      <Tabs value={tab} onChange={(v) => replaceAll({ tab: v })} tabs={[{ id: "controls", label: "By control", count: ctl?.rows.length },
        { id: "rules", label: "Failed rules" }, { id: "assets", label: "By asset", count: s.reported }]} />
      {tab === "controls" ? (
        <Card>
          <div className="grid grid-cols-[minmax(0,1fr)_minmax(120px,240px)_60px_90px_110px] gap-3 border-b border-border bg-surface-2 px-4 py-2 text-[11.5px] font-semibold text-fg-2">
            <span>Control</span><span>Compliance</span><span className="text-right">%</span><span className="text-right">Rule checks</span><span className="text-right">Hosts failing</span></div>
          {!ctl ? <Loading /> : ctl.rows.map((c: any) => (
            <button key={c.control} onClick={() => replaceAll({ tab: "rules", q: c.control })}
              className="grid w-full grid-cols-[minmax(0,1fr)_minmax(120px,240px)_60px_90px_110px] items-center gap-3 border-b border-border px-4 py-2.5 text-left text-[12.5px] last:border-0 hover:bg-surface-2">
              <span className="truncate font-medium">{c.control}</span>
              <Bar pct={c.pct} />
              <b className={cn("text-right tabular", c.pct == null ? "text-muted" : c.pct >= 90 ? "text-good-fg" : c.pct >= 75 ? "text-warn-fg" : "text-crit-fg")}>{c.pct == null ? "–" : `${Math.round(c.pct)}%`}</b>
              <span className="text-right text-muted tabular">{fmtN(c.pass)} / {fmtN((c.pass || 0) + (c.fail || 0))}</span>
              <span className="text-right tabular">{c.hosts_failing ? <b className="text-crit-fg">{fmtN(c.hosts_failing)}</b> : <span className="text-good-fg">0</span>}<span className="text-muted"> / {fmtN(c.hosts)}</span></span>
            </button>
          ))}
        </Card>
      ) : tab === "rules" ? (
        <DataTable key="r" endpoint="/api/satellite/mbss" columns={cols} state={state} setState={set} omit={["tab"]} storageKey="mbss" noun="failed rules"
          rowKey={(r: any) => `${r.control}|${r.rule_id}`} onReset={() => replaceAll({ tab })}
          filters={<>
            <SearchInput className="w-[260px]" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Control, rule or rule ID" />
            <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="All" options={["High", "Medium", "Low"]} />
          </>} />
      ) : (
        <DataTable key="a" endpoint="/api/satellite/hosts" columns={assetCols} state={state} setState={set} omit={["tab"]} storageKey="mbss-assets" noun="assets"
          rowKey={(r: any) => String(r.host_id)} onReset={() => replaceAll({ tab })} onRowClick={(r: any) => setHost(r)}
          filters={<>
            <SearchInput className="w-[260px]" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Host, IP or OS" />
            <FilterSelect label="Show" value={state.state} onChange={(v) => set({ state: v })} any="All assets" options={[["noncompliant", "Failing a rule"], ["no_report", "No OpenSCAP report"]]} />
          </>} />
      )}
      <Modal open={!!ruleHosts} onOpenChange={(o) => !o && setRuleHosts(null)} wide title={ruleHosts ? `${ruleHosts.control} · ${ruleHosts.title}` : ""}>
        {ruleHosts && <RuleHosts rule={ruleHosts} />}
      </Modal>
      <Modal open={!!host} onOpenChange={(o) => !o && setHost(null)} wide title={host ? <span className="flex items-center gap-3">MBSS report · {host.name}
          <Link className="text-[12.5px] font-normal text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(host.ip || host.name)}&view=patching`}>Asset 360 →</Link></span> : ""}>
        {host && <MbssReport hostId={host.host_id} />}
      </Modal>
    </div>
  );
}

function RuleHosts({ rule }: { rule: any }) {
  const { data } = useQuery({ queryKey: ["mbss-rule", rule.rule_id], queryFn: () => api<any>("/api/satellite/mbss/rule", { params: { rule_id: rule.rule_id } }) });
  if (!data) return <Loading />;
  return (
    <div className="space-y-3">
      <pre className="whitespace-pre-wrap rounded-lg bg-surface-2 p-3 font-mono text-[12px] text-fg-2">{rule.fix}</pre>
      <SimpleTable rows={data.rows} maxHeight="55vh" columns={[
        { key: "name", label: "Asset", render: (x: any) => <Link className="font-medium hover:underline" href={`/ip-search/?q=${encodeURIComponent(x.ip || x.name)}`}>{x.name}</Link> },
        { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> }, { key: "lob", label: "LOB" }, { key: "os", label: "OS" },
        { key: "compliance_pct", label: "Compliance", render: (x: any) => x.compliance_pct == null ? "–" : `${x.compliance_pct}%` },
        { key: "compliance_at", label: "Report", render: (x: any) => fmtDt(x.compliance_at).slice(0, 10) },
      ]} />
    </div>
  );
}
