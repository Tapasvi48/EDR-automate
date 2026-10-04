"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Callout, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Tabs } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { Mono } from "@/components/badges";
import { SpotlightSheet } from "@/components/detail-sheets";

const SEV_TONE: Record<string, any> = { CRITICAL: "crit", HIGH: "serious", MEDIUM: "warn", LOW: "info" };
const sev = (v?: string) => <Badge tone={SEV_TONE[(v || "").toUpperCase()] || "neutral"}>{v ? v.charAt(0) + v.slice(1).toLowerCase() : "–"}</Badge>;
const exploitTone = (e?: string) => (e === "Actively used" ? "crit" : e === "Easily accessible" ? "serious" : e === "Available" ? "warn" : "neutral");

/** CrowdStrike Spotlight vulnerabilities: the agent's own view, kept apart from the VA-scan vulnerability numbers. */
export default function Spotlight() {
  const [state, set, replaceAll] = useUrlState();
  const { data: meta } = useMeta();
  const tab = state.tab || "findings";
  const [openId, setOpenId] = React.useState<string | null>(null);
  const { data: s, error, refetch } = useQuery({ queryKey: ["spotlight-summary"], queryFn: () => api<any>("/api/spotlight/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const only = (patch: Record<string, string>) => replaceAll({ ...(tab !== "findings" ? { tab } : {}), ...patch });
  const host = (r: any) => <Link className="font-medium hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip || r.hostname)}&view=edr`}>{r.hostname || r.aid}</Link>;
  const findingCols: Column[] = [
    { key: "severity", label: "Severity", render: (r) => sev(r.severity) },
    { key: "cve", label: "Vulnerability", wrap: true, render: (r) => <span className="flex max-w-[360px] flex-col">
      <span className="font-medium">{r.title || r.cve}</span>
      <span className="flex items-center gap-1.5 font-mono text-[11px] text-muted">{r.cve}{r.kev ? <Badge tone="crit">CISA KEV</Badge> : null}</span></span> },
    { key: "score", label: "CVSS", num: true },
    { key: "exprt", label: "ExPRT", render: (r) => r.exprt ? sev(r.exprt) : <span className="text-muted">–</span> },
    { key: "exploit_status", label: "Exploit", render: (r) => r.exploit_status ? <Badge tone={exploitTone(r.exploit_status) as any}>{r.exploit_status}</Badge> : "–" },
    { key: "hostname", label: "Host", render: (r) => <span className="flex flex-col">{host(r)}<span className="font-mono text-[11px] text-muted">{r.ip}</span></span> },
    { key: "lob", label: "LOB", render: (r) => r.lob || <span className="text-muted">Not in inventory</span> },
    { key: "product", label: "Product", wrap: true, render: (r) => <span className="text-[12px]">{r.product || "–"}</span> },
    { key: "remediation", label: "Remediation", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.remediation || "–"}</span> },
    { key: "in_scanner", label: "In VA scan", render: (r) => r.in_scanner ? <Badge tone="good">yes</Badge> : <Badge tone="warn">Spotlight only</Badge> },
    { key: "updated_at", label: "Updated", hidden: true, render: (r) => fmtDt(r.updated_at) },
  ];
  const cveCols: Column[] = [
    { key: "cve", label: "Vulnerability", wrap: true, render: (r) => <button className="flex max-w-[360px] flex-col text-left" onClick={() => replaceAll({ cve: r.cve })}>
      <span className="font-medium hover:underline">{r.title || r.cve}</span><span className="flex items-center gap-1.5 font-mono text-[11px] text-accent-fg">{r.cve}{r.kev ? <Badge tone="crit">CISA KEV</Badge> : null}</span></button> },
    { key: "severity", label: "Severity", render: (r) => sev(r.severity) }, { key: "score", label: "CVSS", num: true },
    { key: "exprt", label: "ExPRT", render: (r) => r.exprt ? sev(r.exprt) : "–" },
    { key: "exploit_status", label: "Exploit", render: (r) => r.exploit_status ? <Badge tone={exploitTone(r.exploit_status) as any}>{r.exploit_status}</Badge> : "–" },
    { key: "hosts", label: "Hosts", num: true, render: (r) => <b>{fmtN(r.hosts)}</b> },
    { key: "product", label: "Product", wrap: true, render: (r) => <span className="text-[12px]">{r.product}</span> },
    { key: "remediation", label: "Remediation", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.remediation}</span> },
  ];
  const hostCols: Column[] = [
    { key: "hostname", label: "Host", render: (r) => <span className="flex flex-col">{host(r)}<Mono>{r.ip}</Mono></span> },
    { key: "lob", label: "LOB", render: (r) => r.lob || <span className="text-muted">Not in inventory</span> },
    { key: "findings", label: "Findings", num: true, render: (r) => <button className="font-semibold text-accent-fg hover:underline" onClick={() => replaceAll({ aid: r.aid })}>{fmtN(r.findings)}</button> },
    { key: "critical", label: "Critical", num: true, render: (r) => r.critical ? <b className="text-crit-fg">{r.critical}</b> : "0" },
    { key: "high", label: "High", num: true, render: (r) => r.high ? <b className="text-serious-fg">{r.high}</b> : "0" },
    { key: "exploitable", label: "Exploitable", num: true },
    { key: "online_state", label: "Agent", render: (r) => <Badge tone={r.online_state === "online" ? "good" : "warn"}>{r.online_state || "–"}</Badge> },
  ];
  const filters = <>
    <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="CVE, host, IP, product…" />
    <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="Any" options={[["CRITICAL|HIGH", "Critical + high"], ["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"]]} />
    <FilterSelect label="ExPRT" value={state.exprt} onChange={(v) => set({ exprt: v })} any="Any" options={[["CRITICAL|HIGH", "Critical + high"], ["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"]]} />
    <FilterSelect single label="Exploit" value={state.exploit} onChange={(v) => set({ exploit: v })} any="Any" options={[["1", "Exploit available"]]} />
    <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v })} any="All" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />
    {tab === "findings" && <FilterSelect single label="VA scan" value={state.in_scanner} onChange={(v) => set({ in_scanner: v })} any="Any" options={[["0", "Spotlight only"], ["1", "Also in VA scan"]]} />}
    {(state.cve || state.aid) && <Badge tone="info">{state.cve || "one host"}<button className="ml-1" onClick={() => set({ cve: undefined, aid: undefined })}>×</button></Badge>}
  </>;
  return (
    <div>
      <PageHeader title="Spotlight vulnerabilities"
        sub="Vulnerabilities CrowdStrike's own agent reports (Spotlight). Kept separate from the VA-scan vulnerabilities: these findings do not change vulnerability counts, risk scores or the Overview." />
      {!s.findings && <Callout tone="warn" className="mb-4">No Spotlight data yet. The CrowdStrike API client needs the <b>Vulnerabilities: Read</b> scope; findings arrive with the next sync
        (check <Link className="underline" href="/settings/">Sync &amp; settings → CrowdStrike API features</Link>).</Callout>}
      {s.demo && <Callout tone="info" className="mb-4">Sample data mode.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(155px,1fr))]">
        <Kpi label="Open findings" value={s.findings} tone="info" foot={`${fmtN(s.hosts)} hosts · ${fmtN(s.cves)} CVEs`} active={!state.severity && !state.exploit && !state.in_scanner} onClick={() => only({})} />
        <Kpi label="Critical" value={s.critical} tone="crit" active={state.severity === "CRITICAL"} onClick={() => only({ severity: "CRITICAL" })} />
        <Kpi label="High" value={s.high} tone="serious" active={state.severity === "HIGH"} onClick={() => only({ severity: "HIGH" })} />
        <Kpi label="Exploit available" value={s.exploitable} tone="crit" active={state.exploit === "1"} onClick={() => only({ exploit: "1" })} />
        <Kpi label="ExPRT critical / high" value={s.exprt_high} tone="serious" foot="CrowdStrike's own risk rating" active={state.exprt === "CRITICAL|HIGH"} onClick={() => only({ exprt: "CRITICAL|HIGH" })} />
        <Kpi label="Spotlight only" value={s.spotlight_only} tone="warn" foot={`${fmtN(s.in_scanner)} also in the VA scan`} active={state.in_scanner === "0"} onClick={() => replaceAll({ in_scanner: "0" })} />
      </KpiGrid>
      <Tabs value={tab} onChange={(v) => replaceAll(v === "findings" ? {} : { tab: v })} tabs={[{ id: "findings", label: "Findings", count: s.findings },
        { id: "cves", label: "By CVE", count: s.cves }, { id: "hosts", label: "By host", count: s.hosts }]} />
      {tab === "findings" && <DataTable endpoint="/api/spotlight" exportPath="/api/spotlight/export" state={state} setState={set} noun="findings" storageKey="spotlight"
        rowKey={(r: any) => r.id} onReset={() => replaceAll({})} sortable={false} columns={findingCols} filters={filters} onRowClick={(r: any) => setOpenId(r.id)} />}
      {tab === "cves" && <DataTable endpoint="/api/spotlight/by-cve" state={state} setState={set} omit={["tab"]} noun="CVEs" storageKey="spotlight-cve"
        rowKey={(r: any) => r.cve} onReset={() => replaceAll({ tab })} sortable={false} columns={cveCols} filters={filters} />}
      {tab === "hosts" && <DataTable endpoint="/api/spotlight/by-host" state={state} setState={set} omit={["tab"]} noun="hosts" storageKey="spotlight-host"
        rowKey={(r: any) => r.aid} onReset={() => replaceAll({ tab })} sortable={false} columns={hostCols} filters={filters} />}
      <SpotlightSheet id={openId} onClose={() => setOpenId(null)} />
      {s.fetched_at && <div className="mt-2 text-[11.5px] text-muted">Spotlight data from the sync {fmtRel(s.fetched_at)}</div>}
    </div>
  );
}
