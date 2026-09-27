"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { Badge, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Select } from "@/components/ui";
import { COLORS, HBars } from "@/components/charts";
import { DataTable, SimpleTable } from "@/components/data-table";
import { EdrBadge, HostLink, RiskBadge, SevCounts } from "@/components/badges";
import { ShowOnly } from "@/components/vuln-views";

export const LEVEL_TONE: Record<string, string> = { Critical: "crit", High: "serious", Medium: "warn", Low: "good" };

export function LobMspFilters({ state, set }: { state: Record<string, string>; set: any }) {
  const { data: meta } = useMeta();
  const msps = (meta?.msps || []).filter((m) => !state.lob || String(m.lob_id) === state.lob);
  return (
    <>
      <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={(meta?.lobs || []).map((l) => ({ value: l.id, label: l.name }))} />
      <Select value={state.msp} onChange={(v) => set({ msp: v })} placeholder="All MSPs" options={[...msps.map((m) => ({ value: m.id, label: m.name })), { value: "none", label: "Unassigned" }]} />
    </>
  );
}

/** Risk-ranked asset table, shared by the Risk and Scan coverage pages. */
export function RiskTable({ state, set, reset, fixed, storageKey, omit = [], scanFocus }: {
  state: Record<string, string>; set: any; reset: () => void; fixed?: Record<string, string>; storageKey: string; omit?: string[]; scanFocus?: boolean;
}) {
  return (
    <DataTable endpoint="/api/risk/assets" exportPath="/api/risk/assets/export" state={state} setState={set} fixed={fixed} omit={omit}
      noun="assets" storageKey={storageKey} rowKey={(r: any) => `${r.lob_id}|${r.asset_key}`} onReset={reset}
      columns={[
        { key: "score", label: "Risk", render: (r: any) => <RiskBadge score={r.score} level={r.level} factors={r.factors} /> },
        { key: "why", label: "Why", sort: false, wrap: true, render: (r: any) => (
          <span className="flex min-w-[340px] max-w-[460px] flex-wrap gap-1">
            {r.factors.filter((f: any) => f[1]).slice(0, 4).map(([n, p]: any) => <span key={n} className="whitespace-nowrap rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-fg-2">{n} <b>+{p}</b></span>)}
          </span>
        ) },
        { key: "ip", label: "IP", render: (r: any) => r.ip ? <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip)}`}>{r.ip}</Link> : <span className="text-muted">no IP</span> },
        { key: "node_name", label: "Node / host", render: (r: any) => r.aid && !String(r.aid).startsWith("import-") ? <HostLink aid={r.aid}>{r.node_name || r.hostname}</HostLink> : (r.node_name || r.hostname || <span className="text-muted">–</span>) },
        { key: "lob", label: "LOB" },
        { key: "msp", label: "MSP", render: (r: any) => r.msp || <span className="text-muted">Unassigned</span> },
        { key: "edr_status", label: "EDR", render: (r: any) => r.in_inventory && !r.applicable ? <Badge tone="neutral">{r.coverage_status}</Badge> : <EdrBadge s={r.edr_status} /> },
        { key: "crit", label: "Crit / High / Med / Low", render: (r: any) => <SevCounts c={r.crit} h={r.high} m={r.med} l={r.low} /> },
        { key: "scan_age_days", label: "Last scan", render: (r: any) => r.last_scan
          ? <span>{fmtDt(r.last_scan).slice(0, 10)} <span className={r.scan_age_days > 30 ? "text-xs text-crit-fg" : "text-xs text-muted"}>{r.scan_age_days}d</span></span>
          : <span className="text-crit-fg">Never</span> },
        { key: "node_type", label: "Node type", sort: false, hidden: !scanFocus },
        { key: "in_inventory", label: "Inventory", sort: false, hidden: true, render: (r: any) => r.in_inventory ? "Yes" : <span className="text-violet-fg">Not in inventory</span> },
        { key: "exploitable", label: "Exploitable", sort: false, hidden: true, render: (r: any) => r.exploitable || "" },
      ]}
      filters={<>
        <SearchInput className="w-64" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, CIDR, node name… (paste many)" />
        <LobMspFilters state={state} set={set} />
        {!scanFocus && <Select value={state.level} onChange={(v) => set({ level: v })} placeholder="Any risk level" options={["Critical", "High", "Medium", "Low"]} />}
        {scanFocus
          ? <Select value={state.scan} onChange={(v) => set({ scan: v })} placeholder="Scanned or not" options={[["0-30|31-60|61-90|90+", "Scanned"], ["never", "Never scanned"]]} />
          : <Select value={state.scan} onChange={(v) => set({ scan: v })} placeholder="Any scan age" options={[["never", "Never scanned"], ["31-60|61-90|90+", "Scan older than 30 days"]]} />}
        <ShowOnly state={state} set={set} flags={[["no_edr", "1", "No active EDR"], ["exploitable", "1", "Exploit available"], ["crit_high", "1", "Crit / high vulns"], ["in_inventory", "0", "Not in any inventory"]]} />
      </>} />
  );
}

export default function Risk() {
  const [state, set, replaceAll] = useUrlState();
  const { data: s, error, refetch } = useQuery({
    queryKey: ["risk-summary", state.lob || "", state.msp || ""],
    queryFn: () => api<any>("/api/risk/summary", { params: { lob: state.lob, msp: state.msp } }),
  });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const keep = { ...(state.lob ? { lob: state.lob } : {}), ...(state.msp ? { msp: state.msp } : {}) };
  const go = (patch: Record<string, string>) => replaceAll({ ...keep, ...patch });
  return (
    <div>
      <PageHeader title="Risk ranking"
        sub="Every inventory node and scanned IP gets a 0–100 score from what we know about it: no EDR agent (+35), EDR offline (+8, +15 after 7 days, +25 after 30 days — agents removed from the console count as offline), open critical / high / medium findings, and +10 when a critical / high finding has a known exploit (the scan's “Exploit Ease” column says exploits are available). Non Live nodes count 30%. Hover a score to see its parts." />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
        {(["Critical", "High", "Medium", "Low"] as const).map((l) => (
          <Kpi key={l} label={`${l} risk`} value={s.levels[l]} tone={LEVEL_TONE[l]} active={state.level === l}
            foot={l === "Critical" ? "score ≥ 60" : l === "High" ? "35 – 59" : l === "Medium" ? "15 – 34" : "under 15"} onClick={() => go({ level: l })} />
        ))}
        <Kpi label="Critical risk · no EDR" value={s.critical_no_edr} tone="crit" onClick={() => go({ level: "Critical", no_edr: "1" })} />
        <Kpi label="Exploit available" value={s.exploitable} tone="serious" foot="crit / high with exploit" onClick={() => go({ exploitable: "1" })} />
        <Kpi label="Assets scored" value={s.assets} tone="info" foot={`average score ${s.avg_score ?? "–"}`} onClick={() => replaceAll(keep)} />
      </KpiGrid>

      <div className="my-4 grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader title="By LOB / MSP" hint="click a row to filter" />
          <SimpleTable rows={s.by_msp} maxHeight="280px" onRowClick={(r: any) => go({ lob: String(r.lob_id), msp: r.msp_id ? String(r.msp_id) : "none" })} columns={[
            { key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> }, { key: "msp", label: "MSP" },
            { key: "critical", label: "Critical", num: true, render: (r: any) => r.critical ? <b className="text-crit-fg">{fmtN(r.critical)}</b> : "0" },
            { key: "high", label: "High", num: true, render: (r: any) => r.high ? <span className="text-serious-fg">{fmtN(r.high)}</span> : "0" },
            { key: "medium", label: "Medium", num: true },
            { key: "assets", label: "Assets", num: true },
            { key: "avg_score", label: "Avg score", num: true },
          ]} />
        </Card>
        <Card>
          <CardHeader title="What drives critical & high risk" hint="assets per factor" />
          <div className="px-4 pb-4">
            <HBars items={s.factors.slice(0, 8).map((f: any) => ({ label: f.factor, n: f.n, color: COLORS.serious }))} />
          </div>
        </Card>
      </div>

      <RiskTable state={state} set={set} reset={() => replaceAll(keep)} storageKey="risk" />
    </div>
  );
}

