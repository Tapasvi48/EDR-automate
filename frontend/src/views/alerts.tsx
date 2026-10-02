"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { daysAgo, fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Checkbox } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { DateRange } from "@/components/date-range";

const SEV_TONE: Record<string, any> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Informational: "neutral" };
const SRC_TONE: Record<string, string> = { CrowdStrike: "bg-crit-soft text-crit-fg", Splunk: "bg-accent-soft text-accent-fg", "Seceon NDR": "bg-violet-soft text-violet-fg" };
const SOURCES = ["CrowdStrike", "Splunk", "Seceon NDR"];
const SRC_BAR: Record<string, string> = { CrowdStrike: "bg-crit", Splunk: "bg-accent", "Seceon NDR": "bg-violet" };

/** Recent alerts from CrowdStrike, Splunk ES and Seceon NDR in one feed, each linked to its asset. */
export default function Alerts() {
  const [state, set, replaceAll] = useUrlState();
  const from = state.from === "all" ? "2000-01-01" : state.from ?? daysAgo(6);
  const params = { from, to: state.to };
  const { data, error, refetch } = useQuery({ queryKey: ["alerts-summary", params], queryFn: () => api<any>("/api/alerts", { params: { ...params, size: 1 } }) });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const s = data.summary;
  const days: any[] = data.by_day || [];
  const max = Math.max(1, ...days.map((d) => SOURCES.reduce((a, k) => a + (d[k] || 0), 0)));
  const cols: Column[] = [
    { key: "created_at", label: "When", render: (r) => <span title={fmtDt(r.created_at)}>{fmtRel(r.created_at)}</span> },
    { key: "source", label: "Source", render: (r) => <span className={cn("rounded-md px-1.5 py-0.5 text-[11px] font-semibold", SRC_TONE[r.source])}>{r.source}</span> },
    { key: "severity", label: "Severity", render: (r) => <Badge tone={SEV_TONE[r.severity] || "neutral"}>{r.severity || "–"}</Badge> },
    { key: "name", label: "Alert", wrap: true, render: (r) => <span><b className="text-[12.5px]">{r.name}</b>{r.detail && <span className="block text-[11.5px] text-muted">{r.detail}</span>}</span> },
    { key: "asset", label: "Asset", render: (r) => r.ip || r.asset ? <Link className="hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip || r.asset)}&view=detections`}>
      <span className="font-medium">{r.asset || r.ip}</span>{r.ip && r.asset && <span className="block font-mono text-[11px] text-muted">{r.ip}</span>}</Link> : <span className="text-muted">–</span> },
    { key: "lobs", label: "LOB", render: (r) => r.lobs || <span className="text-muted">–</span> },
    { key: "exposed", label: "Internet", render: (r) => r.exposed ? <Badge tone="crit">exposed</Badge> : null },
    { key: "status", label: "Status", render: (r) => <Badge tone={/closed|resolved/i.test(r.status || "") ? "good" : /progress|investig/i.test(r.status || "") ? "info" : "warn"}>{r.status || "new"}</Badge> },
    { key: "owner", label: "Analyst", render: (r) => r.owner || <span className="text-muted">unassigned</span> },
  ];
  return (
    <div>
      <PageHeader title="Alerts" sub="Recent alerts from CrowdStrike, Splunk Enterprise Security and Seceon NDR in one place, linked to the asset each one is about." />
      <SourceStatus onFetched={() => refetch()} />
      {data.demo && <Callout tone="info" className="mb-4">Sample data mode: Splunk notables are simulated.</Callout>}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <DateRange label="Alerts" from={state.from === "all" ? undefined : from} to={state.to} onChange={(f, t) => set({ from: f ?? "all", to: t })} />
      </div>
      <KpiGrid className="mb-3 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
        <Kpi label="Alerts" value={s.total} tone="info" active={!state.source && !state.severity && !state.open} onClick={() => replaceAll({ from: state.from || "", to: state.to || "" })} />
        {SOURCES.map((k) => <Kpi key={k} label={k} value={s.by_source[k] || 0} active={state.source === k} onClick={() => set({ source: state.source === k ? undefined : k })} />)}
        <Kpi label="Critical / high" value={s.crit_high} tone="crit" active={state.severity === "Critical|High"} onClick={() => set({ severity: state.severity === "Critical|High" ? undefined : "Critical|High" })} />
        <Kpi label="Still open" value={s.open} tone="warn" active={state.open === "1"} onClick={() => set({ open: state.open === "1" ? undefined : "1" })} />
        <Kpi label="On exposed assets" value={s.exposed} tone="serious" active={state.exposed === "1"} onClick={() => set({ exposed: state.exposed === "1" ? undefined : "1" })} />
      </KpiGrid>
      {days.length > 1 && (
        <Card className="mb-4 p-3">
          <div className="mb-2 flex items-center gap-3 text-[11.5px] text-muted">Per day
            {SOURCES.map((k) => <span key={k} className="flex items-center gap-1"><i className={cn("inline-block size-2 rounded-sm", SRC_BAR[k])} />{k}</span>)}</div>
          <div className="flex h-16 items-end gap-1">
            {days.map((d) => (
              <div key={d.day} className="flex flex-1 flex-col-reverse overflow-hidden rounded-sm" title={`${d.day}: ${SOURCES.map((k) => `${k} ${d[k] || 0}`).join(" · ")}`}
                style={{ height: `${(100 * SOURCES.reduce((a, k) => a + (d[k] || 0), 0)) / max}%` }}>
                {SOURCES.map((k) => <div key={k} className={cn(SRC_BAR[k], "opacity-80")} style={{ flexGrow: d[k] || 0 }} />)}
              </div>
            ))}
          </div>
        </Card>
      )}
      <DataTable endpoint="/api/alerts" exportPath="/api/alerts/export" state={{ ...state, from, ...(state.to ? { to: state.to } : {}) }} setState={set} noun="alerts" storageKey="alerts"
        rowKey={(r: any) => `${r.source}|${r.id}`} onReset={() => replaceAll({})} sortable={false} columns={cols}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Alert, host, IP, asset, LOB, analyst…" />
          <FilterSelect label="Source" value={state.source} onChange={(v) => set({ source: v })} any="All" options={SOURCES} />
          <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="Any" options={[["Critical|High", "Critical + high"], "Critical", "High", "Medium", "Low"]} />
          <Checkbox checked={state.open === "1"} onChange={(v) => set({ open: v ? "1" : undefined })} label="Open only" />
        </>} />
      <div className="mt-2 text-[11.5px] text-muted">CrowdStrike alerts come from the last sync ({fmtN(s.by_source.CrowdStrike || 0)} in range) · Seceon NDR from its webhook / uploads · Splunk notables are asked live.</div>
    </div>
  );
}


/** Per source: set up? how many stored? last fetched? what went wrong? — and pull CrowdStrike alerts now. */
function SourceStatus({ onFetched }: { onFetched: () => void }) {
  const qc = useQueryClient();
  const { data, refetch } = useQuery({ queryKey: ["alerts-status"], queryFn: () => api<any>("/api/alerts/status") });
  const [busy, setBusy] = React.useState(false);
  if (!data) return null;
  const fetchNow = async () => {
    setBusy(true);
    try {
      const r = await api<any>("/api/alerts/fetch", { method: "POST" });
      toast[r.ok ? "success" : "error"](r.message);
      refetch(); onFetched(); qc.invalidateQueries({ queryKey: ["/api/alerts"] });
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const items: [string, any, React.ReactNode][] = [
    ["CrowdStrike", data.crowdstrike, data.crowdstrike.stored ? `${fmtN(data.crowdstrike.stored)} stored · newest ${fmtRel(data.crowdstrike.newest)} · fetched ${fmtRel(data.crowdstrike.fetched_at)}` : null],
    ["Splunk", data.splunk, data.splunk.configured ? "asked live" : null],
    ["Seceon NDR", data.ndr, data.ndr.stored ? `${fmtN(data.ndr.stored)} stored · last received ${fmtRel(data.ndr.received_at)}` : null],
  ];
  const problems = items.filter(([, x]) => x.reason);
  return (
    <Card className={cn("mb-4 p-3", problems.length && "border-warn/40")}>
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="font-medium">Sources</span>
        {items.map(([n, x, ok]) => (
          <span key={n} className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5", x.reason ? "border-warn/50 text-warn-fg" : "border-good/40 text-good-fg")}
            title={x.reason || (typeof ok === "string" ? ok : "")}>
            <span className={cn("size-1.5 rounded-full", x.reason ? "bg-warn" : "bg-good")} />{n}
          </span>
        ))}
        <Button size="sm" className="ml-auto" loading={busy} onClick={fetchNow}>Fetch CrowdStrike alerts now</Button>
      </div>
      <div className="mt-2 space-y-0.5 text-[12px]">
        {items.map(([n, x, ok]) => (
          <div key={n} className="flex gap-2"><span className="w-24 shrink-0 text-muted">{n}</span>
            <span className={x.reason ? "text-warn-fg" : "text-fg-2"}>{x.reason || ok || "ok"}</span></div>
        ))}
      </div>
    </Card>
  );
}
