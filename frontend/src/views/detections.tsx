"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { daysAgo, fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Checkbox, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { DateRange } from "@/components/date-range";
import { Mono } from "@/components/badges";

const SEV_TONE: Record<string, any> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Informational: "neutral" };
const statusTone = (s?: string) => (/closed|resolved|false|ignored/i.test(s || "") ? "good" : /progress|investig/i.test(s || "") ? "info" : "warn");

/** CrowdStrike detections (Alerts API) stored by each sync: what fired, where, and who is on it. */
export default function Detections() {
  const [state, set, replaceAll] = useUrlState();
  const qc = useQueryClient();
  const from = state.from === "all" ? "2000-01-01" : state.from ?? daysAgo(6);
  const range = { from, ...(state.to ? { to: state.to } : {}) };
  const { data: s, error, refetch } = useQuery({ queryKey: ["detections-summary", range], queryFn: () => api<any>("/api/detections/summary", { params: range }) });
  const { data: st } = useQuery({ queryKey: ["alerts-status"], queryFn: () => api<any>("/api/alerts/status") });
  const [busy, setBusy] = React.useState(false);
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const cs = st?.crowdstrike;
  const fetchNow = async () => {
    setBusy(true);
    try {
      const r = await api<any>("/api/alerts/fetch", { method: "POST" });
      toast[r.ok ? "success" : "error"](r.message);
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const toggle = (k: string, v: string) => set({ [k]: state[k] === v ? undefined : v });
  const maxDay = Math.max(1, ...s.by_day.map((d: any) => d.n));
  const cols: Column[] = [
    { key: "created_at", label: "When", render: (r) => <span title={fmtDt(r.created_at)}>{fmtRel(r.created_at)}</span> },
    { key: "severity", label: "Severity", render: (r) => <Badge tone={SEV_TONE[r.severity] || "neutral"}>{r.severity || "–"}</Badge> },
    { key: "name", label: "Detection", wrap: true, render: (r) => <span><b className="text-[12.5px]">{r.name || "–"}</b>
      {(r.tactic || r.technique) && <span className="block text-[11.5px] text-muted">{[r.tactic, r.technique].filter(Boolean).join(" · ")}</span>}</span> },
    { key: "hostname", label: "Host", render: (r) => <Link className="hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip || r.hostname || r.aid)}&view=detections`}>
      <span className="font-medium">{r.hostname || r.aid}</span>{r.ip && <span className="block font-mono text-[11px] text-muted">{r.ip}</span>}</Link> },
    { key: "lob", label: "LOB", render: (r) => r.lob || <span className="text-muted">–</span> },
    { key: "filename", label: "File", wrap: true, render: (r) => r.filename ? <Mono>{r.filename}</Mono> : <span className="text-muted">–</span> },
    { key: "disposition", label: "Action", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.disposition || "–"}</span> },
    { key: "status", label: "Status", render: (r) => <Badge tone={statusTone(r.status) as any}>{r.status || "new"}</Badge> },
    { key: "assigned_to", label: "Analyst", render: (r) => r.assigned_to || <span className="text-muted">unassigned</span> },
    { key: "exposed", label: "Internet", render: (r) => r.exposed ? <Badge tone="crit">exposed</Badge> : null },
    { key: "product", label: "Product", hidden: true },
    { key: "updated_at", label: "Updated", hidden: true, render: (r) => fmtDt(r.updated_at) },
  ];
  return (
    <div>
      <PageHeader title="Detections" sub="CrowdStrike detections (Alerts API) saved by each sync, linked to the agent, its LOB and whether it is internet exposed." />
      {cs?.reason && !s.stored.n && <Callout tone="warn" className="mb-4"><b>No detections stored.</b> {cs.reason}</Callout>}
      {cs?.reason && s.stored.n > 0 && /skipped|fail|error/i.test(cs.reason) && <Callout tone="warn" className="mb-4">{cs.reason}</Callout>}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <DateRange label="Detections" from={state.from === "all" ? undefined : from} to={state.to} onChange={(f, t) => set({ from: f ?? "all", to: t })} />
        <span className="text-[11.5px] text-muted">
          {fmtN(s.stored.n)} stored (last {s.days} days kept fresh{s.stored.fetched_at ? `, fetched ${fmtRel(s.stored.fetched_at)}` : ""})
        </span>
        <Button size="sm" className="ml-auto" loading={busy} onClick={fetchNow}>Fetch detections now</Button>
      </div>
      <KpiGrid className="mb-3 grid-cols-[repeat(auto-fill,minmax(145px,1fr))]">
        <Kpi label="Detections" value={s.total} tone="info" foot={`${fmtN(s.hosts)} hosts`} active={!state.severity && !state.open && !state.unassigned && !state.exposed}
          onClick={() => replaceAll({ ...(state.from ? { from: state.from } : {}), ...(state.to ? { to: state.to } : {}) })} />
        <Kpi label="Critical" value={s.critical} tone="crit" active={state.severity === "Critical"} onClick={() => toggle("severity", "Critical")} />
        <Kpi label="High" value={s.high} tone="serious" active={state.severity === "High"} onClick={() => toggle("severity", "High")} />
        <Kpi label="Still open" value={s.open} tone="warn" active={state.open === "1"} onClick={() => toggle("open", "1")} />
        <Kpi label="Open, unassigned" value={s.unassigned} tone="warn" active={state.unassigned === "1"} onClick={() => set({ unassigned: state.unassigned === "1" ? undefined : "1", open: state.unassigned === "1" ? undefined : "1" })} />
        <Kpi label="On exposed assets" value={s.exposed} tone="crit" active={state.exposed === "1"} onClick={() => toggle("exposed", "1")} />
      </KpiGrid>
      <div className="mb-4 grid gap-3 lg:grid-cols-3">
        <Card className="p-3">
          <div className="mb-2 text-[11.5px] text-muted">Per day (dark: critical + high)</div>
          <div className="flex h-20 items-end gap-0.5">
            {s.by_day.map((d: any) => (
              <div key={d.day} className="flex flex-1 flex-col-reverse overflow-hidden rounded-sm bg-accent/40" style={{ height: `${(100 * d.n) / maxDay}%` }} title={`${d.day}: ${d.n} (${d.crit_high} critical / high)`}>
                <div className="bg-crit" style={{ height: `${(100 * d.crit_high) / Math.max(1, d.n)}%` }} />
              </div>
            ))}
            {!s.by_day.length && <span className="text-[12px] text-muted">No detections in this range</span>}
          </div>
        </Card>
        <Card className="p-3">
          <div className="mb-2 text-[11.5px] text-muted">By tactic</div>
          <div className="flex flex-wrap gap-1.5">
            {s.tactics.map((t: any) => (
              <button key={t.tactic} onClick={() => toggle("tactic", t.tactic)}
                className={cn("rounded-md border px-2 py-0.5 text-[12px]", state.tactic === t.tactic ? "border-accent bg-accent-soft text-accent-fg" : "border-border text-fg-2 hover:text-fg")}>
                {t.tactic} <b>{t.n}</b>
              </button>
            ))}
          </div>
        </Card>
        <Card className="p-3">
          <div className="mb-2 text-[11.5px] text-muted">Most affected hosts</div>
          <div className="space-y-1 text-[12px]">
            {s.top_hosts.map((h: any) => (
              <button key={h.aid} onClick={() => toggle("aid", h.aid)} className={cn("flex w-full items-center gap-2 rounded px-1 text-left hover:bg-surface-2", state.aid === h.aid && "bg-accent-soft")}>
                <span className="flex min-w-0 flex-col"><span className="truncate font-medium">{h.hostname || h.aid}</span>
                  <span className="truncate font-mono text-[11px] text-muted">{h.ip}</span></span>
                <span className="ml-auto shrink-0 whitespace-nowrap">{h.crit_high > 0 && <b className="text-crit-fg">{h.crit_high} crit/high · </b>}{h.n}</span>
              </button>
            ))}
          </div>
        </Card>
      </div>
      <DataTable endpoint="/api/detections" exportPath="/api/detections/export" state={{ ...state, from, ...(state.to ? { to: state.to } : {}) }} setState={set}
        noun="detections" storageKey="detections" rowKey={(r: any) => r.id} onReset={() => replaceAll({})} sortable={false} columns={cols}
        renderExpanded={(r: any) => (
          <div className="space-y-1.5 text-[12px]">
            {r.description && <div><span className="text-muted">Description </span>{r.description}</div>}
            {r.cmdline && <div><span className="text-muted">Command line </span><code className="break-all font-mono text-[11.5px]">{r.cmdline}</code></div>}
            <div className="text-muted">Detection ID <Mono>{r.id}</Mono> · Agent <Mono>{r.aid}</Mono>{r.platform_name ? ` · ${r.platform_name}` : ""}{r.online_state ? ` · agent ${r.online_state}` : ""}</div>
          </div>
        )}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Detection, host, IP, file, command line, analyst…" />
          <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="Any" options={[["Critical|High", "Critical + high"], "Critical", "High", "Medium", "Low", "Informational"]} />
          <FilterSelect label="Status" value={state.status} onChange={(v) => set({ status: v })} any="Any" options={s.statuses.map((x: any) => [x.status, `${x.status} (${x.n})`])} />
          {s.lobs.length > 0 && <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v })} any="All" options={s.lobs.map((l: any) => ({ value: String(l.id), label: l.name }))} />}
          <Checkbox checked={state.open === "1"} onChange={(v) => set({ open: v ? "1" : undefined })} label="Open only" />
          {(state.tactic || state.aid) && <Badge tone="info">{state.tactic || "one host"}<button className="ml-1" onClick={() => set({ tactic: undefined, aid: undefined })}>×</button></Badge>}
        </>} />
    </div>
  );
}
