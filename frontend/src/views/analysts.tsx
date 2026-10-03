"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, Callout, Card, CardHeader, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Segmented, Sheet } from "@/components/ui";
import { DetectionSheet } from "@/components/detail-sheets";
import { DateRange } from "@/components/date-range";
import { SimpleTable } from "@/components/data-table";
import { useFrom } from "./top-risks";

const SEV_TONE: Record<string, any> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Informational: "neutral" };
const hrs = (h?: number | null) => (h == null ? "–" : h < 48 ? `${h} h` : `${Math.round(h / 24 * 10) / 10} d`);

/** Who worked on how many alerts: CrowdStrike (assigned analyst) and Splunk ES notables (owner), per date range. */
export default function Analysts() {
  const [state, set] = useUrlState();
  const from = useFrom(state.from);
  const params = { from: from || "2000-01-01", to: state.to, severity: state.severity };
  const { data, error, refetch, isFetching } = useQuery({ queryKey: ["analysts", params], queryFn: () => api<any>("/api/analysts", { params }) });
  const [open, setOpen] = React.useState<{ analyst: string; source: string; status: string } | null>(null);
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const k = data.kpi;
  const max = Math.max(1, ...data.rows.map((r: any) => r.total || 0));
  const show = (analyst: string, source: string, status = "") => setOpen({ analyst, source, status });
  const counts = (r: any, src: "cs" | "splunk") => {
    const x = r[src];
    if (!x || !x.total) return <span className="text-muted">–</span>;
    const s = src === "cs" ? "crowdstrike" : "splunk";
    return (
      <span className="flex items-center gap-1 whitespace-nowrap text-[12px]">
        <button className="rounded-md bg-surface-2 px-1.5 py-0.5 font-semibold hover:bg-accent-soft hover:text-accent-fg" onClick={() => show(r.analyst, s)}>{fmtN(x.total)}</button>
        <button className="rounded-md px-1.5 py-0.5 text-good-fg hover:bg-good-soft" onClick={() => show(r.analyst, s, "closed")}>{fmtN(x.closed)} closed</button>
        {(x.new + x.in_progress) > 0 && <button className="rounded-md px-1.5 py-0.5 text-warn-fg hover:bg-warn-soft" onClick={() => show(r.analyst, s, "new|in_progress")}>{fmtN(x.new + x.in_progress)} open</button>}
      </span>
    );
  };
  return (
    <div>
      <PageHeader title="Analyst workload"
        sub="Alerts each analyst worked on: CrowdStrike alerts by assigned analyst and Splunk ES notables by owner. Click a number to open those alerts; click an alert for its full details."
        actions={<Button onClick={() => downloadExcel("/api/analysts/export", params)}><Download /> Excel</Button>} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <DateRange label="Alerts created" from={from} to={state.to} onChange={(f, t) => set({ from: f ?? "all", to: t })} />
        <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="Any" options={["Critical", "High", "Medium", "Low", "Informational"]} />
        {isFetching && <span className="text-xs text-muted">Updating…</span>}
      </div>
      {data.splunk_error && <Callout tone="warn" className="mb-4">Splunk: {data.splunk_error}. Showing CrowdStrike only. Connect it under Integrations.</Callout>}
      {data.splunk_simulated && <Callout tone="info" className="mb-4">Sample data: Splunk numbers are simulated.</Callout>}
      {!data.splunk_simulated && !k.cs_total && <Callout tone="warn" className="mb-4">No CrowdStrike alerts in this range{data.cs_fetched_at ? "" : " — alerts have never been fetched"}.
        Check <a className="underline" href="/settings/">Sync &amp; settings → CrowdStrike API features</a>: the API client needs <b>Alerts: Read</b>, and analysts must assign alerts to themselves in CrowdStrike for them to count here.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Alerts" value={k.total} tone="info" foot={`${fmtN(k.cs_total)} CrowdStrike · ${fmtN(k.splunk_total)} Splunk`} />
        <Kpi label="Closed" value={k.closed} tone="good" foot={k.total ? `${Math.round((100 * k.closed) / k.total)}% of alerts` : ""} />
        <Kpi label="Still open" value={k.open} tone="warn" foot="new or in progress" />
        <Kpi label="Unassigned" value={k.unassigned} tone="crit" foot="click to see them" onClick={() => show("Unassigned", "crowdstrike")} />
        <Kpi label="Analysts" value={k.analysts} foot={`median time to close ${hrs(k.cs_mttr)}`} />
      </KpiGrid>
      <Card>
        <CardHeader title="Per analyst" hint={`${data.from} → ${data.to} · bar: closed (green) and open (amber)`} />
        <SimpleTable rows={data.rows} empty="No alerts in this range"
          columns={[
            { key: "analyst", label: "Analyst", render: (r: any) => r.unassigned ? <Badge tone="crit">Unassigned</Badge> : <b>{r.analyst}</b> },
            { key: "bar", label: "Alerts", render: (r: any) => (
              <span className="flex items-center gap-2">
                <span className="flex h-2 w-40 overflow-hidden rounded-full bg-surface-3" title={`${r.closed} closed · ${r.open} open`}>
                  <span className="bg-good" style={{ width: `${(100 * (r.closed || 0)) / max}%` }} /><span className="bg-warn" style={{ width: `${(100 * (r.open || 0)) / max}%` }} />
                </span>
                <b className="tabular">{fmtN(r.total)}</b>
              </span>) },
            { key: "cs", label: "CrowdStrike", render: (r: any) => counts(r, "cs") },
            { key: "splunk", label: "Splunk", render: (r: any) => counts(r, "splunk") },
            { key: "closed_pct", label: "Closed", num: true, render: (r: any) => r.closed_pct == null ? "–"
              : <span className={r.closed_pct >= 80 ? "text-good-fg" : r.closed_pct >= 50 ? "text-warn-fg" : "text-crit-fg"}>{r.closed_pct}%</span> },
            { key: "crit_high", label: "Crit + high", num: true, render: (r: any) => fmtN(r.crit_high) },
            { key: "mttr", label: "Time to close", render: (r: any) => (
              <span className="text-[12px]">{r.cs?.mttr != null && <span title="CrowdStrike median">CS {hrs(r.cs.mttr)}</span>}
                {r.cs?.mttr != null && r.splunk?.mttr != null && " · "}{r.splunk?.mttr != null && <span title="Splunk average">SPL {hrs(r.splunk.mttr)}</span>}
                {r.cs?.mttr == null && r.splunk?.mttr == null && <span className="text-muted">–</span>}</span>) },
            { key: "last", label: "Last activity", render: (r: any) => r.last ? <span title={fmtDt(r.last)}>{fmtRel(r.last)}</span> : "–" },
          ]} />
        <div className="border-t border-border px-4 py-2 text-[11.5px] text-muted">
          Names are matched across CrowdStrike and Splunk case-insensitively; use the same display name in both tools to see one combined row.
          {data.cs_fetched_at && ` CrowdStrike alerts from the sync at ${fmtDt(data.cs_fetched_at)}.`}
        </div>
      </Card>
      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)} width={1000} title={open ? `${open.analyst} · alerts` : ""}
        sub={`${data.from} → ${data.to}`}>
        {open && <AlertList {...open} set={(p) => setOpen({ ...open, ...p })} params={params} />}
      </Sheet>
    </div>
  );
}

function AlertList({ analyst, source, status, set, params }: { analyst: string; source: string; status: string; set: (p: { source?: string; status?: string }) => void; params: any }) {
  const [q, setQ] = React.useState("");
  const [detail, setDetail] = React.useState<string | null>(null);
  const qp = { ...params, analyst, source, status };
  const { data, error, refetch } = useQuery({ queryKey: ["analyst-alerts", qp], queryFn: () => api<any>("/api/analysts/alerts", { params: qp }) });
  const rows = (data?.rows || []).filter((r: any) => !q || `${r.name} ${r.hostname} ${r.ip} ${r.filename} ${r.tactic}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Segmented value={source} onChange={(v: string) => set({ source: v })} options={[["crowdstrike", "CrowdStrike"], ["splunk", "Splunk"]] as any} />
        <FilterSelect label="Status" value={status} onChange={(v) => set({ status: v })} any="Any" options={[["new", "New"], ["in_progress", "In progress"], ["closed", "Closed"]]} />
        <SearchInput className="w-64" value={q} onChange={setQ} placeholder="Alert, host, IP, file…" />
        {data && <span className="ml-auto text-[12px] text-muted">{fmtN(rows.length)} alerts</span>}
      </div>
      {!data ? <Loading error={error} retry={() => refetch()} /> : (
        <>
          {data.note && <Callout tone="info" className="mb-2">{data.note}</Callout>}
          <Card>
            <SimpleTable rows={rows} maxHeight="calc(100vh - 230px)" empty="No alerts" onRowClick={source === "crowdstrike" ? (r: any) => setDetail(r.id) : undefined}
              columns={[
                { key: "created_at", label: "Created", render: (r: any) => <span title={fmtDt(r.created_at)}>{fmtRel(r.created_at)}</span> },
                { key: "severity", label: "Severity", render: (r: any) => <Badge tone={SEV_TONE[r.severity] || "neutral"}>{r.severity || "–"}</Badge> },
                { key: "name", label: "Alert", wrap: true, render: (r: any) => <span><b className="text-[12.5px]">{r.name}</b>
                  {(r.tactic || r.technique) && <span className="block text-[11.5px] text-muted">{[r.tactic, r.technique].filter(Boolean).join(" · ")}</span>}</span> },
                { key: "hostname", label: "Host", render: (r: any) => r.hostname ? <span>{r.hostname}{r.ip && <span className="block font-mono text-[11px] text-muted">{r.ip}</span>}</span> : "–" },
                { key: "status", label: "Status", render: (r: any) => <Badge tone={/closed|resolved/i.test(r.status || "") ? "good" : /progress/i.test(r.status || "") ? "info" : "warn"}>{(r.status || "new").replace("_", " ")}</Badge> },
                { key: "updated_at", label: "Updated", render: (r: any) => r.updated_at ? <span title={fmtDt(r.updated_at)}>{fmtRel(r.updated_at)}</span> : "–" },
              ]} />
          </Card>
        </>
      )}
      <DetectionSheet id={detail} onClose={() => setDetail(null)} />
    </div>
  );
}
