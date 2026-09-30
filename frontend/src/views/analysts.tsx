"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, Callout, Card, CardHeader, Kpi, KpiGrid, Loading, Modal, PageHeader, Select, Tabs } from "@/components/ui";
import { DateRange } from "@/components/date-range";
import { SimpleTable } from "@/components/data-table";
import { HBars, COLORS } from "@/components/charts";
import { useFrom } from "./top-risks";

const SEV_TONE: Record<string, any> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Informational: "neutral" };
const hrs = (h?: number | null) => (h == null ? "–" : h < 48 ? `${h} h` : `${Math.round(h / 24 * 10) / 10} d`);

/** Who worked on how many alerts: CrowdStrike (assigned analyst) and Splunk ES notables (owner), per date range. */
export default function Analysts() {
  const [state, set] = useUrlState();
  const from = useFrom(state.from);
  const params = { from: from || "2000-01-01", to: state.to, severity: state.severity };
  const { data, error, refetch, isFetching } = useQuery({ queryKey: ["analysts", params], queryFn: () => api<any>("/api/analysts", { params }) });
  const [open, setOpen] = React.useState<{ analyst: string; source: string } | null>(null);
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const k = data.kpi;
  const assigned = data.rows.filter((r: any) => !r.unassigned);
  const cell = (r: any, src: "cs" | "splunk") => {
    const x = r[src];
    if (!x) return <span className="text-muted">–</span>;
    return (
      <button className="text-left hover:underline" onClick={() => setOpen({ analyst: r.analyst, source: src === "cs" ? "crowdstrike" : "splunk" })}>
        <b>{fmtN(x.total)}</b> <span className="text-[11.5px] text-muted">· {fmtN(x.closed)} closed · {fmtN(x.new + x.in_progress)} open</span>
      </button>
    );
  };
  return (
    <div>
      <PageHeader title="Analyst workload"
        sub="Alerts each analyst worked on in the date range: CrowdStrike alerts by assigned analyst, Splunk Enterprise Security notable events by owner, and both together. Click a count to see the alerts."
        actions={<Button onClick={() => downloadExcel("/api/analysts/export", params)}><Download /> Excel</Button>} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <DateRange label="Alerts created" from={from} to={state.to} onChange={(f, t) => set({ from: f ?? "all", to: t })} />
        <Select value={state.severity} onChange={(v) => set({ severity: v })} placeholder="Any severity" options={["Critical", "High", "Medium", "Low"]} />
        {isFetching && <span className="text-xs text-muted">Updating…</span>}
      </div>
      {data.splunk_error && <Callout tone="warn" className="mb-4">Splunk: {data.splunk_error}. Showing CrowdStrike only. Connect it under Integrations.</Callout>}
      {data.splunk_simulated && <Callout tone="info" className="mb-4">Sample data: Splunk numbers are simulated.</Callout>}
      <KpiGrid className="mb-4">
        <Kpi label="Alerts (both)" value={k.total} tone="info" foot={`${fmtN(k.cs_total)} CrowdStrike · ${fmtN(k.splunk_total)} Splunk`} />
        <Kpi label="Closed" value={k.closed} tone="good" foot={k.total ? `${Math.round((100 * k.closed) / k.total)}% of alerts` : ""} />
        <Kpi label="Still open" value={k.open} tone="warn" foot="new or in progress" />
        <Kpi label="Unassigned" value={k.unassigned} tone="crit" foot="nobody picked them up" onClick={() => setOpen({ analyst: "Unassigned", source: "crowdstrike" })} />
        <Kpi label="Analysts" value={k.analysts} foot={`CrowdStrike median to close: ${hrs(k.cs_mttr)}`} />
      </KpiGrid>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,8fr)_minmax(0,4fr)]">
        <Card>
          <CardHeader title="Per analyst" hint={`${data.from} → ${data.to}`} />
          <SimpleTable rows={data.rows} empty="No alerts in this range"
            columns={[
              { key: "analyst", label: "Analyst", render: (r: any) => r.unassigned ? <Badge tone="crit">Unassigned</Badge> : <b>{r.analyst}</b> },
              { key: "total", label: "Total", num: true, render: (r: any) => <b>{fmtN(r.total)}</b> },
              { key: "cs", label: "CrowdStrike", render: (r: any) => cell(r, "cs") },
              { key: "splunk", label: "Splunk", render: (r: any) => cell(r, "splunk") },
              { key: "closed_pct", label: "Closed", num: true, render: (r: any) => r.closed_pct == null ? "–"
                : <span className={r.closed_pct >= 80 ? "text-good-fg" : r.closed_pct >= 50 ? "text-warn-fg" : "text-crit-fg"}>{r.closed_pct}%</span> },
              { key: "crit_high", label: "Crit + High", num: true, render: (r: any) => fmtN(r.crit_high) },
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
        <Card>
          <CardHeader title="Alerts handled" hint="closed vs open, both sources" />
          <div className="p-4">
            <HBars items={assigned.map((r: any) => ({ label: r.analyst, n: r.total, parts: [{ n: r.closed, color: COLORS.good }, { n: r.open, color: COLORS.warn }] }))} />
            <div className="mt-3 flex gap-3 text-[11.5px] text-muted">
              <span className="flex items-center gap-1"><i className="size-2.5 rounded-sm" style={{ background: COLORS.good }} /> Closed</span>
              <span className="flex items-center gap-1"><i className="size-2.5 rounded-sm" style={{ background: COLORS.warn }} /> Open</span>
            </div>
          </div>
        </Card>
      </div>
      <Modal open={!!open} onOpenChange={(o) => !o && setOpen(null)} wide title={open ? `${open.analyst} · alerts` : ""}>
        {open && <AlertList {...open} setSource={(s) => setOpen({ ...open, source: s })} params={params} />}
      </Modal>
    </div>
  );
}

function AlertList({ analyst, source, setSource, params }: { analyst: string; source: string; setSource: (s: string) => void; params: any }) {
  const [status, setStatus] = React.useState("");
  const q = { ...params, analyst, source, status };
  const { data, error, refetch } = useQuery({ queryKey: ["analyst-alerts", q], queryFn: () => api<any>("/api/analysts/alerts", { params: q }) });
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Tabs value={source} onChange={setSource} tabs={[{ id: "crowdstrike", label: "CrowdStrike" }, { id: "splunk", label: "Splunk" }]} />
        <Select value={status} onChange={setStatus} placeholder="Any status" options={[["new", "New"], ["in_progress", "In progress"], ["closed", "Closed"]] as [string, string][]} />
      </div>
      {!data ? <Loading error={error} retry={() => refetch()} /> : (
        <>
          {data.note && <Callout tone="info" className="mb-2">{data.note}</Callout>}
          <SimpleTable rows={data.rows} maxHeight="60vh" empty="No alerts"
            columns={[
              { key: "created_at", label: "Created", render: (r: any) => fmtDt(r.created_at) },
              { key: "severity", label: "Severity", render: (r: any) => <Badge tone={SEV_TONE[r.severity] || "neutral"}>{r.severity || "–"}</Badge> },
              { key: "name", label: "Alert", wrap: true },
              { key: "hostname", label: "Host", render: (r: any) => r.hostname ? <a className="hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.hostname)}`}>{r.hostname}</a> : "–" },
              { key: "status", label: "Status", render: (r: any) => <Badge tone={/closed|resolved/i.test(r.status || "") ? "good" : /progress/i.test(r.status || "") ? "info" : "warn"}>{(r.status || "new").replace("_", " ")}</Badge> },
              { key: "updated_at", label: "Closed / updated", render: (r: any) => r.updated_at ? fmtDt(r.updated_at) : "–" },
            ]} />
        </>
      )}
    </div>
  );
}
