"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, pct } from "@/lib/format";
import { Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Segmented } from "@/components/ui";
import { StackBar } from "@/components/charts";
import { SimpleTable } from "@/components/data-table";
import { RiskTable } from "./risk";

const SCANNED = "0-30|31-60|61-90|90+";

export default function ScanGaps() {
  const [state, set, replaceAll] = useUrlState();
  const { data: s, error, refetch } = useQuery({
    queryKey: ["scan-gaps", state.lob || "", state.msp || ""],
    queryFn: () => api<any>("/api/scan-gaps/summary", { params: { lob: state.lob, msp: state.msp } }),
  });
  const [group, setGroup] = React.useState<"msp" | "type">("msp");
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const row = (r: any) => ({ ...r, scanned: r.nodes - r.never });
  const t = row(s.total);
  const keep = { ...(state.lob ? { lob: state.lob } : {}), ...(state.msp ? { msp: state.msp } : {}) };
  const rows = (group === "msp" ? s.by_msp : s.by_type).map(row);
  return (
    <div>
      <PageHeader title="Scan coverage"
        sub="Live inventory nodes (scan nodes) and whether their IP has appeared in an uploaded vulnerability scan for their LOB." />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(180px,1fr))]">
        <Kpi label="Live nodes" value={t.nodes} tone="info" foot="nodes that should be scanned" active={!state.scan} onClick={() => replaceAll(keep)} />
        <Kpi label="Scanned" value={t.scanned} tone="good" foot={`${pct(t.scanned, t.nodes)}% of live nodes`} active={state.scan === SCANNED} onClick={() => replaceAll({ ...keep, scan: SCANNED })} />
        <Kpi label="Never scanned" value={t.never} tone="crit" foot={`${fmtN(t.never_no_edr)} of these also have no EDR`} active={state.scan === "never"} onClick={() => replaceAll({ ...keep, scan: "never" })} />
      </KpiGrid>

      <Card className="my-4">
        <CardHeader title={group === "msp" ? "By LOB / MSP" : "By node type"} hint="hover a bar for numbers"
          right={<Segmented value={group} onChange={setGroup} options={[["msp", "LOB / MSP"], ["type", "Node type"]]} />} />
        <SimpleTable rows={rows} maxHeight="360px"
          onRowClick={group === "msp" ? (r: any) => replaceAll({ lob: String(r.lob_id), msp: r.msp_id ? String(r.msp_id) : "none" }) : undefined}
          columns={[
            ...(group === "msp" ? [{ key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> }, { key: "msp", label: "MSP" }]
              : [{ key: "node_type", label: "Node type", render: (r: any) => <b>{r.node_type}</b> }]),
            { key: "nodes", label: "Live nodes", num: true, render: (r: any) => fmtN(r.nodes) },
            { key: "scanned", label: "Scanned", num: true, render: (r: any) => <span className="text-good-fg">{fmtN(r.scanned)}</span> },
            { key: "never", label: "Never scanned", num: true, render: (r: any) => r.never ? <b className="text-crit-fg">{fmtN(r.never)}</b> : <span className="text-muted">0</span> },
            { key: "bar", label: "Scan coverage", render: (r: any) => (
              <div className="flex min-w-[200px] items-center gap-3">
                <StackBar className="flex-1" parts={[{ label: "Scanned", n: r.scanned, color: "var(--good)" }, { label: "Never scanned", n: r.never, color: "var(--crit)" }]} />
                <b className="w-12 text-right tabular">{pct(r.scanned, r.nodes)}%</b>
              </div>) },
            ...(group === "msp" ? [{ key: "last_scan", label: "Latest scan", render: (r: any) => fmtDt(r.last_scan).slice(0, 10) || "–" }] : []),
          ]} />
      </Card>

      <RiskTable state={state} set={set} reset={() => replaceAll(keep)} fixed={{ inventory_live: "1", sort: state.sort || "scan_age_days" }} storageKey="scangaps" scanFocus />
    </div>
  );
}
