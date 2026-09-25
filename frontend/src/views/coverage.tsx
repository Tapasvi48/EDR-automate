"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Segmented } from "@/components/ui";
import { COLORS, HBars, Legend } from "@/components/charts";
import { InventoryTable } from "@/components/inventory-table";
import { CoverageTable } from "@/components/coverage-table";

const FILTERS = ["applicable", "installed", "pending", "coverage_status", "claimed_missing", "marked_no", "cross_msp_dup"];

export default function Coverage() {
  const [state, set, replaceAll] = useUrlState();
  const { data: meta } = useMeta();
  const [mode, setMode] = React.useState<"lob" | "msp">("msp");
  const { data } = useQuery({ queryKey: ["coverage"], queryFn: () => api<any>("/api/coverage") });
  if (!data) return <Loading />;
  const t = data.lobs.reduce((a: any, l: any) => {
    ["nodes", "applicable", "installed", "online", "offline", "not_installed", "hidden", "removed", "not_feasible", "non_live", "unlisted", "claimed_missing", "marked_no"].forEach((k) => (a[k] = (a[k] || 0) + (l[k] || 0)));
    return a;
  }, {} as Record<string, number>);
  const only = (patch: Record<string, string>) => set({ ...Object.fromEntries(FILTERS.map((f) => [f, undefined])), ...patch });
  const is = (k: string, v = "1") => state[k] === v;
  return (
    <div>
      <PageHeader title="Coverage gaps"
        sub="Every LOB inventory reconciled against Falcon. Applicable = Live and EDR feasible. Installed = an agent for the node is in the console (online or offline). Pending = applicable but not installed, or its agent was removed / hidden." />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(145px,1fr))]">
        <Kpi label="Total nodes" value={t.nodes} tone="info" active={!FILTERS.some((f) => state[f])} onClick={() => only({})} />
        <Kpi label="Applicable" value={t.applicable} active={is("applicable")} onClick={() => only({ applicable: "1" })} />
        <Kpi label="Installed" value={t.installed} tone="good" foot={`${pct(t.installed, t.applicable)}% coverage`} active={is("installed")} onClick={() => only({ installed: "1" })} />
        <Kpi label="Online" value={t.online} tone="good" active={is("coverage_status", "Online")} onClick={() => only({ coverage_status: "Online" })} />
        <Kpi label="Offline" value={t.offline} tone="warn" active={is("coverage_status", "Offline")} onClick={() => only({ coverage_status: "Offline" })} />
        <Kpi label="Pending install" value={t.not_installed + t.hidden + t.removed} tone="crit" foot={`${fmtN(t.not_installed)} not installed · ${fmtN(t.hidden + t.removed)} removed/hidden`} active={is("pending")} onClick={() => only({ pending: "1" })} />
        <Kpi label="Not feasible" value={t.not_feasible} active={is("coverage_status", "Not Feasible")} onClick={() => only({ coverage_status: "Not Feasible" })} />
        <Kpi label="Non Live" value={t.non_live} active={is("coverage_status", "Non Live")} onClick={() => only({ coverage_status: "Non Live" })} />
        <Kpi label="Not in inventory" value={t.unlisted} tone="violet" foot="agents on EDR, missing from inventory" href="/assets/?unlisted=1" />
        <Kpi label="Unmapped agents" value={data.unmapped} tone="violet" foot="in no LOB" href="/assets/?unmapped=1" />
      </KpiGrid>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader title="Coverage by LOB / MSP" right={<Segmented value={mode} onChange={setMode} options={[["msp", "By MSP"], ["lob", "By LOB"]]} />} />
          <CoverageTable rows={mode === "lob" ? data.lobs : data.msps} mode={mode} maxHeight="380px" />
        </Card>
        <Card>
          <CardHeader title="Node type" hint="applicable nodes" />
          <div className="px-4 pb-4">
            <Legend series={[{ key: "i", label: "Installed", color: COLORS.good }, { key: "o", label: "Offline", color: COLORS.warn }, { key: "p", label: "Pending", color: COLORS.crit }]} />
            <HBars items={data.by_node_type.filter((r: any) => r.applicable > 0).map((r: any) => ({
              label: r.label, n: r.applicable, href: `/coverage/?node_type=${encodeURIComponent(r.label)}&applicable=1`,
              title: `${r.label}: ${r.installed}/${r.applicable} installed, ${r.pending} pending`,
              parts: [{ n: r.installed - r.offline, color: COLORS.good }, { n: r.offline, color: COLORS.warn }, { n: r.pending, color: COLORS.crit }],
            }))} />
            <div className="mt-4 rounded-lg bg-surface-2 p-3 text-[12px] text-fg-2">
              Inventory accuracy: <button className="font-semibold text-crit-fg hover:underline" onClick={() => only({ claimed_missing: "1" })}>{fmtN(t.claimed_missing)}</button> say “Yes” with no agent,
              {" "}<button className="font-semibold text-serious-fg hover:underline" onClick={() => only({ marked_no: "1" })}>{fmtN(t.marked_no)}</button> say “No” while an agent runs.
            </div>
          </div>
        </Card>
      </div>

      <div className="mt-4">
        <InventoryTable lobId={0} showLob lobs={meta?.lobs} state={state} set={set} reset={() => replaceAll({})} />
      </div>
    </div>
  );
}
