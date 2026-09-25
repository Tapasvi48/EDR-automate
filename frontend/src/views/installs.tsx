"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { daysAgo, fillDays, pct, today } from "@/lib/format";
import { Card, CardHeader, Input, Kpi, KpiGrid, PageHeader, Segmented } from "@/components/ui";
import { COLORS, DayBars } from "@/components/charts";
import { HostTable } from "@/components/host-table";

const PRESETS: [string, string, () => [string, string]][] = [
  ["0", "Today", () => [today(), today()]], ["1", "Yesterday", () => [daysAgo(1), daysAgo(1)]],
  ["6", "7 days", () => [daysAgo(6), today()]], ["29", "30 days", () => [daysAgo(29), today()]], ["89", "90 days", () => [daysAgo(89), today()]],
];

export default function Installs() {
  const defaults = React.useMemo(() => ({ first_from: daysAgo(6), first_to: today(), sort: "first_seen", dir: "desc" }), []);
  const [state, set, replaceAll] = useUrlState(defaults);
  const from = state.first_from || daysAgo(6), to = state.first_to || today();
  const { data } = useQuery({ queryKey: ["series", "installs", from, to], queryFn: () => api<any>("/api/series", { params: { kind: "installs", start: from, end: to } }) });
  const rows: any[] = data ? fillDays(data.rows, from, to, ["n", "reinstalls", "still_active"]).map((r) => ({ ...r, fresh: r.n - r.reinstalls })) : [];
  const tot = rows.reduce((a, r) => a + r.n, 0), re = rows.reduce((a, r) => a + r.reinstalls, 0);
  const preset = PRESETS.find(([, , f]) => { const [a, b] = f(); return a === from && b === to; })?.[0] || "custom";
  return (
    <div>
      <PageHeader
        title="New installs"
        sub={<>Agents by first-seen (install) date. A <b>reinstall</b> means an older, different agent ID already had the same connection IP — the sensor was reinstalled or the machine re-imaged.</>}
        actions={<>
          <Segmented value={preset} onChange={(v) => { const p = PRESETS.find((x) => x[0] === v); if (p) { const [a, b] = p[2](); set({ first_from: a, first_to: b }); } }}
            options={PRESETS.map(([k, l]) => [k, l] as [string, string])} />
          <Input type="date" value={from} onChange={(e) => set({ first_from: e.target.value })} className="w-[150px]" />
          <span className="text-muted">→</span>
          <Input type="date" value={to} onChange={(e) => set({ first_to: e.target.value })} className="w-[150px]" />
        </>}
      />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(220px,1fr))]">
        <Kpi label="New agents" value={tot} tone="info" active={!state.reinstall} onClick={() => set({ reinstall: undefined })} />
        <Kpi label="Fresh installs" value={tot - re} tone="good" foot="no earlier agent on the same connection IP" />
        <Kpi label="Reinstalls" value={re} tone="violet" foot={`${pct(re, tot)}% of new agents`} active={state.reinstall === "1"} onClick={() => set({ reinstall: state.reinstall === "1" ? undefined : "1" })} />
      </KpiGrid>
      <Card className="mt-4">
        <CardHeader title="Installs per day" hint={`${from} → ${to} · click a bar to filter`} />
        <div className="px-3 pb-3">
          <DayBars data={rows} height={220} series={[{ key: "fresh", label: "Fresh install", color: COLORS.s1 }, { key: "reinstalls", label: "Reinstall", color: COLORS.s7 }]}
            onClick={(r) => set({ first_from: r.day, first_to: r.day })} />
        </div>
      </Card>
      <div className="mt-4">
        <HostTable state={state} set={set} reset={() => replaceAll({})} defaults={defaults} fixed={{ state: "all" }} storageKey="installs" title="Agents first seen in range" />
      </div>
    </div>
  );
}
