"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { daysAgo, fillDays, fmtN, today } from "@/lib/format";
import { Button, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader } from "@/components/ui";
import { COLORS, DayBars } from "@/components/charts";
import { HostTable } from "@/components/host-table";
import { MappedUpload } from "@/components/mapped-upload";

/** Offline = offline in the console + EDR history (agents that left the console, or known only from an old EDR export).
 *  One row per device: duplicate agents of a machine are merged. */
const VIEWS: Record<string, { fixed: Record<string, string>; defaults: Record<string, string> }> = {
  all: { fixed: { state: "active", status: "offline", history: "1", dedupe: "1" }, defaults: { sort: "last_seen", dir: "desc" } },
  console: { fixed: { state: "active", status: "offline", history: "0", dedupe: "1" }, defaults: { sort: "last_seen", dir: "desc" } },
  removed: { fixed: { state: "gone", gone_source: "console", dedupe: "1" }, defaults: { sort: "removed_at", dir: "desc" } },
  import: { fixed: { state: "gone", gone_source: "import", dedupe: "1" }, defaults: { sort: "removed_at", dir: "desc" } },
};

export default function Health() {
  const [state, set, replaceAll] = useUrlState();
  const { data: d, error, refetch } = useQuery({ queryKey: ["dashboard"], queryFn: () => api<any>("/api/dashboard") });
  const { data: h } = useQuery({ queryKey: ["edr-history"], queryFn: () => api<any>("/api/edr-history/summary") });
  const { data: series } = useQuery({ queryKey: ["series", "offline", "29"], queryFn: () => api<any>("/api/series", { params: { kind: "offline", start: daysAgo(29), end: today() } }) });
  const { data: meta } = useMeta();
  const [upload, setUpload] = React.useState(false);
  if (!d) return <Loading error={error} retry={() => refetch()} />;
  const k = d.kpi;
  const days = meta?.settings.auto_remove_days || "90";
  const view = VIEWS[state.view] ? state.view : "all";
  const v = VIEWS[view];
  const pick = (x: string) => replaceAll(x === "all" ? {} : { view: x });
  return (
    <div>
      <PageHeader title="Offline"
        sub={`Devices whose CrowdStrike agent is not checking in: offline in the console, removed from it (auto-removed after ${days} days offline, or deleted), or known only from an uploaded old EDR inventory. One row per device.`}
        actions={<Button onClick={() => setUpload(true)}><Upload /> Upload old EDR inventory</Button>} />
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(180px,1fr))]">
        <Kpi label="All offline" value={k.offline + (h?.devices ?? 0)} tone="crit" foot="console + EDR history" active={view === "all"} onClick={() => pick("all")} />
        <Kpi label="Offline in the console" value={k.offline} tone="serious" foot={`${fmtN(k.offline_lt24h)} today · ${fmtN(k.offline_gt30d)} > 30 days`} active={view === "console"} onClick={() => pick("console")} />
        <Kpi label="Removed from console" value={h?.from_console ?? "–"} tone="warn" foot={h ? `${fmtN(h.auto)} auto-removed · ${fmtN(h.deleted)} deleted` : undefined} active={view === "removed"} onClick={() => pick("removed")} />
        <Kpi label="Old EDR import only" value={h?.import_only ?? "–"} foot="known only from an old inventory" active={view === "import"} onClick={() => pick("import")} />
      </KpiGrid>
      {(view === "all" || view === "console") && (
        <Card className="mb-4">
          <CardHeader title="Went offline per day" hint="by last-seen date · click a bar for that day" />
          <div className="px-3 pb-3">
            <DayBars height={150} data={series ? fillDays(series.rows, daysAgo(29), today(), ["n"]) : []} series={[{ key: "n", label: "Went offline", color: COLORS.s2 }]}
              onClick={(r) => set({ last_from: r.day, last_to: r.day })} />
          </div>
        </Card>
      )}
      <HostTable key={view} state={state} set={set} reset={() => pick(view)} defaults={v.defaults} fixed={v.fixed} omit={["view"]}
        storageKey="offline" removalFilter={view !== "console"} />
      {upload && <MappedUpload kind="edr" open onOpenChange={setUpload} />}
    </div>
  );
}
