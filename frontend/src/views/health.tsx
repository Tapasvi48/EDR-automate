"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { daysAgo, fillDays, today } from "@/lib/format";
import { Callout, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Segmented, Tabs } from "@/components/ui";
import { COLORS, DayBars } from "@/components/charts";
import { HostTable } from "@/components/host-table";

export default function Health() {
  const [state, set, replaceAll] = useUrlState();
  const tab = state.tab || "offline";
  const { data: d } = useQuery({ queryKey: ["dashboard"], queryFn: () => api<any>("/api/dashboard") });
  const { data: meta } = useMeta();
  if (!d) return <Loading />;
  const k = d.kpi;
  const days = meta?.settings.auto_remove_days || "90";
  return (
    <div>
      <PageHeader title="Offline & stale" sub={`Devices that stopped checking in, agents that left the console (deleted, auto-removed after ${days} days, or hidden), and sensors that report online but have not been seen recently. Duplicate agents are counted once.`} />
      <Tabs value={tab} onChange={(t) => replaceAll({ tab: t })} tabs={[
        { id: "offline", label: "Offline", count: k.offline },
        { id: "removed", label: "Removed & hidden", count: k.removed + k.hidden },
        { id: "stale", label: "Online · last seen stale", count: k.stale_online },
      ]} />
      {tab === "stale" && <Stale d={d} state={state} set={set} replaceAll={replaceAll} />}
      {tab === "offline" && <Offline d={d} state={state} set={set} replaceAll={replaceAll} />}
      {tab === "removed" && <Removed d={d} days={days} state={state} set={set} replaceAll={replaceAll} />}
    </div>
  );
}

type P = { d: any; state: Record<string, string>; set: any; replaceAll: any };

function Stale({ d, state, set, replaceAll }: P) {
  const st = d.stale_buckets;
  const b = state.seen_bucket || "";
  return (
    <>
      <KpiGrid>
        {[["", "All stale", d.kpi.stale_online, "crit"], ["1-2h", "Seen 1 – 2 h ago", st.b1_2, "warn"], ["2-4h", "Seen 2 – 4 h ago", st.b2_4, "warn"], ["4-8h", "Seen 4 – 8 h ago", st.b4_8, "serious"], ["8-24h", "Seen 8 – 24 h ago", st.b8_24, "serious"]].map(([bk, l, n, tone]) => (
          <Kpi key={bk as string} label={l} value={n as number} tone={tone as string} active={b === bk} onClick={() => set({ seen_bucket: bk || undefined })} />
        ))}
      </KpiGrid>
      <Callout className="my-4">
        Falcon reports these sensors as <b>online</b>, but their <b>last seen</b> is older than {d.stale_hours}h — usually proxies, sleeping laptops, RFM or cloud connectivity problems.
      </Callout>
      <HostTable state={state} set={set} reset={() => replaceAll({ tab: "stale" })} defaults={{ status: "stale", sort: "last_seen", dir: "asc" }}
        fixed={{ state: "active", dedupe: "1" }} omit={["tab"]} storageKey="health" />
    </>
  );
}

function Offline({ d, state, set, replaceAll }: P) {
  const k = d.kpi;
  const [days, setDays] = React.useState("29");
  const { data } = useQuery({ queryKey: ["series", "offline", days], queryFn: () => api<any>("/api/series", { params: { kind: "offline", start: daysAgo(+days), end: today() } }) });
  const b = state.seen_bucket || "";
  return (
    <>
      <KpiGrid>
        {[["", "All offline", k.offline, "neutral"], ["lt24h", "Went offline today", k.offline_lt24h, "warn"], ["1-7d", "Offline 1 – 7 days", k.offline_1_7d, "serious"], ["7-30d", "Offline 7 – 30 days", k.offline_7_30d, "crit"], ["gt30d", "Offline > 30 days", k.offline_gt30d, "crit"]].map(([bk, l, n, tone]) => (
          <Kpi key={bk as string} label={l} value={n as number} tone={tone as string} active={b === bk && !state.last_from} onClick={() => set({ seen_bucket: bk || undefined, last_from: undefined, last_to: undefined })} />
        ))}
      </KpiGrid>
      <Card className="my-4">
        <CardHeader title="Went offline per day" hint="by last-seen date · click a bar for that day"
          right={<Segmented value={days} onChange={setDays} options={[["6", "7 days"], ["29", "30 days"], ["89", "90 days"]]} />} />
        <div className="px-3 pb-3">
          <DayBars height={180} data={data ? fillDays(data.rows, daysAgo(+days), today(), ["n"]) : []} series={[{ key: "n", label: "Went offline", color: COLORS.s2 }]}
            onClick={(r) => set({ last_from: r.day, last_to: r.day, seen_bucket: undefined })} />
        </div>
      </Card>
      <HostTable state={state} set={set} reset={() => replaceAll({ tab: "offline" })} defaults={{ status: "offline", sort: "last_seen", dir: "desc" }}
        fixed={{ state: "active", dedupe: "1" }} omit={["tab"]} storageKey="health" />
    </>
  );
}

function Removed({ d, days, state, set, replaceAll }: P & { days: string }) {
  const { data: counts } = useQuery({
    queryKey: ["removed-counts"],
    queryFn: async () => {
      const [del, auto] = await Promise.all([
        api<any>("/api/hosts", { params: { state: "removed", removal_type: "deleted", size: 1 } }),
        api<any>("/api/hosts", { params: { state: "removed", removal_type: "auto_inactive", size: 1 } }),
      ]);
      return { deleted: del.total, auto: auto.total };
    },
  });
  const view = state.view || "";
  const pick = (v: string) => set({ view: view === v ? undefined : v });
  const fixed: Record<string, string> = view === "hidden" ? { state: "hidden" } : view === "deleted" ? { state: "removed", removal_type: "deleted" } : view === "auto" ? { state: "removed", removal_type: "auto_inactive" } : { state: "gone" };
  return (
    <>
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(240px,1fr))]">
        <Kpi label="Deleted manually" value={counts?.deleted ?? "–"} tone="crit" foot="removed from the console while still recently active" active={view === "deleted"} onClick={() => pick("deleted")} />
        <Kpi label={`Removed > ${days} days`} value={counts?.auto ?? "–"} tone="serious" foot={`auto-removed by Falcon after ${days} days without check-in`} active={view === "auto"} onClick={() => pick("auto")} />
        <Kpi label="Hidden" value={d.kpi.hidden} tone="violet" foot="hidden in the console" active={view === "hidden"} onClick={() => pick("hidden")} />
      </KpiGrid>
      <div className="mt-4">
        <HostTable state={state} set={set} reset={() => replaceAll({ tab: "removed" })} defaults={{ sort: "removed_at", dir: "desc" }}
          fixed={fixed} omit={["tab", "view"]} storageKey="removed" removalFilter
          title={view ? { deleted: "Deleted manually", auto: `Removed > ${days} days`, hidden: "Hidden" }[view] : "Removed & hidden"} />
      </div>
    </>
  );
}
