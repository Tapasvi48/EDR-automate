"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { daysAgo, fillDays, fmtN, today } from "@/lib/format";
import { Callout, Card, CardHeader, Loading, PageHeader, Segmented, Tabs } from "@/components/ui";
import { COLORS, DayBars } from "@/components/charts";
import { HostTable } from "@/components/host-table";

export default function Health() {
  const [state, set, replaceAll] = useUrlState();
  const tab = state.tab || "offline";
  const { data: d, error: dErr, refetch: dRetry } = useQuery({ queryKey: ["dashboard"], queryFn: () => api<any>("/api/dashboard") });
  const { data: meta } = useMeta();
  if (!d) return <Loading error={dErr} retry={() => dRetry()} />;
  const k = d.kpi;
  const days = meta?.settings.auto_remove_days || "90";
  return (
    <div>
      <PageHeader title="Offline & stale" sub={`Devices that stopped checking in, and sensors that report online but have not been seen recently. Duplicate agents are counted once.`} />
      <Tabs value={tab} onChange={(t) => replaceAll({ tab: t })} tabs={[
        { id: "offline", label: "Offline", count: k.offline },
        { id: "stale", label: "Online · last seen stale", count: k.stale_online },
      ]} />
      {tab === "stale" && <Stale d={d} state={state} set={set} replaceAll={replaceAll} />}
      {tab === "offline" && <Offline d={d} state={state} set={set} replaceAll={replaceAll} />}
      {tab === "removed" && <Callout className="mb-4">Agents that left the console are in <Link className="font-semibold underline" href="/edr-history/">EDR history</Link>.</Callout>}
    </div>
  );
}

type P = { d: any; state: Record<string, string>; set: any; replaceAll: any };

/** Offline has three different causes; the table shows one at a time. EDR history lives here, not on its own tab. */
const OFFLINE_VIEWS: [string, string, Record<string, string>][] = [
  ["console", "Offline in the console", { state: "active", dedupe: "1" }],
  ["removed", "Removed from console", { state: "gone", gone_source: "console", dedupe: "1" }],
  ["import", "Old EDR import", { state: "gone", gone_source: "import", dedupe: "1" }],
];

function Stale({ d, state, set, replaceAll }: P) {
  return (
    <>
      <Callout className="my-4">
        Falcon reports these sensors as <b>online</b>, but their <b>last seen</b> is older than {d.stale_hours}h — usually proxies, sleeping laptops, RFM or cloud connectivity problems.
        {d.kpi.stale_online ? <> <b>{fmtN(d.kpi.stale_online)}</b> hosts: {fmtN(d.stale_buckets.b1_2)} in the last 1–2 h, {fmtN(d.stale_buckets.b2_4)} in 2–4 h, {fmtN(d.stale_buckets.b4_8)} in 4–8 h, {fmtN(d.stale_buckets.b8_24)} in 8–24 h.</> : null}
      </Callout>
      <HostTable state={state} set={set} reset={() => replaceAll({ tab: "stale" })} defaults={{ status: "stale", sort: "last_seen", dir: "asc" }}
        fixed={{ state: "active", dedupe: "1" }} omit={["tab"]} storageKey="health" />
    </>
  );
}

function Offline({ d, state, set, replaceAll }: P) {
  const k = d.kpi;
  const days = state.offline_kind || "console";
  const view = OFFLINE_VIEWS.find((v) => v[0] === days) || OFFLINE_VIEWS[0];
  const { data } = useQuery({ queryKey: ["series", "offline", "29"], queryFn: () => api<any>("/api/series", { params: { kind: "offline", start: daysAgo(29), end: today() } }) });
  return (
    <>
      <Callout className="my-4">
        <b>{fmtN(k.offline)}</b> hosts are offline in the console ({fmtN(k.offline_lt24h)} went offline today, {fmtN(k.offline_1_7d)} 1–7 days ago, {fmtN(k.offline_7_30d)} 7–30 days ago, {fmtN(k.offline_gt30d)} over 30 days ago).
        Agents that left the console (<b>{fmtN(d.removed_devices?.devices || 0)}</b> devices — {fmtN(d.removed_devices?.from_console || 0)} removed from the console, {fmtN(d.removed_devices?.import_only || 0)} known from the old EDR upload) count as Offline too and are in <Link className="font-semibold underline" href="/edr-history/">EDR history</Link>.
      </Callout>
      <Card className="mb-4">
        <CardHeader title="Went offline per day" hint="by last-seen date · click a bar for that day" />
        <div className="px-3 pb-3">
          <DayBars height={180} data={data ? fillDays(data.rows, daysAgo(29), today(), ["n"]) : []} series={[{ key: "n", label: "Went offline", color: COLORS.s2 }]}
            onClick={(r) => set({ last_from: r.day, last_to: r.day, seen_bucket: undefined })} />
        </div>
      </Card>
      <Segmented value={days} onChange={(v) => replaceAll({ tab: "offline", offline_kind: v })} options={OFFLINE_VIEWS.map(([v, l]) => [v, l])} />
      <div className="mt-3">
        <HostTable state={state} set={set} reset={() => replaceAll({ tab: "offline" })}
          defaults={{ ...(view[0] === "console" ? { status: "offline", sort: "last_seen", dir: "desc" } : { sort: "removed_at", dir: "desc" }) }}
          fixed={view[2]} omit={["tab", "offline_kind"]} storageKey="health-offline" removalFilter={view[0] !== "console"} />
      </div>
    </>
  );
}
