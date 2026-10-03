"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Tabs } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";

const LV_TONE: Record<string, any> = { N: "good", "N-1": "info", "N-2": "warn", older: "crit" };
const ST_TONE: Record<string, any> = { Supported: "good", Legacy: "warn", "Not supported": "crit" };

/** Sensor versions: the N / N-1 / N-2 builds CrowdStrike publishes, how many agents run each version, which OS the sensor
 *  supports (the catalog EDR feasibility uses) and the Linux kernels CrowdStrike lists as supported. */
export default function Sensors() {
  const qc = useQueryClient();
  const [state, set, replaceAll] = useUrlState();
  const tab = state.tab || "fleet";
  const { data, error, refetch } = useQuery({ queryKey: ["cs-sensors"], queryFn: () => api<any>("/api/crowdstrike/sensors") });
  const [busy, setBusy] = React.useState(false);
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const refresh = async () => {
    setBusy(true);
    try { const r = await api<any>("/api/sensor-support/refresh", { method: "POST" }); toast.success(r.message); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const total = data.fleet.reduce((a: number, r: any) => a + r.agents, 0);
  const lv = (k: string) => Object.values(data.levels).reduce((a: number, x: any) => a + (x[k] || 0), 0) as number;
  const q = (state.q || "").toLowerCase();
  const plat = (state.platform || "").split("|").filter(Boolean);
  const cat = data.catalog.filter((e: any) => (!q || e.pattern.toLowerCase().includes(q)) && (!plat.length || plat.includes(e.platform))
    && (!state.status || state.status.split("|").includes(e.status)));
  return (
    <div>
      <PageHeader title="Sensor versions & OS support"
        sub={<>Builds CrowdStrike tags N / N-1 / N-2 (Sensor update policies API), which sensor every agent runs, and which operating systems the sensor supports — the same list <Link className="underline" href="/feasibility/">EDR feasibility</Link> decides with.
          {data.fetched?.at ? ` Fetched ${fmtDt(data.fetched.at)}${data.fetched.kernels ? ` · ${fmtN(data.fetched.kernels)} Linux kernels` : ""}.` : " Not fetched from CrowdStrike yet."}</>}
        actions={<Button loading={busy} onClick={refresh}><RefreshCw /> Refresh from CrowdStrike</Button>} />
      {data.fetched?.kernel_error && <Callout tone="warn" className="mb-4">Supported kernels: {data.fetched.kernel_error}</Callout>}
      <div className="mb-4 grid gap-3 md:grid-cols-3">
        {Object.entries(data.builds).map(([p, bs]: [string, any]) => (
          <Card key={p} className="p-3">
            <div className="mb-2 text-[12.5px] font-semibold">{p}</div>
            <div className="space-y-1 text-[12.5px]">
              {bs.map((b: any) => <div key={b.tag} className="flex items-center gap-2"><Badge tone={LV_TONE[b.tag] || "neutral"}>{b.tag}</Badge><span className="font-mono">{b.version}</span>
                <span className="ml-auto text-[11.5px] text-muted">release {b.release} · {b.stage}</span></div>)}
            </div>
          </Card>
        ))}
        {!Object.keys(data.builds).length && <Callout tone="warn">No sensor builds yet: the API client needs <b>Sensor update policies: Read</b>.</Callout>}
      </div>
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
        <Kpi label="Agents" value={total} tone="info" />
        <Kpi label="On N" value={lv("N")} tone="good" href="/assets/?sensor_level=N" />
        <Kpi label="On N-1" value={lv("N-1")} tone="info" href="/assets/?sensor_level=N-1" />
        <Kpi label="On N-2" value={lv("N-2")} tone="warn" href="/assets/?sensor_level=N-2" />
        <Kpi label="Older than N-2" value={lv("older")} tone="crit" href="/assets/?sensor_level=older" />
      </KpiGrid>
      <Tabs value={tab} onChange={(v) => replaceAll(v === "fleet" ? {} : { tab: v })} tabs={[
        { id: "fleet", label: "Agents per version", count: data.fleet.length }, { id: "os", label: "Supported OS", count: data.catalog.length },
        { id: "linux", label: "Linux kernels", count: data.linux.length }, { id: "unmatched", label: "OS not in the list", count: data.unmatched.length }]} />
      {tab === "fleet" && <Card><SimpleTable rows={data.fleet} maxHeight="60vh" empty="No agents" columns={[
        { key: "platform", label: "Platform" },
        { key: "version", label: "Sensor version", render: (r: any) => <span className="font-mono">{r.version}</span> },
        { key: "level", label: "Level", render: (r: any) => <Badge tone={LV_TONE[r.level] || "neutral"}>{r.level || "–"}</Badge> },
        { key: "agents", label: "Agents", num: true, render: (r: any) => <Link className="font-semibold text-accent-fg hover:underline" href={`/assets/?agent_version=${encodeURIComponent(r.version)}`}>{fmtN(r.agents)}</Link> },
        { key: "online", label: "Online", num: true },
        { key: "share", label: "Share", render: (r: any) => <span className="flex items-center gap-2"><span className="h-1.5 w-24 overflow-hidden rounded-full bg-surface-3"><span className="block h-full bg-accent" style={{ width: `${(100 * r.agents) / Math.max(1, total)}%` }} /></span><span className="text-[11.5px] text-muted">{Math.round((100 * r.agents) / Math.max(1, total))}%</span></span> },
      ]} /></Card>}
      {tab === "os" && <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-2.5">
          <SearchInput className="w-64" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="OS…" />
          <FilterSelect label="Platform" value={state.platform} onChange={(v) => set({ platform: v })} any="All" options={["Windows", "Linux", "macOS", "Other"]} />
          <FilterSelect label="Support" value={state.status} onChange={(v) => set({ status: v })} any="Any" options={data.statuses} />
        </div>
        <SimpleTable rows={cat} maxHeight="60vh" columns={[
          { key: "platform", label: "Platform" }, { key: "pattern", label: "OS", render: (e: any) => <b>{e.pattern}</b> },
          { key: "status", label: "Sensor support", render: (e: any) => <Badge tone={ST_TONE[e.status] || "neutral"}>{e.status}</Badge> },
          { key: "last_sensor", label: "Last sensor for it", render: (e: any) => e.last_sensor ? <span className="font-mono text-[12px]">{e.last_sensor}</span> : <span className="text-muted">–</span> },
          { key: "nodes", label: "Inventory nodes", num: true }, { key: "installed", label: "With EDR", num: true },
          { key: "source", label: "Source", render: (e: any) => <span className="text-[12px] text-fg-2">{{ custom: "edited", crowdstrike: "CrowdStrike API", baseline: "built-in" }[e.source as string] || e.source}</span> },
        ]} />
      </Card>}
      {tab === "linux" && <Card><SimpleTable rows={data.linux} maxHeight="60vh" empty="No kernel list fetched (needs Sensor update policies: Read)" columns={[
        { key: "distro", label: "Distribution" }, { key: "version", label: "Version" }, { key: "kernels", label: "Supported kernels", num: true },
        { key: "newest_sensor", label: "Newest sensor", render: (r: any) => <span className="font-mono text-[12px]">{r.newest_sensor}</span> },
        { key: "oldest_sensor", label: "Oldest sensor", render: (r: any) => <span className="font-mono text-[12px]">{r.oldest_sensor}</span> },
        { key: "n2_supported", label: "N-2 supported", render: (r: any) => r.n2_supported ? <Badge tone="good">yes</Badge> : <Badge tone="warn">no</Badge> },
      ]} /></Card>}
      {tab === "unmatched" && <Card><SimpleTable rows={data.unmatched} maxHeight="60vh" empty="Every inventory OS is in the list" columns={[
        { key: "os", label: "OS (inventory)", render: (r: any) => <b>{r.os}</b> }, { key: "n", label: "Nodes", num: true },
        { key: "go", label: "", render: (r: any) => <Link className={cn("text-[12px] text-accent-fg hover:underline")} href={`/feasibility/?os=${encodeURIComponent(r.os)}`}>decide in EDR feasibility →</Link> },
      ]} /></Card>}
    </div>
  );
}
