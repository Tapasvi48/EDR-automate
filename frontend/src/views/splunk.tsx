"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Activity, AlertTriangle, Check, ChevronDown, Code2, Copy, Database, FileText, Gauge, Radio, RefreshCw, Server, Settings2, ShieldAlert, Siren, Unplug } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Field, Input, Kpi, KpiGrid, Loading, Modal, PageHeader, SearchInput, Select, Tabs } from "@/components/ui";
import { DataTable, SimpleTable, type Column } from "@/components/data-table";
import { COLORS, DayBars, HBars, TrendLines } from "@/components/charts";
import { SyncProgress } from "@/components/sync-progress";
import { ExplainButton } from "@/components/ai/brief";

const TABS = [["overview", "Overview", Gauge], ["coverage", "Asset coverage", ShieldAlert], ["hosts", "Hosts", Server], ["sources", "Log sources", FileText],
  ["eps", "EPS", Activity], ["notables", "Detections", Siren], ["indexes", "Indexes & license", Database], ["forwarders", "Forwarders", Radio],
  ["sync", "Sync", RefreshCw]] as const;
const PALETTE = [COLORS.s1, COLORS.s2, COLORS.s3, COLORS.s4, COLORS.s5, COLORS.s7, COLORS.s8, COLORS.serious, COLORS.warn, COLORS.good];
const URG: Record<string, any> = { critical: "crit", high: "serious", medium: "warn", low: "info", informational: "neutral" };
const LOG_TONE: Record<string, any> = { Logging: "good", Reporting: "good", Silent: "warn", "No logs": "crit", Stale: "warn", Active: "good" };

/** Splunk automation: log sources, EPS, detections, indexes, forwarders, license — synced and matched to the assets. */
export default function SplunkView() {
  const [state, set, replaceAll] = useUrlState();
  const tab = TABS.some(([id]) => id === state.tab) ? state.tab : "overview";
  const qc = useQueryClient();
  const { data: st, refetch: refetchStatus } = useQuery({ queryKey: ["splunk-sync"], queryFn: () => api<any>("/api/splunk/sync/status"),
    refetchInterval: (q) => ((q.state.data as any)?.running ? 1500 : 30_000) });
  const { data: s, error } = useQuery({ queryKey: ["splunk-summary"], queryFn: () => api<any>("/api/splunk/summary") });
  const wasRunning = React.useRef(false);
  React.useEffect(() => {  // a sync just finished: refresh every Splunk view
    if (wasRunning.current && st && !st.running) {
      qc.invalidateQueries({ predicate: (x) => String(x.queryKey[0]).startsWith("splunk") && x.queryKey[0] !== "splunk-sync" });
      st.error ? toast.error(`Splunk sync: ${st.error}`) : toast.success("Splunk sync complete");
    }
    wasRunning.current = !!st?.running;
  }, [st, qc]);
  const sync = async (full = false) => {
    try { const r = await api<any>("/api/splunk/sync", { method: "POST", body: { full } }); r.ok ? toast.message(r.message) : toast.warning(r.message); refetchStatus(); }
    catch (e: any) { toast.error(e.message); }
  };
  if (!s) return <Loading error={error} />;
  const never = !s.last?.sync_at;
  return (
    <div>
      <PageHeader title="Splunk SIEM"
        sub={<>Which assets send logs, how much (EPS, license), from which sources, and what Splunk ES detects — synced from Splunk and joined with the asset registry.
          {s.last?.sync_at ? ` Last sync ${fmtRel(s.last.sync_at)}.` : ""}{s.demo && !s.configured ? " Sample data: Splunk is simulated." : ""}</>}
        actions={<>
          {st?.running ? <Badge tone="info"><RefreshCw className="mr-1 inline size-3 animate-spin" />Syncing…</Badge> : null}
          <Button onClick={() => replaceAll({ tab: "sync" })}><Settings2 /> Settings</Button>
          <Button variant="primary" disabled={st?.running} onClick={() => sync(false)}><RefreshCw className={st?.running ? "animate-spin" : ""} /> Sync now</Button>
        </>} />
      {!s.configured && !s.demo && (
        <Callout tone="warn" className="mb-4"><Unplug className="mr-1 inline size-4" /> Splunk is not connected. Add the management URL (port 8089) and a token on
          {" "}<Link className="underline" href="/connectors/">Integrations</Link>, then sync.</Callout>
      )}
      {st?.running && <div className="mb-4"><SyncProgress status={st} compact /></div>}
      {never && !st?.running ? (
        <Card className="p-8 text-center">
          <div className="mx-auto mb-3 flex size-12 items-center justify-center rounded-2xl bg-accent-soft text-accent-fg"><Database className="size-6" /></div>
          <div className="text-[15px] font-semibold">No Splunk data yet</div>
          <p className="mx-auto mt-1 max-w-md text-[13px] text-fg-2">The first sync reads 7 days of host and source statistics, EPS, notables, indexes, forwarders and license usage. Later syncs read only what changed.</p>
          <Button className="mt-4" variant="primary" onClick={() => sync(true)}><RefreshCw /> Run the first sync</Button>
        </Card>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap gap-1 rounded-2xl border border-border bg-surface p-1 shadow-card">
            {TABS.map(([id, label, Icon]) => (
              <button key={id} onClick={() => replaceAll(id === "overview" ? {} : { tab: id })}
                className={cn("flex items-center gap-1.5 whitespace-nowrap rounded-xl px-3 py-1.5 text-[12.5px] font-medium transition",
                  tab === id ? "bg-accent text-white shadow" : "text-fg-2 hover:bg-surface-2 hover:text-fg")}><Icon className="size-3.5" />{label}</button>
            ))}
          </div>
          {tab === "overview" && <Overview s={s} go={(t, extra = {}) => replaceAll({ tab: t, ...extra })} />}
          {tab === "coverage" && <Coverage state={state} set={set} replaceAll={replaceAll} lobs={s.by_lob} />}
          {tab === "hosts" && <Hosts state={state} set={set} replaceAll={replaceAll} />}
          {tab === "sources" && <Sources />}
          {tab === "eps" && <Eps />}
          {tab === "notables" && <Notables state={state} set={set} replaceAll={replaceAll} />}
          {tab === "indexes" && <Indexes />}
          {tab === "forwarders" && <Forwarders />}
          {tab === "sync" && <SyncTab st={st} sync={sync} />}
        </>
      )}
    </div>
  );
}

function Overview({ s, go }: { s: any; go: (t: string, extra?: Record<string, string>) => void }) {
  const c = s.coverage;
  const pct = c.assets ? Math.round((100 * c.logging) / c.assets) : 0;
  const { data: eps } = useQuery({ queryKey: ["splunk-eps", 7], queryFn: () => api<any>("/api/splunk/eps", { params: { days: 7 } }) });
  const top = (eps?.indexes || []).slice(0, 6);
  return (
    <div className="space-y-4">
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(165px,1fr))]">
        <Kpi label="Assets logging" value={`${pct}%`} tone={pct >= 90 ? "good" : pct >= 70 ? "warn" : "crit"} foot={`${fmtN(c.logging)} of ${fmtN(c.assets)} in the last ${s.silent_hours} h`} onClick={() => go("coverage", { log: "logging" })} />
        <Kpi label="EDR but no logs" value={c.edr_no_logs} tone="crit" foot="CrowdStrike sees it, Splunk doesn't" onClick={() => go("coverage", { gap: "edr_no_logs" })} />
        <Kpi label="Exposed, no logs" value={c.exposed_no_logs} tone="crit" foot="internet-facing and blind in the SIEM" onClick={() => go("coverage", { gap: "exposed_no_logs" })} />
        <Kpi label="Silent hosts" value={s.hosts.silent} tone="warn" foot={`logged before, nothing for ${s.silent_hours} h`} onClick={() => go("hosts", { status: "silent" })} />
        <Kpi label="Unknown log sources" value={s.hosts.unmatched} tone="violet" foot="Splunk hosts in no inventory" onClick={() => go("hosts", { matched: "0" })} />
        <Kpi label="EPS now" value={fmtN(Math.round(s.eps.now))} tone="info" foot={`24 h avg ${fmtN(Math.round(s.eps.avg_24h))} · peak ${fmtN(Math.round(s.eps.peak_7d))}`} onClick={() => go("eps")} />
        <Kpi label="License / day" value={`${fmtN(s.license.yesterday_gb)} GB`} tone="neutral" foot={`30-day avg ${fmtN(s.license.avg_gb)} · max ${fmtN(s.license.max_gb)}`} onClick={() => go("indexes")} />
        <Kpi label="Open ES notables" value={s.notables.open} tone={s.notables.open_crit_high ? "crit" : "neutral"} foot={`${fmtN(s.notables.open_crit_high)} critical / high · ${fmtN(s.notables.last_24h)} in 24 h`} onClick={() => go("notables", { open: "1" })} />
      </KpiGrid>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader title="Events per second, last 7 days" hint="per index (hourly averages)" right={<button className="text-[12px] text-accent-fg hover:underline" onClick={() => go("eps")}>Details →</button>} />
          <div className="px-3 pb-3">{eps ? <TrendLines data={eps.rows} xKey="hour" height={230} series={top.map((i: string, k: number) => ({ key: i, label: i, color: PALETTE[k] }))} /> : <Loading />}</div>
        </Card>
        <Card>
          <CardHeader title="Logging coverage per LOB" hint="assets sending logs in the window" />
          <div className="max-h-[300px] overflow-y-auto px-4 pb-4 scroll-thin">
            {s.by_lob.map((l: any) => {
              const p = l.assets ? Math.round((100 * (l.logging || 0)) / l.assets) : 0;
              return (
                <div key={l.lob} className="border-t border-border py-2 first:border-0">
                  <div className="flex items-center gap-2 text-[12.5px]"><b className="min-w-0 flex-1 truncate">{l.lob}</b>
                    <span className="tabular text-fg-2">{fmtN(l.logging || 0)} / {fmtN(l.assets)}</span><b className={cn("w-11 text-right tabular", p >= 90 ? "text-good-fg" : p >= 70 ? "text-warn-fg" : "text-crit-fg")}>{p}%</b></div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-3"><div className={cn("h-full rounded-full", p >= 90 ? "bg-good" : p >= 70 ? "bg-warn" : "bg-crit")} style={{ width: `${p}%` }} /></div>
                  {l.edr_no_logs > 0 && <div className="mt-0.5 text-[11px] text-muted">{fmtN(l.edr_no_logs)} with EDR but no logs · {fmtN(l.never || 0)} never logged</div>}
                </div>
              );
            })}
          </div>
        </Card>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <MiniStat icon={Database} title="Indexes" value={`${fmtN(s.indexes.n)}`} foot={`${fmtN(s.indexes.gb)} GB stored · ${fmtN(s.indexes.stale)} with no event in 24 h`} onClick={() => go("indexes")} warn={s.indexes.stale > 0} />
        <MiniStat icon={Radio} title="Forwarders" value={`${fmtN(s.forwarders.n)}`} foot={`${fmtN(s.forwarders.silent)} not connected for 4 h`} onClick={() => go("forwarders")} warn={s.forwarders.silent > 0} />
        <MiniStat icon={Server} title="Hosts reporting" value={`${fmtN(s.hosts.reporting)}`} foot={`${fmtN(s.hosts.total)} known to Splunk · ${fmtN(s.hosts.events_24h)} events in 24 h`} onClick={() => go("hosts")} />
      </div>
    </div>
  );
}

const MiniStat = ({ icon: Icon, title, value, foot, onClick, warn }: { icon: React.ElementType; title: string; value: string; foot: string; onClick: () => void; warn?: boolean }) => (
  <button onClick={onClick} className="flex items-center gap-3 rounded-2xl border border-border bg-surface p-3.5 text-left shadow-card transition hover:-translate-y-0.5 hover:border-accent/50">
    <span className={cn("flex size-10 items-center justify-center rounded-xl", warn ? "bg-warn-soft text-warn-fg" : "bg-accent-soft text-accent-fg")}><Icon className="size-5" /></span>
    <span className="min-w-0"><span className="block text-[12px] text-muted">{title}</span><span className="block text-[18px] font-semibold tabular">{value}</span>
      <span className="block truncate text-[11.5px] text-fg-2">{foot}</span></span>
  </button>
);

function Coverage({ state, set, replaceAll, lobs }: any) {
  const cols: Column[] = [
    { key: "ip", label: "IP", render: (r) => <Link className="font-mono text-accent-fg hover:underline" href={`/ip-search/?q=${r.ip}`}>{r.ip}</Link> },
    { key: "name", label: "Asset", render: (r) => r.name || <span className="text-muted">–</span> },
    { key: "lobs", label: "LOB" }, { key: "edr_status", label: "EDR", render: (r) => <Badge tone={r.edr_status === "Online" ? "good" : r.edr_status === "Offline" ? "warn" : "crit"}>{r.edr_status}</Badge> },
    { key: "log_status", label: "Splunk", sort: "last_log", render: (r) => <Badge tone={LOG_TONE[r.log_status]}>{r.log_status}</Badge> },
    { key: "last_log", label: "Last event", render: (r) => r.last_log ? <span title={fmtDt(r.last_log)}>{fmtRel(r.last_log)}</span> : <span className="text-muted">never</span> },
    { key: "indexes", label: "Indexes", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.indexes || "–"}</span> },
    { key: "splunk_hosts", label: "Splunk host", hidden: true },
    { key: "exposed", label: "Internet exposed", render: (r) => r.exposed ? <Badge tone="crit">yes</Badge> : "–" },
  ];
  return (
    <DataTable endpoint="/api/splunk/coverage" columns={cols} state={state} setState={set} omit={["tab"]} storageKey="splunk-cov" noun="assets" rowKey={(r: any) => r.ip}
      onReset={() => replaceAll({ tab: "coverage" })}
      filters={<>
        <SearchInput className="w-56" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP or asset name" />
        <Select className="w-44" value={state.log || ""} onChange={(v) => set({ log: v })} placeholder="Any logging state"
          options={[{ value: "logging", label: "Logging" }, { value: "silent", label: "Silent" }, { value: "none", label: "No logs" }]} />
        <Select className="w-52" value={state.gap || ""} onChange={(v) => set({ gap: v })} placeholder="Any gap"
          options={[{ value: "edr_no_logs", label: "EDR but no logs" }, { value: "logs_no_edr", label: "Logs but no EDR" }, { value: "exposed_no_logs", label: "Exposed, no logs" }]} />
      </>} />
  );
}

function Hosts({ state, set, replaceAll }: any) {
  const cols: Column[] = [
    { key: "host", label: "Splunk host", render: (r) => <span className="font-medium">{r.host}</span> },
    { key: "status", label: "Status", sort: "last_seen", render: (r) => <Badge tone={LOG_TONE[r.status]}>{r.status}</Badge> },
    { key: "last_seen", label: "Last event", render: (r) => <span title={fmtDt(r.last_seen)}>{fmtRel(r.last_seen)}</span> },
    { key: "events_24h", label: "Events 24 h", num: true, render: (r) => fmtN(r.events_24h) }, { key: "events_7d", label: "Events 7 d", num: true, render: (r) => fmtN(r.events_7d) },
    { key: "indexes", label: "Indexes", wrap: true, render: (r) => <span className="text-[12px]">{r.indexes || "–"}</span> },
    { key: "sourcetypes", label: "Sourcetypes", wrap: true, hidden: true },
    { key: "asset_ip", label: "Asset", render: (r) => r.asset_ip ? <Link className="text-accent-fg hover:underline" href={`/ip-search/?q=${r.asset_ip}`}>{r.asset_name || r.asset_ip}</Link> : <Badge tone="violet">not in inventory</Badge> },
    { key: "lob", label: "LOB" }, { key: "edr_status", label: "EDR", render: (r) => r.edr_status || "–" },
  ];
  return (
    <DataTable endpoint="/api/splunk/hosts" columns={cols} state={state} setState={set} omit={["tab"]} storageKey="splunk-hosts" noun="hosts" rowKey={(r: any) => r.host}
      onReset={() => replaceAll({ tab: "hosts" })}
      filters={<>
        <SearchInput className="w-56" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Host, IP, LOB" />
        <Select className="w-40" value={state.status || ""} onChange={(v) => set({ status: v })} placeholder="Any status"
          options={[{ value: "reporting", label: "Reporting" }, { value: "silent", label: "Silent" }]} />
        <Select className="w-48" value={state.matched || ""} onChange={(v) => set({ matched: v })} placeholder="Matched or not"
          options={[{ value: "1", label: "Matched to an asset" }, { value: "0", label: "Not in any inventory" }]} />
      </>} />
  );
}

function Sources() {
  const { data } = useQuery({ queryKey: ["splunk-sources"], queryFn: () => api<any>("/api/splunk/sources") });
  if (!data) return <Loading />;
  return (
    <Card>
      <CardHeader title="Log sources (index · sourcetype)" hint="7-day volume, hosts sending it, newest event — a source with no event in the silent window is Stale" />
      <SimpleTable rows={data.rows} maxHeight="65vh" columns={[
        { key: "idx", label: "Index", render: (r: any) => <b>{r.idx}</b> }, { key: "sourcetype", label: "Sourcetype" },
        { key: "status", label: "Status", render: (r: any) => <Badge tone={LOG_TONE[r.status]}>{r.status}</Badge> },
        { key: "hosts", label: "Hosts", num: true, render: (r: any) => fmtN(r.hosts) }, { key: "events_7d", label: "Events 7 d", num: true, render: (r: any) => fmtN(r.events_7d) },
        { key: "eps", label: "Avg EPS", num: true, render: (r: any) => fmtN(r.eps) }, { key: "last_seen", label: "Last event", render: (r: any) => fmtRel(r.last_seen) },
        { key: "first_seen", label: "First seen", render: (r: any) => fmtDt(r.first_seen).slice(0, 10) }]} />
    </Card>
  );
}

function Eps() {
  const [days, setDays] = React.useState("7");
  const { data } = useQuery({ queryKey: ["splunk-eps", days], queryFn: () => api<any>("/api/splunk/eps", { params: { days } }) });
  if (!data) return <Loading />;
  const totals = data.rows.map((r: any) => ({ hour: r.hour, total: Math.round(data.indexes.reduce((a: number, i: string) => a + (r[i] || 0), 0)) }));
  const avg = totals.length ? totals.reduce((a: number, r: any) => a + r.total, 0) / totals.length : 0;
  const peak = totals.reduce((m: any, r: any) => (r.total > (m?.total || 0) ? r : m), null);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2"><Select className="w-36" value={days} onChange={setDays} options={["1", "3", "7", "14"].map((d) => ({ value: d, label: `last ${d} day${d === "1" ? "" : "s"}` }))} />
        <span className="text-[12.5px] text-fg-2">average <b>{fmtN(Math.round(avg))}</b> EPS · peak <b>{fmtN(peak?.total || 0)}</b> EPS {peak ? `at ${fmtDt(peak.hour)}` : ""}</span></div>
      <Card><CardHeader title="Total events per second" /><div className="px-3 pb-3"><TrendLines data={totals} xKey="hour" height={220} series={[{ key: "total", label: "All indexes", color: COLORS.s1 }]} /></div></Card>
      <Card><CardHeader title="Per index" /><div className="px-3 pb-3"><TrendLines data={data.rows} xKey="hour" height={300} series={data.indexes.map((i: string, k: number) => ({ key: i, label: i, color: PALETTE[k % PALETTE.length] }))} /></div></Card>
    </div>
  );
}

function Notables({ state, set, replaceAll }: any) {
  const cols: Column[] = [
    { key: "created_at", label: "When", render: (r) => <span title={fmtDt(r.created_at)}>{fmtRel(r.created_at)}</span> },
    { key: "urgency", label: "Urgency", render: (r) => <Badge tone={URG[r.urgency] || "neutral"}>{r.urgency || "–"}</Badge> },
    { key: "rule", label: "Detection", wrap: true, render: (r) => <span className="font-medium">{r.rule}</span> },
    { key: "domain", label: "Domain" }, { key: "host", label: "Host", render: (r) => r.asset_ip ? <Link className="text-accent-fg hover:underline" href={`/ip-search/?q=${r.asset_ip}&view=detections`}>{r.host}</Link> : r.host },
    { key: "src", label: "Source" }, { key: "dest", label: "Destination", hidden: true }, { key: "user", label: "User" },
    { key: "status", label: "Status", render: (r) => <Badge tone={/closed|resolved/i.test(r.status || "") ? "good" : /progress/i.test(r.status || "") ? "info" : "warn"}>{r.status || "New"}</Badge> },
    { key: "owner", label: "Owner" }, { key: "lob", label: "LOB", hidden: true },
  ];
  return (
    <DataTable endpoint="/api/splunk/notables" columns={cols} state={state} setState={set} omit={["tab"]} storageKey="splunk-notables" noun="notables" rowKey={(r: any) => r.event_id}
      onReset={() => replaceAll({ tab: "notables" })}
      filters={<>
        <SearchInput className="w-56" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Rule, host, user, IP" />
        <Select className="w-36" value={state.urgency || ""} onChange={(v) => set({ urgency: v })} placeholder="Any urgency"
          options={["critical", "high", "medium", "low"].map((u) => ({ value: u, label: u }))} />
        <Select className="w-36" value={state.open || ""} onChange={(v) => set({ open: v })} placeholder="Open or closed" options={[{ value: "1", label: "Open only" }]} />
        <Select className="w-36" value={state.days || ""} onChange={(v) => set({ days: v })} placeholder="Any time"
          options={[["1", "Last 24 h"], ["7", "Last 7 days"], ["30", "Last 30 days"]].map(([v, l]) => ({ value: v, label: l }))} />
      </>} />
  );
}

function Indexes() {
  const { data } = useQuery({ queryKey: ["splunk-indexes"], queryFn: () => api<any>("/api/splunk/indexes") });
  const { data: lic } = useQuery({ queryKey: ["splunk-license"], queryFn: () => api<any>("/api/splunk/license", { params: { days: 30 } }) });
  if (!data) return <Loading />;
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader title="License usage per day (GB)" hint="from Splunk's license usage log — needs read access to _internal" />
        <div className="px-3 pb-3">{lic?.rows?.length ? <DayBars data={lic.rows} height={240} series={lic.indexes.map((i: string, k: number) => ({ key: i, label: i, color: PALETTE[k % PALETTE.length] }))} />
          : <div className="p-4 text-[12.5px] text-muted">No license data (no access to _internal, or not synced yet).</div>}</div>
      </Card>
      <Card>
        <CardHeader title="Indexes" hint="size, events, retention, newest event — an index with no event in a day is flagged" />
        <SimpleTable rows={data.rows} maxHeight="50vh" columns={[
          { key: "name", label: "Index", render: (r: any) => <b>{r.name}</b> },
          { key: "stale", label: "State", render: (r: any) => r.disabled ? <Badge>disabled</Badge> : r.stale ? <Badge tone="warn"><AlertTriangle className="mr-1 inline size-3" />no event in 24 h</Badge> : <Badge tone="good">receiving</Badge> },
          { key: "size_mb", label: "Size", num: true, render: (r: any) => r.size_mb >= 1024 ? `${fmtN(Math.round(r.size_mb / 1024))} GB` : `${fmtN(Math.round(r.size_mb))} MB` },
          { key: "events", label: "Events", num: true, render: (r: any) => fmtN(r.events) },
          { key: "license_gb_day", label: "License GB / day", num: true, render: (r: any) => fmtN(r.license_gb_day) },
          { key: "retention_days", label: "Retention", num: true, render: (r: any) => `${fmtN(r.retention_days)} d` },
          { key: "max_time", label: "Newest event", render: (r: any) => fmtRel(r.max_time) }, { key: "min_time", label: "Oldest event", render: (r: any) => fmtDt(r.min_time).slice(0, 10) }]} />
      </Card>
    </div>
  );
}

function Forwarders() {
  const { data } = useQuery({ queryKey: ["splunk-forwarders"], queryFn: () => api<any>("/api/splunk/forwarders") });
  if (!data) return <Loading />;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
      <Card>
        <CardHeader title="Universal forwarders" hint="connected to the indexers in the last 24 h (needs read access to _internal)" />
        <SimpleTable rows={data.rows} maxHeight="65vh" empty="No forwarder data" columns={[
          { key: "hostname", label: "Forwarder", render: (r: any) => <b>{r.hostname}</b> }, { key: "ip", label: "IP" }, { key: "version", label: "Version" },
          { key: "os", label: "OS" }, { key: "last_seen", label: "Last connected", render: (r: any) => fmtRel(r.last_seen) },
          { key: "asset_ip", label: "Asset", render: (r: any) => r.asset_ip ? <Link className="text-accent-fg hover:underline" href={`/ip-search/?q=${r.asset_ip}`}>{r.asset_ip}</Link> : "–" }]} />
      </Card>
      <Card><CardHeader title="Versions" /><div className="px-4 pb-4"><HBars items={data.versions.map((v: any) => ({ label: v.version || "unknown", n: v.n }))} /></div></Card>
    </div>
  );
}

function SyncTab({ st, sync }: { st: any; sync: (full?: boolean) => void }) {
  const qc = useQueryClient();
  const [minutes, setMinutes] = React.useState(String(st?.minutes ?? 60));
  const [silent, setSilent] = React.useState(String(st?.silent_hours ?? 24));
  const save = async () => { await api("/api/splunk/sync/settings", { method: "PUT", body: { minutes: +minutes, silent_hours: +silent } }); toast.success("Saved"); qc.invalidateQueries({ queryKey: ["splunk-sync"] }); };
  if (!st) return <Loading />;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
      <div className="space-y-4">
        <SyncProgress status={st} />
        <QueryPlan running={st.running} />
        <Card>
          <CardHeader title="Sync history" />
          <SimpleTable rows={st.runs} maxHeight="40vh" columns={[{ key: "started_at", label: "Started", render: (r: any) => fmtDt(r.started_at) },
            { key: "status", label: "Result", render: (r: any) => <Badge tone={r.status === "ok" ? "good" : r.status === "running" ? "info" : "crit"}>{r.status}</Badge> },
            { key: "full", label: "Type", render: (r: any) => r.full ? "full" : "incremental" }, { key: "message", label: "Message", wrap: true }]} />
        </Card>
      </div>
      <div className="space-y-4">
        <Card className="p-4">
          <div className="mb-3 text-[13px] font-semibold">Schedule</div>
          <div className="space-y-3">
            <Field label="Sync every" hint="0 = manual only"><Select className="max-w-none" value={minutes} onChange={setMinutes}
              options={[["0", "Manual only"], ["15", "15 minutes"], ["30", "30 minutes"], ["60", "1 hour"], ["180", "3 hours"], ["720", "12 hours"], ["1440", "1 day"]].map(([v, l]) => ({ value: v, label: l }))} /></Field>
            <Field label="Silent after (hours)" hint="a host or source with no event for this long is Silent / Stale"><Input type="number" min={1} value={silent} onChange={(e) => setSilent(e.target.value)} /></Field>
            <Button variant="primary" onClick={save}>Save</Button>
          </div>
        </Card>
        <Card className="p-4 text-[12.5px]">
          <div className="mb-2 font-semibold">How often each step reads Splunk</div>
          <ul className="space-y-1 text-fg-2">
            {st.schedule.map((x: any) => <li key={x.key} className="flex justify-between gap-2"><span>{x.label}</span><span className="text-muted">{x.every_minutes ? `once every ${x.every_minutes / 60} h` : "every sync"}</span></li>)}
          </ul>
          <p className="mt-2 text-[11.5px] text-muted">Hosts and notables are incremental; EPS continues from the last stored hour. Full refresh re-reads everything.</p>
          <div className="mt-3 flex gap-2"><Button onClick={() => sync(false)} disabled={st.running}><RefreshCw /> Sync now</Button>
            <Button onClick={() => sync(true)} disabled={st.running}>Full refresh</Button></div>
        </Card>
      </div>
    </div>
  );
}

/** The exact Splunk searches the next sync (or a full refresh) runs, step by step, with time range and whether the step is due. */
function QueryPlan({ running }: { running: boolean }) {
  const [full, setFull] = React.useState(false);
  const [open, setOpen] = React.useState<Record<string, boolean>>({});
  const { data } = useQuery({ queryKey: ["splunk-plan", full, running], queryFn: () => api<any>(`/api/splunk/sync/plan?full=${full}`) });
  const allOpen = data?.steps?.every((x: any) => open[x.key]);
  return (
    <Card>
      <CardHeader title={<span className="flex items-center gap-2"><Code2 className="size-4 text-accent" /> Queries this sync runs</span>}
        hint={data ? `Splunk ${data.endpoint}${data.simulated ? " · sample data: simulated, nothing is sent" : data.url ? ` · ${data.url}` : ""}` : undefined}
        right={<div className="ml-auto flex items-center gap-2">
          <div className="flex rounded-lg border border-border p-0.5 text-[12px]">
            {[[false, "Next sync"], [true, "Full refresh"]].map(([v, l]) => (
              <button key={String(v)} onClick={() => setFull(v as boolean)}
                className={cn("rounded-md px-2.5 py-1 font-medium transition", full === v ? "bg-accent text-white" : "text-fg-2 hover:text-fg")}>{l as string}</button>))}
          </div>
          <Button size="sm" onClick={() => setOpen(allOpen ? {} : Object.fromEntries((data?.steps || []).map((x: any) => [x.key, true])))}>{allOpen ? "Collapse all" : "Expand all"}</Button>
        </div>} />
      {!data ? <Loading /> : (
        <div className="divide-y divide-border">
          {data.steps.map((x: any, i: number) => (
            <div key={x.key} className={cn(!x.due && "opacity-60")}>
              <button onClick={() => setOpen((o) => ({ ...o, [x.key]: !o[x.key] }))} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2">
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-surface-2 text-[11px] font-semibold text-fg-2">{i + 1}</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[13px] font-medium">{x.label}</span>
                  <span className="block text-[11.5px] text-muted">
                    {x.each_sync ? "every sync" : `once every ${x.every_minutes / 60} h`}
                    {x.last_ok && <> · last ok {fmtRel(x.last_ok)}</>}
                    {x.optional && <> · optional (skipped if the token may not read it)</>}
                  </span>
                </span>
                <Badge tone={x.due ? "info" : "neutral"}>{x.due ? "will run" : "skipped — fresh"}</Badge>
                <span className="w-16 text-right text-[11.5px] text-muted">{x.queries.length ? `${x.queries.length} search${x.queries.length > 1 ? "es" : ""}` : "local"}</span>
                <ChevronDown className={cn("size-4 text-muted transition", open[x.key] && "rotate-180")} />
              </button>
              {open[x.key] && (
                <div className="space-y-2 px-4 pb-3 sm:pl-[52px]">
                  {x.note && <p className="text-[12px] text-fg-2">{x.note}</p>}
                  {x.queries.map((q: any) => <QueryBlock key={q.name} q={q} />)}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {data && <p className="border-t border-border px-4 py-2 text-[11.5px] text-muted">Index filter from Integrations → Splunk: <code className="text-fg-2">{data.index_filter}</code>.
        Searches use the export endpoint, so results stream and large result sets never sit in memory.</p>}
    </Card>
  );
}

function QueryBlock({ q }: { q: any }) {
  const [copied, setCopied] = React.useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(q.query); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { toast.error("Copy failed"); }
  };
  return (
    <div className="rounded-xl border border-border bg-surface-2/60">
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5 text-[11.5px]">
        <span className="font-medium text-fg-2">{q.name}</span>
        {q.fallback && <Badge tone="neutral">fallback</Badge>}
        <span className="ml-auto text-muted">earliest <code className="text-fg-2">{q.earliest}</code> · latest <code className="text-fg-2">{q.latest}</code></span>
        <button onClick={copy} title="Copy SPL" className="rounded p-1 text-muted hover:bg-surface hover:text-fg">{copied ? <Check className="size-3.5 text-good" /> : <Copy className="size-3.5" />}</button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-[12px] leading-relaxed text-fg">{q.query}</pre>
    </div>
  );
}
