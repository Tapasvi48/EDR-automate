"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowUpRight, Crosshair, GitMerge, ListFilter, Route, ShieldAlert, SlidersHorizontal, X } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { Badge, Button, Callout, Card, CardHeader, Checkbox, Input, Kpi, KpiGrid, Loading, PageHeader, Segmented, Select, Tabs } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { EdrBadge, SevCounts } from "@/components/badges";
import { GraphLegend, PathGraph, PathSteps, buildPathGraph, worstPath, type GNode } from "@/components/path-graph";
import { cn } from "@/lib/utils";

/** Internet -> exposed asset -> what it can reach inside (communication matrix), with choke points and the rules to tighten. */
export default function AttackPaths() {
  const [state, set] = useUrlState();
  const { data: meta } = useMeta();
  const depth = state.depth || "2";
  const tab = state.tab || "paths";
  const params = { lob: state.lob, depth };
  const { data, error, refetch, isFetching } = useQuery({ queryKey: ["attack-paths", params], queryFn: () => api<any>("/api/attack-paths", { params }) });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const chokes = data.choke_points.filter((c: any) => c.entries > 1);
  const tighten = data.tighten.filter((r: any) => r.weak > 0);
  return (
    <div>
      <PageHeader title="Attack paths"
        sub="How an attacker who lands on an internet-exposed asset could move inside, following the active Allow rules of the communication matrix. Weak assets (critical vulnerability or no EDR) on the way are highlighted. Choke points and rules to tighten show where one fix cuts the most paths." />
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
        <Kpi label="Entry points" value={data.rows.length} tone="info" icon={<Crosshair className="size-3.5" />} foot="internet-exposed assets" onClick={() => set({ tab: undefined, weak: undefined })} active={tab === "paths" && !state.weak} />
        <Kpi label="With a path inside" value={data.with_paths} tone="warn" icon={<Route className="size-3.5" />} foot="matrix lets them move on" onClick={() => set({ tab: undefined, weak: undefined })} />
        <Kpi label="Reach a weak asset" value={data.weak_paths} tone="crit" icon={<ShieldAlert className="size-3.5" />} foot="critical vuln or no EDR on the way" onClick={() => set({ tab: undefined, weak: "1" })} active={tab === "paths" && state.weak === "1"} />
        <Kpi label="Choke points" value={data.choke_total ?? chokes.length} tone="serious" icon={<GitMerge className="size-3.5" />} foot="internal assets on paths from 2+ entries" onClick={() => set({ tab: "choke" })} active={tab === "choke"} />
        <Kpi label="Rules to tighten" value={tighten.length} tone="violet" icon={<SlidersHorizontal className="size-3.5" />} foot={`of ${data.rules.internal} internal matrix rules`} onClick={() => set({ tab: "rules" })} active={tab === "rules"} />
      </KpiGrid>
      {!data.rules.internal && <Callout tone="warn" className="mb-4">The communication matrix has no internal (non-internet) Allow rules, so no path inside can be traced. Upload the full matrix under <Link className="underline" href="/matrix/">Communication matrix</Link>.</Callout>}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Tabs value={tab} onChange={(v) => set({ tab: v === "paths" ? undefined : v })} tabs={[
          { id: "paths", label: "Paths", count: data.with_paths }, { id: "choke", label: "Choke points", count: data.choke_total ?? chokes.length }, { id: "rules", label: "Rules to tighten", count: tighten.length }]} />
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Select value={state.lob} onChange={(v) => set({ lob: v })} placeholder="All LOBs" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />
          <Segmented value={depth} onChange={(v) => set({ depth: v === "2" ? undefined : v })} options={[["1", "1 hop"], ["2", "2 hops"]]} />
          {isFetching && <span className="text-xs text-muted">Updating…</span>}
        </div>
      </div>
      {tab === "paths" && <PathsTab data={data} state={state} set={set} depth={depth} />}
      {tab === "choke" && <ChokeTab rows={data.choke_points} set={set} />}
      {tab === "rules" && <RulesTab rows={data.tighten} />}
    </div>
  );
}

/* ---------------- Paths: entry list + graph ---------------- */
function PathsTab({ data, state, set, depth }: { data: any; state: Record<string, string>; set: any; depth: string }) {
  const [q, setQ] = React.useState("");
  let rows = state.all === "1" ? data.rows : data.rows.filter((r: any) => r.hop1);
  if (state.weak === "1") rows = rows.filter((r: any) => r.weak);
  if (q) rows = rows.filter((r: any) => `${r.name} ${r.ip} ${r.lobs}`.toLowerCase().includes(q.toLowerCase()));
  const sel = state.ip || rows[0]?.ip;
  const max = Math.max(1, ...data.rows.map((r: any) => r.hop1 + r.hop2));
  return (
    <div className="grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
      <Card className="flex max-h-[calc(100vh-220px)] flex-col xl:sticky xl:top-16 xl:self-start">
        <div className="space-y-2 border-b border-border p-3">
          <Input placeholder="Filter entry points…" value={q} onChange={(e) => setQ(e.target.value)} className="w-full" />
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            <Checkbox checked={state.weak === "1"} onChange={(v) => set({ weak: v ? "1" : undefined })} label="Reach a weak asset" />
            <Checkbox checked={state.all === "1"} onChange={(v) => set({ all: v ? "1" : undefined })} label="Include no-path" />
          </div>
        </div>
        <div className="flex-1 overflow-auto scroll-thin p-1.5">
          {!rows.length && <div className="p-4 text-center text-[12.5px] text-muted">No entry point matches</div>}
          {rows.map((r: any) => {
            const tot = r.hop1 + r.hop2;
            return (
              <button key={r.ip} onClick={() => set({ ip: r.ip })}
                className={cn("mb-1 w-full rounded-lg border px-2.5 py-2 text-left transition-colors", r.ip === sel ? "border-accent bg-accent-soft/50" : "border-transparent hover:bg-surface-2")}>
                <div className="flex items-center gap-2">
                  <span className="truncate text-[12.5px] font-semibold">{r.name || r.ip}</span>
                  <span className="ml-auto"><EdrBadge s={r.edr_status} /></span>
                </div>
                <div className="flex items-center justify-between text-[11px] text-muted">
                  <span className="font-mono">{r.ip}{r.entry_ports ? ` :${r.entry_ports}` : ""}</span>
                  {r.weak > 0 && <span className="font-semibold text-crit-fg">{r.weak} weak</span>}
                </div>
                <div className="mt-1.5 flex h-1.5 overflow-hidden rounded-full bg-surface-3" title={`reaches ${tot} (${r.weak} weak)`}>
                  <span className="bg-crit" style={{ width: `${(100 * r.weak) / max}%` }} />
                  <span className="bg-accent/60" style={{ width: `${(100 * (tot - r.weak)) / max}%` }} />
                </div>
              </button>
            );
          })}
        </div>
        <div className="border-t border-border px-3 py-2 text-[11px] text-muted">{fmtN(rows.length)} entry points · bar = assets reachable, red = weak</div>
      </Card>
      {sel ? <PathView ip={sel} depth={depth} set={set} /> : <Card className="grid place-items-center p-10 text-muted">No entry point selected</Card>}
    </div>
  );
}

export function PathView({ ip, depth, set, compact }: { ip: string; depth: string; set?: any; compact?: boolean }) {
  const [weakOnly, setWeakOnly] = React.useState(true);
  const [limit, setLimit] = React.useState(compact ? 6 : 10);
  const [picked, setPicked] = React.useState<GNode | null>(null);
  React.useEffect(() => setPicked(null), [ip]);
  const { data: d, error, refetch } = useQuery({ queryKey: ["attack-path", ip, depth], queryFn: () => api<any>("/api/attack-paths/detail", { params: { ip, depth } }) });
  const g = React.useMemo(() => (d ? buildPathGraph(d, { weakOnly, limit, sources: compact }) : null), [d, weakOnly, limit, compact]);
  if (!d || !g) return compact ? <Loading error={error} retry={() => refetch()} /> : <Card><Loading error={error} retry={() => refetch()} /></Card>;
  const e = d.entry;
  const steps = worstPath(d);
  const nothing = !d.hop1_total && !(compact && d.reached_by?.length) && !d.internet.length;
  const body = (
    <>
      {steps && (
        <div className="border-b border-border px-4 py-3">
          <div className="mb-1.5 flex items-center gap-2 text-[12px] font-semibold text-crit-fg"><ShieldAlert className="size-3.5" /> Most dangerous path</div>
          <PathSteps steps={steps} />
        </div>
      )}
      <div className="flex flex-wrap items-center gap-3 px-4 pt-3">
        <GraphLegend />
        <div className="ml-auto flex items-center gap-2">
          <Checkbox checked={weakOnly} onChange={setWeakOnly} label="Weak targets only" />
          <Select value={String(limit)} onChange={(v) => setLimit(+v)} options={[["6", "6 per hop"], ["10", "10 per hop"], ["20", "20 per hop"], ["40", "40 per hop"]] as [string, string][]} />
        </div>
      </div>
      {nothing ? <div className="p-8 text-center text-[13px] text-good-fg">No matrix rule lets this asset reach, or be reached from, another asset.</div>
        : <PathGraph columns={g.columns} nodes={g.nodes} edges={g.edges} selected={picked?.id} onSelect={setPicked} />}
      {picked && <NodeDetail n={picked} onClose={() => setPicked(null)} set={set} d={d} />}
      {d.broad > 0 && <div className="px-4 pb-3 text-[11.5px] text-warn-fg">{d.broad} rule(s) from this asset allow a destination wider than 4,096 addresses; they are not drawn as paths. Review them in the communication matrix.</div>}
    </>
  );
  if (compact) return body;
  return (
    <Card className="min-w-0">
      <CardHeader title={<span className="flex items-center gap-2"><Crosshair className="size-4 text-accent-fg" /> {e.name || e.ip}
        <span className="font-mono text-[12px] font-normal text-muted">{e.ip}{e.public_ips ? ` ← ${e.public_ips}` : ""}</span></span>}
        hint={`reaches ${d.hop1_total} in 1 hop${depth === "2" ? `, ${d.hop2_total} more in 2 hops` : ""}`}
        right={<Link className="flex items-center gap-1 text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(e.ip)}`}>Asset 360 <ArrowUpRight className="size-3.5" /></Link>} />
      {body}
    </Card>
  );
}

function NodeDetail({ n, onClose, set, d }: { n: GNode; onClose: () => void; set?: any; d: any }) {
  const t = n.data || {};
  if (n.kind === "internet") return (
    <div className="mx-4 mb-4 rounded-xl border border-border bg-surface-2 p-3 text-[12.5px]">
      <div className="mb-2 flex items-center"><b>Inbound internet rules</b><button className="ml-auto text-muted hover:text-fg" onClick={onClose}><X className="size-4" /></button></div>
      {d.internet.length ? <SimpleTable rows={d.internet} columns={[{ key: "rule_id", label: "Rule" }, { key: "ports", label: "Ports", render: (r: any) => `${r.protocol || "any"}/${r.ports}` },
        { key: "zone", label: "Zone" }, { key: "isp", label: "ISP" }, { key: "firewall", label: "Firewall" }, { key: "public", label: "Public IP" }]} />
        : <span className="text-muted">Exposed by a public IP (VA scan / inventory), no inbound matrix rule.</span>}
    </div>
  );
  return (
    <div className="mx-4 mb-4 rounded-xl border border-border bg-surface-2 p-3 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <b className="text-[13.5px]">{n.title}</b><span className="font-mono text-muted">{t.ip}</span><EdrBadge s={t.edr_status} /><SevCounts c={t.crit} h={t.high} />
        {t.weak && <Badge tone="crit">weak</Badge>}
        <button className="ml-auto text-muted hover:text-fg" onClick={onClose}><X className="size-4" /></button>
      </div>
      <div className="mt-1 text-muted">{[t.lobs || "Not in inventory", t.os, t.node_type].filter(Boolean).join(" · ")}</div>
      {t.via?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">{t.via.slice(0, 8).map((v: any, i: number) => (
          <span key={i} className="rounded-md border border-border bg-surface px-2 py-0.5 font-mono text-[11px]">{v.from ? `${v.from} → ` : ""}port {v.ports} · {v.rule_id}</span>))}</div>
      )}
      <div className="mt-2.5 flex gap-2">
        <Link href={`/ip-search/?q=${encodeURIComponent(t.ip)}`}><Button size="sm" variant="soft">Open Asset 360</Button></Link>
        {set && n.kind !== "entry" && <Button size="sm" onClick={() => set({ ip: t.ip, all: "1", tab: undefined })}><ListFilter /> Paths from here</Button>}
      </div>
    </div>
  );
}

/* ---------------- Choke points ---------------- */
function ChokeTab({ rows, set }: { rows: any[]; set: any }) {
  const max = Math.max(1, ...rows.map((r) => r.entries));
  return (
    <Card>
      <CardHeader title="Choke points" hint="internal assets that many attack paths pass through: harden, segment or monitor these first" />
      <SimpleTable rows={rows} maxHeight="65vh" empty="No choke points" onRowClick={(r: any) => set({ tab: undefined, ip: r.ip, all: "1" })} columns={[
        { key: "name", label: "Asset", render: (r: any) => <span className="flex flex-col"><Link className="font-semibold hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip)}`}>{r.name || r.ip}</Link><span className="font-mono text-[11px] text-muted">{r.ip}</span></span> },
        { key: "entries", label: "Entry points through it", render: (r: any) => (
          <span className="flex items-center gap-2"><span className="h-1.5 w-24 overflow-hidden rounded-full bg-surface-3"><span className="block h-full bg-serious" style={{ width: `${(100 * r.entries) / max}%` }} /></span><b>{r.entries}</b></span>) },
        { key: "weak_behind", label: "Weak assets behind it", num: true, render: (r: any) => r.weak_behind ? <b className="text-crit-fg">{r.weak_behind}</b> : <span className="text-muted">0</span> },
        { key: "edr_status", label: "EDR", render: (r: any) => <EdrBadge s={r.edr_status} /> },
        { key: "v", label: "Crit / High", render: (r: any) => <SevCounts c={r.crit} h={r.high} /> },
        { key: "lobs", label: "LOB" }, { key: "node_type", label: "Node type" },
        { key: "act", label: "Suggested action", wrap: true, render: (r: any) => <span className="text-[12px]">{
          r.edr_status === "Not Installed" ? "Install EDR: many paths cross this host unmonitored"
            : r.crit ? "Patch first: a compromised hop here opens the tier behind it"
              : r.weak_behind ? "Segment: restrict what this host may reach" : "Monitor: high-traffic hop"}</span> },
      ]} />
    </Card>
  );
}

/* ---------------- Rules to tighten ---------------- */
function RulesTab({ rows }: { rows: any[] }) {
  return (
    <Card>
      <CardHeader title="Matrix rules that open the most paths" hint="narrowing a rule's source, destination or ports cuts every path it carries" />
      <SimpleTable rows={rows} maxHeight="65vh" empty="No internal rule is on any path" columns={[
        { key: "rule_id", label: "Rule", render: (r: any) => <Link className="font-semibold hover:underline" href={`/matrix/?q=${encodeURIComponent(r.rule_id)}`}>{r.rule_id}</Link> },
        { key: "svc", label: "Service", render: (r: any) => <span><span className="font-mono">{(r.protocol || "any").toUpperCase()} {r.ports}</span>{r.service && <span className="text-muted"> · {r.service}</span>}</span> },
        { key: "zones", label: "Zones", render: (r: any) => `${r.src_zone || "?"} → ${r.dst_zone || "?"}` },
        { key: "firewall", label: "Firewall" },
        { key: "entries", label: "Entry points using it", num: true },
        { key: "targets", label: "Assets it opens", num: true },
        { key: "weak", label: "Weak assets it opens", num: true, render: (r: any) => r.weak ? <Badge tone="crit">{r.weak}</Badge> : <span className="text-muted">0</span> },
      ]} />
    </Card>
  );
}
