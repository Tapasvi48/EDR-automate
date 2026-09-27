"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Check, History, MoreHorizontal, Plus, RefreshCw, RotateCcw, ShieldCheck, ShieldOff, Trash2, X } from "lucide-react";
import { api } from "@/lib/api";
import { fmtRel } from "@/lib/format";
import { useUrlState } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Checkbox, FilterSelect, Kpi, KpiGrid, Loading, Menu, PageHeader, SearchInput, Select, Tabs } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { useSyncStatus } from "@/components/sync-progress";
import { EdrBadge, FeasibleBadge, Live, Mono, OsCell, OsSupportBadge, SensorCell, YN } from "@/components/badges";

type Rules = { os: string[]; node_type: string[]; domain: string[]; os_yes?: string[]; node_type_yes?: string[]; domain_yes?: string[]; use_inventory_column: boolean };
type Facet = { value: string; nodes: number; not_feasible: number; installed: number };
const GROUPS: { key: "node_type" | "domain"; title: string; how: string; placeholder: string }[] = [
  { key: "node_type", title: "Node type", how: "is", placeholder: "e.g. Firewall, Switch, Server" },
  { key: "domain", title: "Domain", how: "is", placeholder: "e.g. VAS, NMS, Core (node domain, not DNS)" },
];
const same = (a: Rules, b: Rules) => JSON.stringify(a) === JSON.stringify(b);

/** EDR feasibility for every inventory node, decided from OS / node type / domain rules (plus manual decisions). */
export default function Feasibility() {
  const qc = useQueryClient();
  const [state, set, replaceAll] = useUrlState();
  const { data, error, refetch } = useQuery({ queryKey: ["feasibility"], queryFn: () => api<any>("/api/feasibility") });
  const [draft, setDraft] = React.useState<Rules | null>(null);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => { if (data && !draft) setDraft(data.rules); }, [data, draft]);
  const dirty = !!(data && draft && !same(data.rules, draft));
  const { data: status } = useSyncStatus() as { data?: any };
  const { data: old } = useQuery({ queryKey: ["feas-sensor-old"], queryFn: () => api<any>("/api/feasibility/nodes", { params: { sensor: "older", size: "1" } }) });
  const sensorOld = old?.total;
  const { data: impact } = useQuery({
    queryKey: ["feasibility-preview", draft], enabled: dirty,
    queryFn: () => api<any>("/api/feasibility/preview", { method: "POST", body: draft }),
  });
  if (!data || !draft) return <Loading error={error} retry={() => refetch()} />;
  const s = data.summary;

  const save = async () => {
    setSaving(true);
    try {
      const r = await api<any>("/api/feasibility/rules", { method: "PUT", body: draft });
      setDraft(r.rules);
      toast.success("Rules saved · feasibility, applicability and coverage recalculated");
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
  };
  const decide = async (feasible: "Yes" | "No" | "Legacy" | null, body: any) => {
    try {
      const r = await api<any>("/api/feasibility/override", { method: "POST", body: { feasible, ...body } });
      toast.success(`${fmtN(r.updated)} node${r.updated === 1 ? "" : "s"} ${feasible ? `set to ${({ Yes: "feasible", No: "not feasible", Legacy: "legacy" } as any)[feasible]}` : "back to the rules"}`);
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); }
  };
  const on = (k: string, v: string) => state[k] === v;
  const filterNow = Object.fromEntries(Object.entries(state).filter(([k]) => !["page", "size", "sort", "dir"].includes(k)));

  const cols: Column[] = [
    { key: "lob", label: "LOB", render: (r) => <b>{r.lob}</b> },
    { key: "ip", label: "IP", render: (r) => <Mono>{r.ip}</Mono> },
    { key: "node_name", label: "Node name" },
    { key: "node_type", label: "Node type" },
    { key: "domain", label: "Domain" },
    { key: "os", label: "OS", render: (r) => <OsCell os={r.os_resolved} src={r.os_source} /> },
    { key: "os_support", label: "OS support (N-2)", sort: false, render: (r) => <OsSupportBadge v={r.os_support} /> },
    { key: "live", label: "Live / Non Live", sort: false, hidden: true, render: (r) => <Live v={r.live} /> },
    { key: "edr", label: "EDR", render: (r) => <EdrBadge s={r.edr_state} /> },
    { key: "sensor", label: "Sensor", sort: false, render: (r) => r.edr_state === "Not Installed" ? <span className="text-muted">–</span> : <SensorCell v={r.cs_agent_version} level={r.sensor_level} /> },
    { key: "feasible", label: "EDR feasible", render: (r) => <FeasibleBadge v={r.feasible} reason={r.feasible_reason} /> },
    { key: "reason", label: "Why", render: (r) => <span className={cn("text-[12px]", r.feasible_reason?.startsWith("Set manually") ? "font-medium text-accent-fg" : "text-fg-2")}>{r.feasible_reason}</span> },
    { key: "edr_feasible", label: "Sheet says", sort: false, render: (r) => <YN v={r.edr_feasible} /> },
    { key: "act", label: "", sort: false, render: (r) => {
      const item = { items: [{ lob_id: r.lob_id, item_key: r.item_key }] };
      return (
        <Menu width={220} trigger={<Button size="icon" variant="ghost" aria-label="Decide"><MoreHorizontal /></Button>} items={[
          { label: "Mark feasible", icon: <ShieldCheck />, onSelect: () => decide("Yes", item) },
          { label: "Mark not feasible", icon: <ShieldOff />, onSelect: () => decide("No", item) },
          { label: "Mark legacy", icon: <History />, onSelect: () => decide("Legacy", item) },
          ...(r.feasible_reason?.startsWith("Set manually") ? ["sep" as const, { label: "Back to the rules", icon: <RotateCcw />, onSelect: () => decide(null, item) }] : []),
        ]} />
      );
    } },
  ];

  return (
    <div>
      <PageHeader title="EDR feasibility"
        sub="Feasibility depends only on the OS and node type / domain (Live / Non Live does not matter). The OS is checked against what the supported CrowdStrike sensors (N, N-1, N-2) run on: Legacy = only an end-of-life sensor or Falcon for Legacy Systems runs on it, even when an agent is installed. Domain here means the node's functional domain (VAS, NMS, Core…), not a DNS domain. The inventory sheet's EDR Feasible column is shown for reference only." />

      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
        <Kpi label="Inventory nodes" value={s.nodes} tone="info" foot={`OS known for ${fmtN(s.nodes - s.os_unknown)}`} active={!Object.keys(filterNow).length} onClick={() => replaceAll({})} />
        <Kpi label="Feasible" value={s.feasible} tone="good" foot={`${pct(s.feasible, s.nodes)}% · ${fmtN(s.by_edr)} have EDR`} active={on("feasible", "Yes")} onClick={() => replaceAll({ feasible: "Yes" })} />
        <Kpi label="Not feasible" value={s.not_feasible} tone="crit" foot={`OS ${fmtN(s.by_os)} · node type ${fmtN(s.by_node_type)}${s.by_domain ? ` · domain ${fmtN(s.by_domain)}` : ""}`} active={on("feasible", "No")} onClick={() => replaceAll({ feasible: "No" })} />
        <Kpi label="EDR applicable" value={s.applicable} foot="feasible + legacy with an agent" active={on("applicable", "1")} />
        <Kpi label="Sensor older than N-2" value={sensorOld ?? "–"} tone="warn" foot="installed agents to upgrade" active={on("sensor", "older")} onClick={() => replaceAll({ sensor: "older" })} />
        <Kpi label="Feasibility to be decided" value={s.to_be_decided} tone="warn" foot={`OS unknown ${fmtN(s.os_unknown)} · not in catalog ${fmtN(s.os_not_in_catalog)}`} active={on("feasible", "To be decided")} onClick={() => replaceAll({ feasible: "To be decided" })} />
        <Kpi label="Legacy" value={s.legacy} tone="serious" foot={`${fmtN(s.legacy_installed)} with an agent · OS not on N-2 sensors`} active={on("feasible", "Legacy")} onClick={() => replaceAll({ feasible: "Legacy" })} />
      </KpiGrid>

      <SensorSupport demo={!!status?.demo} />

      <Card className="mb-4">
        <CardHeader title="Node type & domain rules" hint="every value below comes from your inventory · pick what a node without an agent should be marked as (not feasible or feasible) — OS rules are the OS support catalog above"
          right={dirty ? (
            <div className="flex items-center gap-2">
              {impact && <span className="text-xs text-fg-2">Saving: <b className="text-crit-fg">{fmtN(impact.to_not_feasible)}</b> become not feasible · <b className="text-good-fg">{fmtN(impact.to_feasible)}</b> become feasible{impact.to_be_decided ? <> · <b className="text-warn-fg">{fmtN(impact.to_be_decided)}</b> to be decided</> : null}</span>}
              <Button size="sm" variant="ghost" onClick={() => setDraft(data.rules)}>Discard</Button>
              <Button size="sm" variant="primary" onClick={save} disabled={saving}><Check /> {saving ? "Saving…" : "Save rules"}</Button>
            </div>
          ) : <span className="text-xs text-muted">saved</span>} />
        <div className="grid gap-4 px-4 pb-4 lg:grid-cols-2">
          {GROUPS.map((g) => (
            <RuleGroup key={g.key} title={g.title} how={g.how} placeholder={g.placeholder} values={draft[g.key]} yesValues={draft[`${g.key}_yes`]}
              facets={data.facets[g.key] as Facet[]} contains={false}
              onChange={(v) => setDraft({ ...draft, [g.key]: v })} onYesChange={(v) => setDraft({ ...draft, [`${g.key}_yes`]: v })} />
          ))}
        </div>
        <div className="border-t border-border px-4 py-3">
          <Checkbox checked={draft.use_inventory_column} onChange={(v) => setDraft({ ...draft, use_inventory_column: v })}
            label={<span>Also treat <b>EDR Feasible = No</b> in the inventory sheet as not feasible <span className="text-muted">(when no rule matches)</span></span>} />
        </div>
      </Card>

      <DataTable endpoint="/api/feasibility/nodes" exportPath="/api/feasibility/export" columns={cols} state={state} setState={set}
        storageKey="feasibility" noun="nodes" rowKey={(r: any) => `${r.lob_id}|${r.item_key}`} onReset={() => replaceAll({})}
        filters={
          <div className="flex w-full flex-wrap items-center gap-2">
            <SearchInput className="w-[260px] max-w-full" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, name, OS, node type…" />
            <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v })} any="All" options={data.lobs.map((l: any) => ({ value: l.id, label: l.name }))} />
            <FilterSelect label="EDR feasible" value={state.feasible} onChange={(v) => set({ feasible: v })} any="Any" options={[["Yes", "Feasible"], ["No", "Not feasible"], ["Legacy", "Legacy"], ["To be decided", "To be decided"]]} />
            <FilterSelect label="OS support" value={state.os_support} onChange={(v) => set({ os_support: v })} any="Any"
              options={[["Supported", "Supported"], ["Legacy", "Legacy"], ["Not supported", "Not supported"], ["unknown", "Not in catalog"]]} />
            <FilterSelect label="Sensor" value={state.sensor} onChange={(v) => set({ sensor: v })} any="Any"
              options={[["N", "N"], ["N-1", "N-1"], ["N-2", "N-2"], ["older", "Older than N-2"]]} />
            <FilterSelect label="Why" value={state.reason} onChange={(v) => set({ reason: v })} any="Any"
              options={[["Legacy OS", "Legacy OS"], ["OS not supported", "OS not supported"], ["OS supported", "OS supported"], ["rule", "Any rule"], ["Node type rule", "Node type rule"], ["Domain rule", "Domain rule"], ["Set manually", "Set manually"],
                ["EDR installed", "EDR installed"], ["Inventory sheet", "Inventory sheet"], ["No rule matched", "No rule matched"]]} />
            <FilterSelect label="OS from" value={state.os_source} onChange={(v) => set({ os_source: v })} any="Any"
              options={[["edr", "CrowdStrike agent"], ["inventory", "Inventory sheet"], ["scan", "VA scan"], ["none", "Unknown"]]} />
            {state.differs && <Badge tone="info" className="gap-1">Differs from sheet<button onClick={() => set({ differs: undefined })}><X className="size-3" /></button></Badge>}
            <div className="ml-auto">
              <Menu width={260} trigger={<Button size="sm">Set for all filtered…</Button>} items={[
                { label: "Mark all feasible", hint: "every node matching the filters", icon: <ShieldCheck />, onSelect: () => decide("Yes", { filter: filterNow }) },
                { label: "Mark all not feasible", hint: "every node matching the filters", icon: <ShieldOff />, onSelect: () => decide("No", { filter: filterNow }) },
                { label: "Mark all legacy", hint: "every node matching the filters", icon: <History />, onSelect: () => decide("Legacy", { filter: filterNow }) },
                "sep",
                { label: "Clear manual decisions", hint: "back to the rules", icon: <RotateCcw />, onSelect: () => decide(null, { filter: filterNow }) },
              ]} />
            </div>
          </div>
        } />
    </div>
  );
}

function RuleGroup({ title, how, placeholder, values, yesValues, facets, contains, onChange, onYesChange }: {
  title: string; how: string; placeholder: string; values: string[]; yesValues?: string[]; facets: Facet[]; contains: boolean;
  onChange: (v: string[]) => void; onYesChange?: (v: string[]) => void;
}) {
  const [text, setText] = React.useState("");
  const [all, setAll] = React.useState(false);
  const [mode, setMode] = React.useState<"no" | "yes">("no");
  const yes = yesValues || [];
  const lower = values.map((v) => v.toLowerCase());
  const yesLower = yes.map((v) => v.toLowerCase());
  const has = (list: string[], s: string) => list.some((v) => (contains ? s.includes(v) : s === v));
  const hitNo = (f: Facet) => has(lower, f.value.toLowerCase());
  const hitYes = (f: Facet) => has(yesLower, f.value.toLowerCase());
  const add = (v: string, m: "no" | "yes" = mode) => {
    v = v.trim();
    if (!v) return;
    if (m === "no") { if (!has(lower, v.toLowerCase())) onChange([...values, v]); }
    else if (!has(yesLower, v.toLowerCase())) onYesChange?.([...yes, v]);
    setText("");
  };
  const shown = all ? facets : facets.slice(0, 10);
  const id = "dl-" + title.replace(/\W/g, "");
  return (
    <div className="flex flex-col rounded-xl border border-border p-3">
      <div className="text-[13px] font-semibold">{title} <span className="font-normal text-muted">{how}…</span></div>
      <div className="mt-2 flex min-h-[30px] flex-wrap gap-1.5">
        {values.map((v) => (
          <span key={"n" + v} className="inline-flex items-center gap-1 rounded-md bg-crit-soft px-2 py-0.5 text-[12px] font-medium text-crit-fg">
            {v}<button aria-label={`Remove ${v} not-feasible rule`} onClick={() => onChange(values.filter((x) => x !== v))}><X className="size-3" /></button>
          </span>
        ))}
        {yes.map((v) => (
          <span key={"y" + v} className="inline-flex items-center gap-1 rounded-md bg-good-soft px-2 py-0.5 text-[12px] font-medium text-good-fg">
            {v}<button aria-label={`Remove ${v} feasible rule`} onClick={() => onYesChange?.(yes.filter((x) => x !== v))}><X className="size-3" /></button>
          </span>
        ))}
        {!values.length && !yes.length && <span className="text-[12px] text-muted">No rule: the OS catalog decides</span>}
      </div>
      <div className="mt-2 flex items-center gap-1.5">
        <span className="text-[11px] text-muted">Add as</span>
        <button type="button" onClick={() => setMode("no")} className={cn("rounded-md px-2 py-1 text-[11.5px] font-medium", mode === "no" ? "bg-crit-soft text-crit-fg" : "text-muted hover:bg-surface-2")}>not feasible</button>
        <button type="button" onClick={() => setMode("yes")} className={cn("rounded-md px-2 py-1 text-[11.5px] font-medium", mode === "yes" ? "bg-good-soft text-good-fg" : "text-muted hover:bg-surface-2")}>feasible</button>
      </div>
      <form className="mt-1.5 flex gap-1.5" onSubmit={(e) => { e.preventDefault(); add(text); }}>
        <input list={id} value={text} onChange={(e) => setText(e.target.value)} placeholder={placeholder}
          className="h-8 min-w-0 flex-1 rounded-lg border border-border-strong bg-surface px-2.5 text-[13px] outline-none focus:border-accent" />
        <datalist id={id}>{facets.map((f) => <option key={f.value} value={f.value} />)}</datalist>
        <Button size="sm" type="submit" disabled={!text.trim()}><Plus /> Add</Button>
      </form>
      {facets.length > 0 && (
        <div className="mt-3">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted">In your inventory · mark with ✕ not feasible / ✓ feasible</div>
          <ul className="max-h-[220px] space-y-0.5 overflow-y-auto scroll-thin">
            {shown.map((f) => (
              <li key={f.value} className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-surface-2">
                <span className={cn("min-w-0 flex-1 truncate text-[12.5px]", hitNo(f) && "text-muted line-through")}>{f.value}</span>
                <span className="shrink-0 tabular text-[12px] text-muted" title={`${f.nodes} nodes · ${f.installed} with EDR installed`}>{fmtN(f.nodes)}{f.installed ? <span className="text-good-fg"> · {fmtN(f.installed)} EDR</span> : null}</span>
                <button title={hitNo(f) ? "Already marked not feasible" : `Mark every ${f.value} not feasible`} disabled={hitNo(f)}
                  onClick={() => add(f.value, "no")}
                  className={cn("grid size-5 shrink-0 place-items-center rounded border", hitNo(f) ? "border-border text-muted" : "border-border-strong text-crit-fg hover:bg-crit-soft")}>
                  <X className="size-3" />
                </button>
                <button title={hitYes(f) ? "Already marked feasible" : `Mark every ${f.value} feasible`} disabled={hitYes(f)}
                  onClick={() => add(f.value, "yes")}
                  className={cn("grid size-5 shrink-0 place-items-center rounded border", hitYes(f) ? "border-border text-muted" : "border-border-strong text-good-fg hover:bg-good-soft")}>
                  <Check className="size-3" />
                </button>
              </li>
            ))}
          </ul>
          {facets.length > 10 && <button className="mt-1 text-[12px] text-accent-fg hover:underline" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${facets.length}`}</button>}
        </div>
      )}
    </div>
  );
}

const PLATS = ["Windows", "Linux", "macOS", "Other"];
const STATUS_OPTS: [string, string][] = [["Supported", "Supported"], ["Legacy", "Legacy"], ["Not supported", "Not supported"]];

/** Published sensor builds (N / N-1 / N-2) and the OS support catalog: which OS the supported sensors run on. */
function SensorSupport({ demo }: { demo: boolean }) {
  const qc = useQueryClient();
  const { data, error, refetch } = useQuery({ queryKey: ["sensor-support"], queryFn: () => api<any>("/api/sensor-support") });
  const [plat, setPlat] = React.useState("Windows");
  const [busy, setBusy] = React.useState(false);
  const [add, setAdd] = React.useState<{ platform: string; pattern: string; status: string; note: string } | null>(null);
  if (!data) return <Card className="mb-4"><Loading error={error} retry={() => refetch()} /></Card>;
  const custom = data.catalog.filter((e: any) => e.source === "custom");
  const save = async (entries: any[], msg: string) => {
    setBusy(true);
    try {
      await api("/api/sensor-support/catalog", { method: "PUT", body: { entries: entries.map(({ platform, pattern, status, note }: any) => ({ platform, pattern, status, note })) } });
      toast.success(msg + " · feasibility recalculated");
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const setEntry = (e: any, patch: any) => save([...custom.filter((x: any) => x.pattern.toLowerCase() !== e.pattern.toLowerCase()), { ...e, ...patch }], `${e.pattern}: ${patch.status || "updated"}`);
  const remove = (e: any) => save(custom.filter((x: any) => x !== e), `${e.pattern}: back to ${e.source === "custom" ? "the default" : "default"}`);
  const refresh = async () => {
    setBusy(true);
    try { const r = await api<any>("/api/sensor-support/refresh", { method: "POST" }); toast.success(r.message); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const rows = data.catalog.filter((e: any) => (PLATS.includes(e.platform) ? e.platform : "Other") === plat);
  const f = data.fetched;
  return (
    <Card className="mb-4">
      <CardHeader title="Supported sensors & OS"
        hint={f ? <>sensor builds {f.sample ? "(sample data)" : `fetched from CrowdStrike ${fmtRel(f.at)}`}{f.kernels ? ` · ${fmtN(f.kernels)} supported Linux kernels` : ""}</> : "not fetched from CrowdStrike yet"}
        right={<Button size="sm" onClick={refresh} disabled={busy || demo} title={demo ? "Sample data: not connected to CrowdStrike" : "Fetch N / N-1 / N-2 builds and the supported Linux kernel list"}>
          <RefreshCw className={cn(busy && "animate-spin")} /> Refresh from CrowdStrike</Button>} />
      <div className="px-4 pb-4">
        {Object.keys(data.builds).length ? (
          <div className="mb-4 grid gap-2 sm:grid-cols-3">
            {Object.entries(data.builds).map(([p, bs]: any) => (
              <div key={p} className="rounded-xl border border-border px-3 py-2.5">
                <div className="text-[12px] font-semibold text-fg-2">{p === "Mac" ? "macOS" : p} sensor</div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {bs.map((b: any) => <span key={b.tag} className="inline-flex items-center gap-1 text-[12px]"><Badge tone={b.tag === "N-2" ? "warn" : "good"}>{b.tag}</Badge><span className="font-mono">{b.version}</span></span>)}
                </div>
                <div className="mt-1 text-[11px] text-muted">older than {bs.find((b: any) => b.tag === "N-2")?.release || "N-2"} = end of support</div>
              </div>
            ))}
          </div>
        ) : (
          <Callout tone="warn" className="mb-4">Sensor builds are fetched on every sync. Give the API client the <b>Sensor update policies: Read</b> scope, then click Refresh. Until then N / N-1 / N-2 is counted from the sensor versions installed in the console.</Callout>
        )}
        <div className="mb-2 text-[12.5px] text-fg-2">
          Which OS the supported sensors run on. CrowdStrike publishes the full matrix only in its support portal, so this starts from a built-in list
          {data.linux.length ? <>, with Linux taken from CrowdStrike&apos;s supported-kernel list ({fmtN(data.linux.length)} distribution versions)</> : null}.
          Check it once against the portal and change any status: your edits win. Matching ignores vendor wording (“Red Hat Enterprise Linux 8.8” = “RHEL 8”); the longest match wins.
        </div>
        <Tabs value={plat} onChange={setPlat} tabs={PLATS.map((p) => ({ id: p, label: p, count: data.catalog.filter((e: any) => (PLATS.includes(e.platform) ? e.platform : "Other") === p).length }))} />
        <div className="max-h-[340px] overflow-y-auto rounded-lg border border-border scroll-thin">
          <table className="w-full text-[13px]">
            <thead className="sticky top-0 bg-surface-2 text-left text-[11.5px] text-muted">
              <tr><th className="px-3 py-2 font-medium">OS</th><th className="px-3 py-2 font-medium">Status</th><th className="px-3 py-2 font-medium">Inventory nodes</th>
                <th className="px-3 py-2 font-medium">Note</th><th className="px-3 py-2 font-medium">Source</th><th /></tr>
            </thead>
            <tbody>
              {rows.map((e: any) => (
                <tr key={e.pattern} className="border-t border-border">
                  <td className="px-3 py-1.5 font-medium">{e.pattern}</td>
                  <td className="px-3 py-1.5">
                    <select value={e.status} disabled={busy} onChange={(ev) => setEntry(e, { status: ev.target.value })}
                      className={cn("h-7 rounded-md border border-border-strong bg-surface px-1.5 text-[12.5px] font-medium",
                        e.status === "Supported" ? "text-good-fg" : e.status === "Legacy" ? "text-serious-fg" : "text-crit-fg")}>
                      {STATUS_OPTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                  </td>
                  <td className="px-3 py-1.5 tabular">{e.nodes ? <>{fmtN(e.nodes)}{e.installed ? <span className="text-good-fg"> · {fmtN(e.installed)} EDR</span> : null}</> : <span className="text-muted">–</span>}</td>
                  <td className="px-3 py-1.5 text-[12px] text-fg-2">{e.note}</td>
                  <td className="px-3 py-1.5"><Badge tone={e.source === "custom" ? "violet" : e.source === "crowdstrike" ? "info" : "outline"}>{e.source === "custom" ? "edited" : e.source === "crowdstrike" ? "CrowdStrike" : "built-in"}</Badge></td>
                  <td className="px-2 py-1.5 text-right">{e.source === "custom" && <Button size="icon" variant="ghost" title="Remove your edit" onClick={() => remove(e)} disabled={busy}><Trash2 /></Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {add ? (
          <form className="mt-3 flex flex-wrap items-center gap-2" onSubmit={(ev) => { ev.preventDefault(); if (add.pattern.trim()) { save([...custom, add], `${add.pattern} added`); setAdd(null); } }}>
            <Select value={add.platform} onChange={(v) => setAdd({ ...add, platform: v })} options={PLATS} />
            <input autoFocus value={add.pattern} onChange={(ev) => setAdd({ ...add, pattern: ev.target.value })} placeholder="OS, e.g. Windows Server 2012 R2"
              className="h-8 w-[260px] rounded-lg border border-border-strong bg-surface px-2.5 text-[13px] outline-none focus:border-accent" />
            <Select value={add.status} onChange={(v) => setAdd({ ...add, status: v })} options={STATUS_OPTS} />
            <input value={add.note} onChange={(ev) => setAdd({ ...add, note: ev.target.value })} placeholder="Note (optional)"
              className="h-8 w-[220px] rounded-lg border border-border-strong bg-surface px-2.5 text-[13px] outline-none focus:border-accent" />
            <Button size="sm" variant="primary" type="submit" disabled={!add.pattern.trim() || busy}><Check /> Add</Button>
            <Button size="sm" variant="ghost" type="button" onClick={() => setAdd(null)}>Cancel</Button>
          </form>
        ) : (
          <Button size="sm" className="mt-3" onClick={() => setAdd({ platform: plat, pattern: "", status: "Legacy", note: "" })}><Plus /> Add OS</Button>
        )}
        {data.unmatched.length > 0 && (
          <div className="mt-4">
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted">OS in your inventory not in this list (feasible unless a rule says otherwise) · click to classify</div>
            <div className="flex flex-wrap gap-1.5">
              {data.unmatched.map((u: any) => (
                <button key={u.os} onClick={() => setAdd({ platform: /windows/i.test(u.os) ? "Windows" : /mac|sequoia|sonoma|ventura/i.test(u.os) ? "macOS" : /linux|rhel|centos|ubuntu|debian|suse|sles/i.test(u.os) ? "Linux" : "Other", pattern: u.os, status: "Legacy", note: "" })}
                  className="rounded-md border border-border px-2 py-0.5 text-[12px] hover:border-accent">{u.os} <span className="text-muted">{fmtN(u.n)}</span></button>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
