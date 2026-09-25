"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { useQuery } from "@tanstack/react-query";
import { SlidersHorizontal, X } from "lucide-react";
import { api } from "@/lib/api";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, Checkbox, Field, KV, Loading, SearchInput, Select, Sheet, SectionTitle } from "./ui";
import { DataTable, SimpleTable, type Column } from "./data-table";
import { useMeta } from "@/lib/hooks";
import { ActualBadge, ChangeTag, DupBadge, dupReasons, CoverageBadge, COVERAGE_HELP, HostLink, Live, Mono, VERIFICATION_HELP, VerifBadge, When, YN } from "./badges";

export const VERIFICATIONS = Object.keys(VERIFICATION_HELP);
export const COVERAGE_STATUSES = Object.keys(COVERAGE_HELP);
export const ACTUALS = ["Online", "Offline", "Inactive", "Removed", "Hidden", "Not Found", "IP Used by Other Host"];
const MATCHES = ["ip+hostname", "hostname", "ip", "ip (hostname differs)", "ip_history"];

export function inventoryColumns(showLob: boolean, historical: boolean): Column[] {
  const cols: Column[] = [
    ...(showLob ? [{ key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> }] : []),
    { key: "change_tag", label: "Tag", sort: historical ? false : undefined, render: (r: any) => <span className="inline-flex gap-1"><ChangeTag t={r.change_tag} /><DupBadge r={r} /></span> },
    { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip}</Mono> },
    { key: "node_name", label: "Node name", render: (r: any) => <b>{r.node_name}</b> },
    { key: "msp", label: "MSP", render: (r: any) => r.msp || <span className="text-muted">Unassigned</span> },
    ...(historical ? [] : [{ key: "coverage_status", label: "EDR status", render: (r: any) => <CoverageBadge v={r.coverage_status} /> }]),
    { key: "node_type", label: "Node type" },
    { key: "domain", label: "Domain", hidden: true },
    { key: "live", label: "Live / Non Live", render: (r: any) => <Live v={r.live} /> },
    { key: "os", label: "OS" },
    { key: "edr_feasible", label: "EDR feasible", render: (r: any) => <YN v={r.edr_feasible} /> },
    { key: "edr_installed", label: "EDR installed (inventory)", render: (r: any) => <YN v={r.edr_installed} /> },
    { key: "remarks", label: "Remarks", wrap: true, hidden: true },
  ];
  if (!historical)
    cols.push(
      { key: "edr_actual", label: "Falcon detail", hidden: true, render: (r: any) => <ActualBadge v={r.edr_actual} /> },
      { key: "verification", label: "Inventory claim check", hidden: true, render: (r: any) => <VerifBadge v={r.verification} /> },
      { key: "cs_hostname", label: "Falcon host", sort: false, render: (r: any) => r.matched_aid ? <span><HostLink aid={r.matched_aid}>{r.cs_hostname || r.matched_aid}</HostLink>{r.match_count > 1 && <Badge tone="serious" className="ml-1.5" title="Several active agents match">×{r.match_count}</Badge>}</span> : <span className="text-muted">–</span> },
      { key: "cs_last_seen", label: "Falcon last seen", render: (r: any) => r.cs_last_seen ? <When ts={r.cs_last_seen} /> : "–" },
      { key: "cs_agent_version", label: "Sensor", hidden: true, sort: false, render: (r: any) => <Mono>{r.cs_agent_version}</Mono> },
      { key: "cs_os", label: "Falcon OS", hidden: true, sort: false },
      { key: "match_method", label: "Matched by", hidden: true, sort: false, render: (r: any) => r.match_method ? <Badge>{r.match_method}</Badge> : null },
      { key: "first_version_no", label: "Since version", hidden: true, sort: false, render: (r: any) => `v${r.first_version_no}` },
      { key: "last_changed_version_no", label: "Last changed", hidden: true, sort: false, render: (r: any) => `v${r.last_changed_version_no}` },
    );
  cols.push({ key: "extra", label: "Other columns", hidden: true, sort: false, wrap: true, render: (r: any) => <span className="text-xs text-fg-2">{Object.entries(r.extra || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span> });
  return cols;
}

type Facet = { label: string; n: number }[];
type Facets = Record<string, any> & { dup?: Record<string, number>; total?: number };

const STATUS_MAIN: [string, string][] = [["", "All"], ["Online", "Online"], ["Offline", "Offline"], ["Not Installed", "Not installed"]];
const CHECKS: [string, string][] = [
  ["applicable", "Applicable only (Live & feasible)"],
  ["claimed_missing", "Inventory says Yes · no agent"],
  ["marked_no", "Inventory says No · agent running"],
];
const DUPS: [string, string, string][] = [
  ["any", "Any duplicate", "any_dup"], ["file", "Repeated rows in uploaded file", "file_dup"],
  ["ip", "Same IP on several rows", "ip_dup"], ["name", "Same node name on several rows", "name_dup"], ["cross_msp", "IP in more than one MSP", ""],
  ["cross_lob", "IP also in another LOB", ""],
];
/** labels for the active-filter pills (params can also arrive from dashboard links) */
const PILL: Record<string, string> = {
  coverage_status: "EDR status", node_type: "Node type", os: "OS", domain: "Domain", live: "Live / Non Live", edr_feasible: "EDR feasible",
  edr_installed: "EDR installed (inventory)", dup: "Duplicates", change_tag: "Change", verification: "Claim check", edr_actual: "Falcon detail",
  match_method: "Matched by", edr_state: "Agent state", applicable: "Applicable only", installed: "Installed", pending: "Not installed / removed / hidden",
  claimed_missing: "Inventory says Yes · no agent", marked_no: "Inventory says No · agent running", installed_na: "Not applicable · agent running",
  cross_msp_dup: "IP in more than one MSP", in_scope: "Applicable only", mismatch: "Inventory claim mismatch",
};
const MORE_KEYS = ["live", "edr_feasible", "edr_installed", "domain", "dup", "change_tag", "applicable", "claimed_missing", "marked_no",
  "installed", "pending", "installed_na", "cross_msp_dup", "verification", "edr_actual", "match_method", "edr_state", "in_scope", "mismatch"];
const isMainStatus = (v?: string) => STATUS_MAIN.some(([s]) => s && s === v);

export function InventoryTable({ lobId, state, set, reset, versions, showLob, lobs, types }: {
  lobId: number; state: Record<string, string>; set: any; reset: () => void;
  versions?: any[]; showLob?: boolean; lobs?: { id: number; name: string }[]; types?: { id: number; name: string }[];
}) {
  const historical = !!state.version_id;
  const [item, setItem] = React.useState<any>(null);
  const cols = React.useMemo(() => inventoryColumns(!!showLob, historical), [showLob, historical]);
  const scopeLob = lobId || (state.lob ? +state.lob : 0);
  const { data: facets } = useQuery({
    queryKey: ["inv-facets", scopeLob, state.msp || ""],
    queryFn: () => api<Facets>("/api/inventory/facets", { params: { lob: scopeLob || undefined, msp: state.msp || undefined } }),
  });
  const list = (key: string): Facet => (Array.isArray(facets?.[key]) ? facets![key] : []);
  const opts = (key: string, fallback: string[] = []) =>
    list(key).length ? list(key).map((f) => [f.label, `${f.label} (${fmtN(f.n)})`] as [string, string]) : fallback.map((v) => [v, v] as [string, string]);
  const count = (key: string, v: string) => list(key).find((f) => f.label === v)?.n ?? (facets ? 0 : undefined);
  const moreActive = MORE_KEYS.filter((k) => state[k]).length + (state.coverage_status && !isMainStatus(state.coverage_status) ? 1 : 0);
  const pills = Object.keys(PILL).filter((k) => state[k] && !(k === "coverage_status" && isMainStatus(state.coverage_status)));
  const pillValue = (k: string) => {
    const v = state[k];
    if (v === "1") return null;
    if (k === "dup") return DUPS.find(([d]) => d === v)?.[1] || v;
    if (k === "change_tag") return v === "new" ? "New in latest version" : v === "modified" ? "Modified in latest version" : v;
    return v.split("|").join(", ");
  };
  const clearAll = () => set(Object.fromEntries(Object.keys(PILL).map((k) => [k, undefined])));
  return (
    <>
      <DataTable
        key={historical ? "h" + state.version_id : "cur"}
        endpoint={`/api/lobs/${lobId}/inventory`}
        exportPath={`/api/lobs/${lobId}/inventory/export`}
        columns={cols}
        state={state}
        setState={set}
        omit={["tab", "id"]}
        storageKey={"inv3" + (showLob ? "all" : "")}
        noun="items"
        defaultSize={100}
        rowKey={(r: any) => `${r.lob_id || ""}|${r.item_key}`}
        onReset={reset}
        onRowClick={(r) => setItem(r)}
        filters={<>
          <SearchInput className="w-64" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, node name, remarks… (paste many)" />
          {!historical && (
            <div className="inline-flex rounded-lg border border-border-strong bg-surface p-0.5 shadow-card" role="group" aria-label="EDR status">
              {STATUS_MAIN.map(([v, l]) => {
                const on = v ? state.coverage_status === v : !state.coverage_status;
                const n = v ? count("coverage_status", v) : facets?.total;
                return (
                  <button key={l} onClick={() => set({ coverage_status: v || undefined })} aria-pressed={on}
                    className={cn("h-7 rounded-md px-2.5 text-xs font-medium transition-colors", on ? "bg-accent-soft text-accent-fg" : "text-fg-2 hover:text-fg")}>
                    {l}{n !== undefined && <span className="ml-1 tabular opacity-60">{fmtN(n)}</span>}
                  </button>
                );
              })}
            </div>
          )}
          {showLob && lobs && <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={lobs.map((l) => ({ value: l.id, label: l.name }))} />}
          {!historical && types && types.length > 0 && (
            <Select value={state.type} onChange={(v) => set({ type: v })} placeholder="All inventories"
              options={[["main", "Main inventory"], ...types.map((t) => [String(t.id), `Type: ${t.name}`] as [string, string])]} />
          )}
          {!historical && <MspSelect lobId={scopeLob} value={state.msp} onChange={(v) => set({ msp: v })} />}
          <Select value={state.node_type} onChange={(v) => set({ node_type: v })} placeholder="All node types" options={opts("node_type")} />
          <Select value={state.os} onChange={(v) => set({ os: v })} placeholder="All OS" options={opts("os")} />
          <Popover.Root>
            <Popover.Trigger asChild>
              <Button variant={moreActive ? "soft" : "default"}>
                <SlidersHorizontal /> More filters{moreActive > 0 && <Badge tone="info" className="ml-0.5">{moreActive}</Badge>}
              </Button>
            </Popover.Trigger>
            <Popover.Portal>
              <Popover.Content align="start" sideOffset={6} className="z-50 w-[min(560px,94vw)] rounded-xl border border-border bg-surface p-4 shadow-xl">
                <div className="grid gap-3 sm:grid-cols-2">
                  {!historical && (
                    <Field label="EDR status (every value)">
                      <Select className="max-w-none" value={state.coverage_status} onChange={(v) => set({ coverage_status: v })} placeholder="Any" options={opts("coverage_status", COVERAGE_STATUSES)} />
                    </Field>
                  )}
                  <Field label="Live / Non Live">
                    <Select className="max-w-none" value={state.live} onChange={(v) => set({ live: v })} placeholder="Any" options={opts("live", ["Live", "Non Live", "(blank)"])} />
                  </Field>
                  <Field label="EDR feasible">
                    <Select className="max-w-none" value={state.edr_feasible} onChange={(v) => set({ edr_feasible: v })} placeholder="Any" options={opts("edr_feasible", ["Yes", "No", "(blank)"])} />
                  </Field>
                  <Field label="EDR installed (inventory)">
                    <Select className="max-w-none" value={state.edr_installed} onChange={(v) => set({ edr_installed: v })} placeholder="Any" options={opts("edr_installed", ["Yes", "No", "(blank)"])} />
                  </Field>
                  <Field label="Domain">
                    <Select className="max-w-none" value={state.domain} onChange={(v) => set({ domain: v })} placeholder="Any" options={opts("domain")} />
                  </Field>
                  <Field label="Duplicates">
                    <Select className="max-w-none" value={state.dup} onChange={(v) => set({ dup: v, cross_msp_dup: undefined })} placeholder="Any row"
                      options={DUPS.filter(([d]) => !historical || d === "file").map(([d, l, fk]) => [d, fk && facets?.dup ? `${l} (${fmtN(facets.dup[fk])})` : l] as [string, string])} />
                  </Field>
                  {!historical && (
                    <Field label="Change in latest version">
                      <Select className="max-w-none" value={state.change_tag} onChange={(v) => set({ change_tag: v })} placeholder="Any" options={[["new", "New"], ["modified", "Modified"], ["unchanged", "Unchanged"]]} />
                    </Field>
                  )}
                </div>
                <div className="mt-4 border-t border-border pt-3">
                  <div className="mb-2 text-xs font-medium text-fg-2">Checks</div>
                  <div className="flex flex-col gap-2">
                    {CHECKS.filter(([k]) => !historical || k === "applicable").map(([k, l]) => (
                      <Checkbox key={k} checked={state[k] === "1"} onChange={(on) => set({ [k]: on ? "1" : undefined })} label={l} />
                    ))}
                  </div>
                </div>
              </Popover.Content>
            </Popover.Portal>
          </Popover.Root>
          {versions && (
            <Select className="ml-auto" value={state.version_id || ""} onChange={(v) => set({ version_id: v })} placeholder="Current inventory"
              options={versions.filter((v) => !v.is_current).map((v) => ({ value: v.id, label: `${v.type_name || "Main"} v${v.version_no} · ${fmtDt(v.uploaded_at)}` }))} />
          )}
          {(pills.length > 0 || historical) && (
            <div className="flex w-full flex-wrap items-center gap-1.5">
              {pills.map((k) => {
                const v = pillValue(k);
                return (
                  <span key={k} className="inline-flex h-6 items-center gap-1 rounded-full bg-accent-soft pl-2.5 pr-1 text-[11.5px] font-medium text-accent-fg">
                    <span>{PILL[k]}{v && <span className="font-normal">: {v}</span>}</span>
                    <button aria-label={`Remove ${PILL[k]} filter`} className="grid size-4 place-items-center rounded-full hover:bg-accent/15" onClick={() => set({ [k]: undefined })}>
                      <X className="size-3" />
                    </button>
                  </span>
                );
              })}
              {pills.length > 1 && <button className="px-1 text-[11.5px] text-accent-fg hover:underline" onClick={clearAll}>Clear all</button>}
              {historical && <Badge tone="warn">Viewing a historical snapshot — EDR status is only computed for the current version</Badge>}
            </div>
          )}
        </>}
      />
      {item && <ItemSheet lobId={item.lob_id || lobId} item={item} onClose={() => setItem(null)} />}
    </>
  );
}

function ItemSheet({ lobId, item, onClose }: { lobId: number; item: any; onClose: () => void }) {
  const { data } = useQuery({ queryKey: ["item", lobId, item.item_key], queryFn: () => api<any>(`/api/lobs/${lobId}/items/${encodeURIComponent(item.item_key)}/history`) });
  const cur = data?.current || item;
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} width={820}
      title={<span>{cur.node_name || cur.ip} <ChangeTag t={cur.change_tag} /></span>}
      sub={<span><Mono>{cur.ip}</Mono> · key <Mono>{item.item_key}</Mono>{item.lob ? ` · ${item.lob}` : ""}</span>}>
      {!data ? <Loading /> : (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted">Inventory record</div>
            <KV items={[
              ["IP", <Mono key="i">{cur.ip}</Mono>], ["Node name", cur.node_name], ["MSP", cur.msp || "Unassigned"], ["Node type", cur.node_type], ["Domain", cur.domain],
              ["Live / Non Live", <Live key="l" v={cur.live} />], ["OS", cur.os], ["EDR feasible", <YN key="f" v={cur.edr_feasible} />],
              ["EDR installed (inventory)", <YN key="e" v={cur.edr_installed} />], ["Remarks", cur.remarks],
              ...(dupReasons({ ...item, ...cur }).length
                ? [["Duplicate", <span key="d" className="text-serious-fg">{dupReasons({ ...item, ...cur }).join(" · ")}</span>] as [string, React.ReactNode]]
                : []),
              ...Object.entries(cur.extra || {}).map(([k, v]) => [k, String(v)] as [string, React.ReactNode]),
            ]} />
          </Card>
          {data.current && (
            <Card className="p-4">
              <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted">Falcon verification</div>
              <div className="mb-3 flex flex-wrap items-center gap-2"><CoverageBadge v={cur.coverage_status} />
                <span className="text-xs text-muted">{COVERAGE_HELP[cur.coverage_status]}</span></div>
              <div className="mb-3 flex flex-wrap items-center gap-2 text-xs"><span className="text-muted">Inventory claim check:</span><VerifBadge v={cur.verification} />
                <span className="text-muted">{VERIFICATION_HELP[cur.verification]}</span></div>
              <KV items={[
                ["Falcon host", cur.matched_aid ? <HostLink key="h" aid={cur.matched_aid}>{cur.cs_hostname || cur.matched_aid}</HostLink> : "Not found"],
                ["Matched by", cur.match_method], ["Active agents matching", cur.match_count],
                ["Console state", cur.cs_console_state], ["Online state", cur.cs_online_state],
                ["Last seen", cur.cs_last_seen ? <When key="w" ts={cur.cs_last_seen} /> : "–"], ["Sensor", cur.cs_agent_version], ["Falcon OS", cur.cs_os],
              ]} />
            </Card>
          )}
          <div>
            <SectionTitle className="mt-0">Version history</SectionTitle>
            <div className="mb-2 text-xs text-muted">Present in versions: {data.versions_present.map((v: number) => `v${v}`).join(", ") || "–"}</div>
            <Card>
              <SimpleTable rows={data.changes} empty="No changes recorded" columns={[
                { key: "version_no", label: "Version", render: (r: any) => <Badge tone="info">v{r.version_no}</Badge> },
                { key: "uploaded_at", label: "Uploaded", render: (r: any) => fmtDt(r.uploaded_at) },
                { key: "change_type", label: "Change", render: (r: any) => <Badge tone={r.change_type === "added" ? "info" : r.change_type === "removed" ? "crit" : "warn"}>{r.change_type}</Badge> },
                { key: "field_label", label: "Field" },
                { key: "diff", label: "Old → New", wrap: true, render: (r: any) => r.change_type === "modified" ? <span><span className="text-crit-fg line-through">{r.old_value || "∅"}</span> → <b className="text-good-fg">{r.new_value || "∅"}</b></span> : null },
              ]} />
            </Card>
          </div>
        </div>
      )}
    </Sheet>
  );
}

function MspSelect({ lobId, value, onChange }: { lobId: number; value?: string; onChange: (v: string) => void }) {
  const { data: m } = useMeta();
  const msps = (m?.msps || []).filter((x) => !lobId || x.lob_id === lobId);
  const lobName = (id: number) => m?.lobs.find((l) => l.id === id)?.name || "";
  return (
    <Select value={value} onChange={onChange} placeholder="All MSPs"
      options={[...msps.map((x) => ({ value: x.id, label: lobId ? x.name : `${x.name} · ${lobName(x.lob_id)}` })), { value: "none", label: "Unassigned MSP" }]} />
  );
}
