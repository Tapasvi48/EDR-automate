"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { fmtDt } from "@/lib/format";
import { Badge, Card, Chip, KV, Loading, SearchInput, Select, Sheet, SectionTitle } from "./ui";
import { DataTable, SimpleTable, type Column } from "./data-table";
import { useMeta } from "@/lib/hooks";
import { ActualBadge, ChangeTag, CoverageBadge, COVERAGE_HELP, HostLink, Live, Mono, VERIFICATION_HELP, VerifBadge, When, YN } from "./badges";

export const VERIFICATIONS = Object.keys(VERIFICATION_HELP);
export const COVERAGE_STATUSES = Object.keys(COVERAGE_HELP);
export const ACTUALS = ["Online", "Offline", "Inactive", "Removed", "Hidden", "Not Found", "IP Used by Other Host"];
const MATCHES = ["ip+hostname", "hostname", "ip", "ip (hostname differs)", "ip_history"];

export function inventoryColumns(showLob: boolean, historical: boolean): Column[] {
  const cols: Column[] = [
    ...(showLob ? [{ key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> }] : []),
    { key: "change_tag", label: "Tag", sort: historical ? false : undefined, render: (r: any) => <ChangeTag t={r.change_tag} /> },
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

export function InventoryTable({ lobId, state, set, reset, facets, versions, showLob, lobs }: {
  lobId: number; state: Record<string, string>; set: any; reset: () => void; facets?: Record<string, { label: string; n: number }[]>;
  versions?: any[]; showLob?: boolean; lobs?: { id: number; name: string }[];
}) {
  const historical = !!state.version_id;
  const [item, setItem] = React.useState<any>(null);
  const cols = React.useMemo(() => inventoryColumns(!!showLob, historical), [showLob, historical]);
  const opts = (key: string, fallback: string[] = []) => (facets?.[key]?.length ? facets[key].map((f) => [f.label, `${f.label} (${f.n})`] as [string, string]) : fallback.map((v) => [v, v] as [string, string]));
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
        storageKey={"inv2" + (showLob ? "all" : "")}
        noun="items"
        defaultSize={100}
        rowKey={(r: any) => `${r.lob_id || ""}|${r.item_key}`}
        onReset={reset}
        onRowClick={(r) => setItem(r)}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, node name, remarks… (paste many)" />
          {versions && (
            <Select value={state.version_id || ""} onChange={(v) => set({ version_id: v })} placeholder={`Current version${versions[0] ? ` (v${versions[0].version_no})` : ""}`}
              options={versions.slice(1).map((v) => ({ value: v.id, label: `v${v.version_no} · ${fmtDt(v.uploaded_at)}` }))} />
          )}
          {showLob && lobs && <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={lobs.map((l) => ({ value: l.id, label: l.name }))} />}
          {!historical && <MspSelect lobId={lobId || (state.lob ? +state.lob : 0)} value={state.msp} onChange={(v) => set({ msp: v })} />}
          {!historical && <Select value={state.coverage_status} onChange={(v) => set({ coverage_status: v })} placeholder="Any EDR status" options={opts("coverage_status", COVERAGE_STATUSES)} />}
          <Select value={state.live} onChange={(v) => set({ live: v })} placeholder="Live / Non Live" options={opts("live", ["Live", "Non Live", "(blank)"])} />
          <Select value={state.edr_feasible} onChange={(v) => set({ edr_feasible: v })} placeholder="EDR feasible" options={opts("edr_feasible", ["Yes", "No", "(blank)"])} />
          <Select value={state.edr_installed} onChange={(v) => set({ edr_installed: v })} placeholder="EDR installed (inventory)" options={opts("edr_installed", ["Yes", "No", "(blank)"])} />
          {facets?.node_type && <Select value={state.node_type} onChange={(v) => set({ node_type: v })} placeholder="Node type" options={opts("node_type")} />}
          {facets?.os && <Select value={state.os} onChange={(v) => set({ os: v })} placeholder="OS" options={opts("os")} />}
          {facets?.domain && <Select value={state.domain} onChange={(v) => set({ domain: v })} placeholder="Domain" options={opts("domain")} />}
          <div className="flex w-full flex-wrap gap-1.5">
            {([
              ["applicable", "Applicable (Live & feasible)", true],
              ["installed", "Installed", !historical],
              ["pending", "Not installed / removed / hidden", !historical],
              ["claimed_missing", "Inventory says Yes · no agent", !historical],
              ["marked_no", "Inventory says No · agent running", !historical],
              ["cross_msp_dup", "IP in more than one MSP", !historical],
            ] as [string, string, boolean][]).filter(([, , show]) => show).map(([k, l]) => (
              <Chip key={k} on={state[k] === "1"} onClick={() => set({ [k]: state[k] === "1" ? undefined : "1" })}>{l}</Chip>
            ))}
            {!historical && <Chip on={state.change_tag === "new"} onClick={() => set({ change_tag: state.change_tag === "new" ? undefined : "new" })}>New in latest version</Chip>}
            {!historical && <Chip on={state.change_tag === "modified"} onClick={() => set({ change_tag: state.change_tag === "modified" ? undefined : "modified" })}>Modified in latest version</Chip>}
            {historical && <Badge tone="warn" className="ml-1">Viewing a historical snapshot — EDR status is only computed for the current version</Badge>}
          </div>
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
