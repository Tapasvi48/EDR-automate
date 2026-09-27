"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { SlidersHorizontal, X } from "lucide-react";
import { useMeta } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Button, Field, FilterSelect, Input, SearchInput, Select } from "./ui";
import { DataTable, type Column } from "./data-table";
import { HostFlags, HostStatus, Live, Mono, VerifBadge, When, YN, removalLabel } from "./badges";
import { DateRange } from "./date-range";
import { useHostDrawer } from "./host-drawer";

export function hostColumns(): Column[] {
  return [
    { key: "hostname", label: "Hostname", render: (r) => <span><b>{r.hostname || "(no hostname)"}</b><HostFlags r={r} /></span> },
    { key: "connection_ip", label: "Connection IP", render: (r) => <Mono>{r.connection_ip}</Mono> },
    { key: "local_ip", label: "Local IP", render: (r) => <Mono>{r.local_ip}</Mono> },
    { key: "online_state", label: "Status", render: (r) => <HostStatus r={r} /> },
    { key: "inv_lobs", label: "LOB", render: (r) => (r.inv_lobs ? r.inv_lobs : <Badge tone="warn">No LOB</Badge>) },
    { key: "inv_msps", label: "MSP", render: (r) => r.inv_msps || (r.inv_lobs ? <span className="text-muted">Unassigned</span> : "") },
    { key: "node_type", label: "Node type" },
    { key: "os_version", label: "OS" },
    { key: "agent_version", label: "Sensor", render: (r) => <Mono>{r.agent_version}</Mono> },
    { key: "niam", label: "NIAM", sort: false, render: (r) => (r.niam_ne_ids ? <Badge tone="good" title={`NE ID ${r.niam_ne_ids}`}>Yes</Badge> : <span className="text-muted">No</span>) },
    { key: "first_seen", label: "First seen", render: (r) => <span title={r.first_seen}>{fmtDt(r.first_seen)}</span> },
    { key: "last_seen", label: "Last seen", render: (r) => <When ts={r.last_seen} /> },
    { key: "platform_name", label: "Platform", hidden: true },
    { key: "product_type_desc", label: "Falcon host type", hidden: true },
    { key: "machine_domain", label: "Domain", hidden: true },
    { key: "site_name", label: "Site", hidden: true },
    { key: "ou", label: "OU", hidden: true, sort: false },
    { key: "external_ip", label: "External IP", hidden: true, sort: false, render: (r) => <Mono>{r.external_ip}</Mono> },
    { key: "mac_address", label: "MAC", hidden: true, sort: false, render: (r) => <Mono>{r.mac_address}</Mono> },
    { key: "serial_number", label: "Serial", hidden: true, sort: false },
    { key: "system_product_name", label: "Model", hidden: true, sort: false },
    { key: "last_login_user", label: "Last user", hidden: true, sort: false },
    { key: "tags", label: "Falcon tags", hidden: true, sort: false },
    { key: "groups", label: "Host groups", hidden: true, sort: false },
    { key: "dup_count", label: "Duplicate agents", num: true, hidden: true, render: (r) => (r.dup_count > 1 ? r.dup_count : "") },
    { key: "console_state", label: "Console", hidden: true, render: (r) => (r.console_state === "active" ? "Active" : <Badge tone="crit">{r.console_state}</Badge>) },
    { key: "gone_group", label: "Agent IDs (merged)", num: true, hidden: true, sort: false, render: (r) => (r.gone_group > 1 ? r.gone_group : r.gone_group ? 1 : "") },
    { key: "removed_at", label: "Removed", hidden: true, render: (r) => (r.removed_at ? <span>{fmtDt(r.removed_at)} <Badge>{removalLabel(r.removal_type)}</Badge></span> : "") },
    { key: "inv_live", label: "Live / Non Live", hidden: true, render: (r) => (r.inv_node_name ? <Live v={r.inv_live} /> : null) },
    { key: "inv_edr_feasible", label: "EDR feasible", hidden: true, sort: false, render: (r) => (r.inv_node_name ? <YN v={r.inv_edr_feasible} /> : null) },
    { key: "inv_edr_installed", label: "EDR installed (inventory)", hidden: true, sort: false, render: (r) => (r.inv_node_name ? <YN v={r.inv_edr_installed} /> : null) },
    { key: "inv_domain", label: "Domain (inventory)", hidden: true, sort: false },
    { key: "inv_remarks", label: "Remarks", hidden: true, sort: false },
    { key: "inv_verification", label: "Inventory claim check", hidden: true, sort: false, render: (r) => (r.inv_verification ? <VerifBadge v={r.inv_verification} /> : null) },
  ];
}

type SetFn = (patch: Record<string, string | number | undefined>, opts?: { resetPage?: boolean }) => void;

const FLAGS: [string, string][] = [
  ["duplicate", "Duplicate agents"],
  ["routing_conflict", "Routing conflict"],
  ["rfm", "Reduced functionality (RFM)"],
  ["unmapped", "No LOB"],
  ["unlisted", "EDR only (not in inventory)"],
  ["outdated", "Outdated sensor"],
  ["contained", "Contained"],
];
const FLAG_KEYS = FLAGS.map(([k]) => k);
const MORE_KEYS = ["agent_version", "sensor_level", "platform", "domain", "site", "chassis", "ip_range", "niam", ...FLAG_KEYS];
const MAIN_KEYS = ["q", "status", "lob", "msp", "os", "node_type", "first_from", "first_to", "last_from", "last_to", "removed_from", "removed_to"];

export function HostFilters({ state, set, extra, removalFilter }: { state: Record<string, string>; set: SetFn; extra?: React.ReactNode; removalFilter?: boolean }) {
  const { data: m } = useMeta();
  const moreCount = MORE_KEYS.filter((k) => state[k]).length;
  const anyActive = moreCount + MAIN_KEYS.filter((k) => state[k]).length > 0;
  const msps = (m?.msps || []).filter((x) => !state.lob || String(x.lob_id) === state.lob);
  const lobName = (id: number) => m?.lobs.find((l) => l.id === id)?.name || "";
  const flag = FLAGS.find(([k]) => state[k] === "1")?.[0] || "";
  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput className="w-[320px] max-w-full" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Hostname, IP, AID, serial… (paste many)" />
        <FilterSelect label="Status" value={state.status === "stale" ? "" : state.status} onChange={(v) => set({ status: v })} options={[["online", "Online"], ["offline", "Offline"], ["unknown", "Unknown"]]} />
        <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} any="All" options={[...(m?.lobs || []).map((l) => ({ value: l.id, label: l.name }))]} />
        <FilterSelect label="MSP" value={state.msp} onChange={(v) => set({ msp: v })} any="All"
          options={[...msps.map((x) => ({ value: x.id, label: state.lob ? x.name : `${x.name} · ${lobName(x.lob_id)}` })), ...(state.lob ? [{ value: "none", label: "Unassigned MSP" }] : [])]} />
        <FilterSelect label="OS" value={state.os} onChange={(v) => set({ os: v })} any="All" options={m?.os || []} />
        <FilterSelect label="Node type" value={state.node_type} onChange={(v) => set({ node_type: v })} any="All" options={m?.node_types || []} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <DateRange label="First seen" from={state.first_from} to={state.first_to} onChange={(a, b) => set({ first_from: a, first_to: b })} />
        <DateRange label="Last seen" older from={state.last_from} to={state.last_to} onChange={(a, b) => set({ last_from: a, last_to: b })} />
        {removalFilter && (
          <DateRange label="Removed" from={state.removed_from} to={state.removed_to} onChange={(a, b) => set({ removed_from: a, removed_to: b })} />
        )}
        <Popover.Root>
          <Popover.Trigger asChild>
            <Button size="sm" variant={moreCount ? "soft" : "default"}><SlidersHorizontal /> More filters{moreCount ? ` · ${moreCount}` : ""}</Button>
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content align="start" sideOffset={6} className="z-50 w-[520px] max-w-[95vw] rounded-xl border border-border bg-surface p-4 shadow-xl">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Show only</div>
              <div className="mb-4 grid grid-cols-2 gap-3">
                <Field label="Special cases"><Select className="max-w-none" value={flag} placeholder="All hosts"
                  onChange={(v) => set({ ...Object.fromEntries(FLAG_KEYS.map((k) => [k, undefined])), ...(v ? { [v]: "1" } : {}) })} options={FLAGS} /></Field>
                <Field label="In NIAM dump"><Select className="max-w-none" value={state.niam} onChange={(v) => set({ niam: v })} placeholder="Any" options={[["1", "Yes — IP is in NIAM"], ["0", "No"]]} /></Field>
              </div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Sensor & host details</div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Sensor version"><Select className="max-w-none" value={state.agent_version} onChange={(v) => set({ agent_version: v })} placeholder="All" options={m?.agent_versions || []} /></Field>
                <Field label="Sensor release level"><Select className="max-w-none" value={state.sensor_level} onChange={(v) => set({ sensor_level: v })} placeholder="All" options={[["N", "N · latest"], ["N-1", "N-1"], ["N-2", "N-2"], ["older", "Older than N-2"]]} /></Field>
                <Field label="Platform"><Select className="max-w-none" value={state.platform} onChange={(v) => set({ platform: v })} placeholder="All" options={m?.platforms || []} /></Field>
                <Field label="Domain"><Select className="max-w-none" value={state.domain} onChange={(v) => set({ domain: v })} placeholder="All" options={m?.domains || []} /></Field>
                <Field label="Site"><Select className="max-w-none" value={state.site} onChange={(v) => set({ site: v })} placeholder="All" options={m?.sites || []} /></Field>
                <Field label="Chassis"><Select className="max-w-none" value={state.chassis} onChange={(v) => set({ chassis: v })} placeholder="All" options={m?.chassis || []} /></Field>
                <Field label="IP range (IPv4 / IPv6 CIDR)" className="col-span-2"><Input defaultValue={state.ip_range || ""} placeholder="10.10.0.0/16 or 2001:db8::/48" onBlur={(e) => set({ ip_range: e.target.value })} onKeyDown={(e) => e.key === "Enter" && set({ ip_range: (e.target as HTMLInputElement).value })} /></Field>
              </div>
              {moreCount > 0 && <Button size="sm" variant="ghost" className="mt-3" onClick={() => set(Object.fromEntries(MORE_KEYS.map((k) => [k, undefined])))}><X /> Clear these</Button>}
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>
        {extra}
        {anyActive && <Button size="sm" variant="ghost" onClick={() => set(Object.fromEntries([...MAIN_KEYS, ...MORE_KEYS].map((k) => [k, undefined])))}><X /> Clear all filters</Button>}
      </div>
    </div>
  );
}

export function HostTable({ state, set, reset, storageKey = "hosts", title, extraFilters, fixed, omit, onData, defaults, removalFilter }: {
  state: Record<string, string>; set: SetFn; reset: () => void; storageKey?: string; title?: React.ReactNode; extraFilters?: React.ReactNode;
  fixed?: Record<string, string>; omit?: string[]; onData?: (d: any) => void; defaults?: Record<string, string>; removalFilter?: boolean;
}) {
  const { open } = useHostDrawer();
  const cols = React.useMemo(() => hostColumns(), []);
  const merged = { ...(defaults || {}), ...state };
  return (
    <DataTable
      endpoint="/api/hosts"
      exportPath="/api/hosts/export"
      columns={cols}
      state={merged}
      setState={set}
      fixed={fixed}
      omit={omit}
      storageKey={storageKey + "-v2"}
      noun="hosts"
      title={title}
      onRowClick={(r) => open(r.aid)}
      onReset={reset}
      onData={onData}
      filters={<HostFilters state={merged} set={set} extra={extraFilters} removalFilter={removalFilter} />}
    />
  );
}
