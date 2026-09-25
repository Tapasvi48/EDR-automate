"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { SlidersHorizontal, X } from "lucide-react";
import { useMeta } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Button, Field, Input, SearchInput, Select } from "./ui";
import { DataTable, type Column } from "./data-table";
import { HostFlags, HostStatus, Live, Mono, VerifBadge, When, YN, removalLabel } from "./badges";
import { DateRange } from "./date-range";
import { useHostDrawer } from "./host-drawer";

export function hostColumns(): Column[] {
  return [
    { key: "hostname", label: "Hostname", render: (r) => <span><b>{r.hostname || "(no hostname)"}</b><HostFlags r={r} /></span> },
    { key: "local_ip", label: "Local IP", render: (r) => <Mono>{r.local_ip}</Mono> },
    { key: "online_state", label: "Status", render: (r) => <HostStatus r={r} /> },
    { key: "inv_lobs", label: "LOB", render: (r) => (r.inv_lobs ? r.inv_lobs : <Badge tone="warn">Unmapped</Badge>) },
    { key: "inv_msps", label: "MSP", render: (r) => r.inv_msps || (r.inv_lobs ? <span className="text-muted">Unassigned</span> : "") },
    { key: "node_type", label: "Node type" },
    { key: "os_version", label: "OS" },
    { key: "agent_version", label: "Sensor", render: (r) => <Mono>{r.agent_version}</Mono> },
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
    { key: "dup_count", label: "Agents on IP", num: true, hidden: true, render: (r) => (r.dup_count > 1 ? r.dup_count : "") },
    { key: "console_state", label: "Console", hidden: true, render: (r) => (r.console_state === "active" ? "Active" : <Badge tone="crit">{r.console_state}</Badge>) },
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
  ["duplicate", "Duplicate IP agents"],
  ["rfm", "Reduced functionality (RFM)"],
  ["unmapped", "Unmapped — no LOB"],
  ["unlisted", "Not in inventory"],
  ["reinstall", "Reinstalls"],
  ["outdated", "Outdated sensor"],
  ["contained", "Contained"],
];
const MORE_KEYS = ["platform", "domain", "site", "chassis", "ip_range", "reinstall_reason"];

export function HostFilters({ state, set, extra, removalFilter }: { state: Record<string, string>; set: SetFn; extra?: React.ReactNode; removalFilter?: boolean }) {
  const { data: m } = useMeta();
  const moreCount = MORE_KEYS.filter((k) => state[k]).length;
  const msps = (m?.msps || []).filter((x) => !state.lob || String(x.lob_id) === state.lob);
  const lobName = (id: number) => m?.lobs.find((l) => l.id === id)?.name || "";
  return (
    <>
      <SearchInput className="w-[300px] max-w-full" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Hostname, IP, AID, serial… (paste many)" />
      <Select value={state.status} onChange={(v) => set({ status: v })} placeholder="Any status"
        options={[["online", "Online"], ["offline", "Offline"], ["stale", "Online · stale last seen"], ["unknown", "Unknown"]]} />
      <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={(m?.lobs || []).map((l) => ({ value: l.id, label: l.name }))} />
      <Select value={state.msp} onChange={(v) => set({ msp: v })} placeholder="All MSPs"
        options={[...msps.map((x) => ({ value: x.id, label: state.lob ? x.name : `${x.name} · ${lobName(x.lob_id)}` })), ...(state.lob ? [{ value: "none", label: "Unassigned MSP" }] : [])]} />
      <Select value={state.os} onChange={(v) => set({ os: v })} placeholder="All OS" options={m?.os || []} />
      <Select value={state.node_type} onChange={(v) => set({ node_type: v })} placeholder="All node types" options={m?.node_types || []} />
      <Select value={state.agent_version} onChange={(v) => set({ agent_version: v })} placeholder="All sensor versions" options={m?.agent_versions || []} />
      <DateRange label="First seen" from={state.first_from} to={state.first_to} onChange={(a, b) => set({ first_from: a, first_to: b })} />
      <DateRange label="Last seen" older from={state.last_from} to={state.last_to} onChange={(a, b) => set({ last_from: a, last_to: b })} />
      {removalFilter && (
        <DateRange label="Removed" from={state.removed_from} to={state.removed_to} onChange={(a, b) => set({ removed_from: a, removed_to: b })} />
      )}
      <Popover.Root>
        <Popover.Trigger asChild>
          <Button size="sm" variant={moreCount ? "soft" : "ghost"}><SlidersHorizontal /> More{moreCount ? ` · ${moreCount}` : ""}</Button>
        </Popover.Trigger>
        <Popover.Portal>
          <Popover.Content align="end" sideOffset={6} className="z-50 w-[460px] max-w-[95vw] rounded-xl border border-border bg-surface p-4 shadow-xl">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Platform"><Select className="max-w-none" value={state.platform} onChange={(v) => set({ platform: v })} placeholder="All" options={m?.platforms || []} /></Field>
              <Field label="Domain"><Select className="max-w-none" value={state.domain} onChange={(v) => set({ domain: v })} placeholder="All" options={m?.domains || []} /></Field>
              <Field label="Site"><Select className="max-w-none" value={state.site} onChange={(v) => set({ site: v })} placeholder="All" options={m?.sites || []} /></Field>
              <Field label="Chassis"><Select className="max-w-none" value={state.chassis} onChange={(v) => set({ chassis: v })} placeholder="All" options={m?.chassis || []} /></Field>
              <Field label="IP range (CIDR)"><Input defaultValue={state.ip_range || ""} placeholder="10.10.0.0/16" onBlur={(e) => set({ ip_range: e.target.value })} onKeyDown={(e) => e.key === "Enter" && set({ ip_range: (e.target as HTMLInputElement).value })} /></Field>
              <Field label="Reinstall match"><Select className="max-w-none" value={state.reinstall_reason} onChange={(v) => set({ reinstall_reason: v })} placeholder="Any" options={[["ip+hostname", "Same IP + hostname"], ["hostname", "Same hostname"], ["ip", "Same IP only"]]} /></Field>
            </div>
            {moreCount > 0 && <Button size="sm" variant="ghost" className="mt-3" onClick={() => set(Object.fromEntries(MORE_KEYS.map((k) => [k, undefined])))}><X /> Clear these</Button>}
          </Popover.Content>
        </Popover.Portal>
      </Popover.Root>
      <Select value={FLAGS.find(([k]) => state[k] === "1")?.[0] || ""} placeholder="Show only…"
        onChange={(v) => set({ ...Object.fromEntries(FLAGS.map(([k]) => [k, undefined])), ...(v ? { [v]: "1" } : {}) })} options={FLAGS} />
      {extra}
    </>
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
