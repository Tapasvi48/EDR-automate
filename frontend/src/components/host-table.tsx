"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { SlidersHorizontal, X } from "lucide-react";
import { useMeta } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Button, Field, FilterSelect, Input, SearchInput } from "./ui";
import { cn } from "@/lib/utils";
import { DataTable, type Column } from "./data-table";
import { HostFlags, HostStatus, Live, Mono, VerifBadge, When, YN, removalLabel } from "./badges";
import { DateRange } from "./date-range";
import { useHostDrawer } from "./host-drawer";

export function hostColumns(): Column[] {
  return [
    { key: "hostname", label: "Hostname", render: (r) => <span><b>{r.hostname || "(no hostname)"}</b><HostFlags r={r} /></span> },
    { key: "connection_ip", label: "IP (connection)", render: (r) => <Mono>{r.connection_ip}</Mono> },
    { key: "local_ip", label: "Local IP", hidden: true, render: (r) => <Mono>{r.local_ip}</Mono> },
    { key: "online_state", label: "Status", render: (r) => <HostStatus r={r} /> },
    { key: "inv_lobs", label: "LOB", render: (r) => (r.inv_lobs ? r.inv_lobs : <Badge tone="warn">Not in inventory</Badge>) },
    { key: "inv_msps", label: "MSP", render: (r) => r.inv_msps || (r.inv_lobs ? <span className="text-muted">Unassigned</span> : "") },
    { key: "node_type", label: "Node type" },
    { key: "os_version", label: "OS" },
    { key: "agent_version", label: "Sensor", render: (r) => <Mono>{r.agent_version}</Mono> },
    { key: "exposed", label: "Internet exposed", sort: false, render: (r) => (r.internet_exposed ? <Badge tone="crit">Yes</Badge> : <span className="text-muted">No</span>) },
    { key: "niam", label: "NIAM", sort: false, render: (r) => (r.niam_ne_ids ? <Badge tone="good" title={`NE ID ${r.niam_ne_ids}`}>Yes</Badge> : <span className="text-muted">No</span>) },
    { key: "first_seen", label: "First seen", render: (r) => <span title={r.first_seen}>{fmtDt(r.first_seen)}</span> },
    { key: "last_seen", label: "Last seen", render: (r) => <When ts={r.last_seen} /> },
    { key: "platform_name", label: "Platform", hidden: true },
    { key: "prevention_policy", label: "Prevention policy", hidden: true, sort: false, render: (r) => r.prevention_policy_id ? <span>{r.prevention_policy || r.prevention_policy_id}{r.prevention_applied === 0 && <Badge tone="warn" className="ml-1">not applied</Badge>}</span> : <span className="text-muted">none</span> },
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
  ["unmapped", "Not in inventory"],
  ["unlisted", "EDR only (not in inventory)"],
  ["outdated", "Outdated sensor"],
  ["contained", "Contained"],
];
const FLAG_KEYS = FLAGS.map(([k]) => k);
const MORE_KEYS = ["agent_version", "sensor_level", "platform", "domain", "site", "chassis", "ip_range", "niam", "exposed", ...FLAG_KEYS];
const MAIN_KEYS = ["q", "status", "lob", "msp", "os", "node_type", "first_from", "first_to", "last_from", "last_to", "removed_from", "removed_to"];

export function HostFilters({ state, set, extra, removalFilter }: { state: Record<string, string>; set: SetFn; extra?: React.ReactNode; removalFilter?: boolean }) {
  const { data: m } = useMeta();
  const moreCount = MORE_KEYS.filter((k) => state[k]).length;
  const anyActive = moreCount + MAIN_KEYS.filter((k) => state[k]).length > 0;
  const lobSel = (state.lob || "").split("|").filter(Boolean);
  const msps = (m?.msps || []).filter((x) => !lobSel.length || lobSel.includes(String(x.lob_id)));
  const lobName = (id: number) => m?.lobs.find((l) => l.id === id)?.name || "";
  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <SearchInput className="w-[320px] max-w-full" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Hostname, IP, AID, serial… (paste many)" />
        <FilterSelect label="Status" value={state.status === "stale" ? "" : state.status} onChange={(v) => set({ status: v })} options={[["online", "Online"], ["offline", "Offline"], ["unknown", "Unknown"]]} />
        <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} any="All" options={[...(m?.lobs || []).map((l) => ({ value: l.id, label: l.name }))]} />
        <FilterSelect label="MSP" value={state.msp} onChange={(v) => set({ msp: v })} any="All"
          options={[...msps.map((x) => ({ value: x.id, label: lobSel.length === 1 ? x.name : `${x.name} · ${lobName(x.lob_id)}` })), { value: "none", label: "Unassigned MSP" }]} />
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
            <Popover.Content align="start" sideOffset={6} className="z-50 w-[560px] max-w-[95vw] rounded-xl border border-border bg-surface p-4 shadow-xl">
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">Show only</div>
              <div className="mb-4 flex flex-wrap gap-1.5">
                {FLAGS.map(([k, l]) => (
                  <button key={k} type="button" onClick={() => set({ [k]: state[k] === "1" ? undefined : "1" })}
                    className={cn("rounded-full border px-2.5 py-1 text-[12px] transition-colors", state[k] === "1" ? "border-accent bg-accent-soft font-semibold text-accent-fg" : "border-border text-fg-2 hover:border-fg-2/40")}>{l}</button>
                ))}
              </div>
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">Coverage</div>
              <div className="mb-4 flex flex-wrap gap-2">
                <FilterSelect single label="In NIAM dump" value={state.niam} onChange={(v) => set({ niam: v })} options={[["1", "Yes"], ["0", "No"]]} />
                <FilterSelect single label="Internet exposed" value={state.exposed} onChange={(v) => set({ exposed: v })} options={[["1", "Yes"], ["0", "No"]]} />
              </div>
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">Sensor & host details</div>
              <div className="flex flex-wrap gap-2">
                <FilterSelect label="Sensor version" value={state.agent_version} onChange={(v) => set({ agent_version: v })} any="All" options={m?.agent_versions || []} />
                <FilterSelect label="Release level" value={state.sensor_level} onChange={(v) => set({ sensor_level: v })} any="All" options={[["N", "N · latest"], ["N-1", "N-1"], ["N-2", "N-2"], ["older", "Older than N-2"]]} />
                <FilterSelect label="Platform" value={state.platform} onChange={(v) => set({ platform: v })} any="All" options={m?.platforms || []} />
                <FilterSelect label="Domain" value={state.domain} onChange={(v) => set({ domain: v })} any="All" options={m?.domains || []} />
                <FilterSelect label="Site" value={state.site} onChange={(v) => set({ site: v })} any="All" options={m?.sites || []} />
                <FilterSelect label="Chassis" value={state.chassis} onChange={(v) => set({ chassis: v })} any="All" options={m?.chassis || []} />
              </div>
              <Field label="IP range (IPv4 / IPv6 CIDR)" className="mt-3"><Input defaultValue={state.ip_range || ""} placeholder="10.10.0.0/16 or 2001:db8::/48" onBlur={(e) => set({ ip_range: e.target.value })} onKeyDown={(e) => e.key === "Enter" && set({ ip_range: (e.target as HTMLInputElement).value })} /></Field>
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
      storageKey={storageKey + "-v3"}
      noun="hosts"
      title={title}
      onRowClick={(r) => open(r.aid)}
      onReset={reset}
      onData={onData}
      filters={<HostFilters state={merged} set={set} extra={extraFilters} removalFilter={removalFilter} />}
    />
  );
}
