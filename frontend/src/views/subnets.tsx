"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Callout, Checkbox, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Segmented } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { EdrBadge, Mono } from "@/components/badges";

const PREFIXES = ["16", "20", "22", "23", "24", "25", "26", "27", "28"];

/** Every known asset grouped by subnet, CrowdStrike gateway (layer-2 segment) or inventory VLAN, with EDR coverage per segment. */
export default function Subnets() {
  const [state, set, replaceAll] = useUrlState();
  const { data: meta } = useMeta();
  const group = state.group || "subnet";
  const prefix = state.prefix || "24";
  const params = { group, prefix };
  const [info, setInfo] = React.useState<any>(null);
  const keep = () => ({ ...(state.group ? { group: state.group } : {}), ...(state.prefix ? { prefix: state.prefix } : {}) });
  const s = info?.summary;
  const noun = group === "gateway" ? "gateways" : group === "vlan" ? "VLANs" : "subnets";
  const cols: Column[] = [
    { key: "label", label: group === "gateway" ? "Gateway (layer-2 segment)" : group === "vlan" ? "VLAN" : "Subnet", render: (r) => (
      <span className="flex flex-col"><Mono>{r.label}</Mono>
        {group !== "subnet" && <span className="font-mono text-[11px] text-muted">{r.range}</span>}
        {r.inferred > 0 && group === "gateway" && <span className="text-[11px] text-muted">{r.inferred} placed by their /24</span>}</span>) },
    { key: "assets", label: "Assets", num: true, render: (r) => <b>{fmtN(r.assets)}</b> },
    { key: "coverage", label: "EDR coverage", render: (r) => r.coverage == null ? <span className="text-muted">n/a</span> : (
      <span className="flex items-center gap-2">
        <span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-2"><span className={cn("block h-full", r.coverage >= 95 ? "bg-good" : r.coverage >= 80 ? "bg-warn" : "bg-crit")} style={{ width: `${r.coverage}%` }} /></span>
        <span className="text-[12px]">{r.coverage}%</span></span>) },
    { key: "edr", label: "With EDR", num: true, render: (r) => <span title={`${r.online} online · ${r.offline} offline`}>{r.edr}</span> },
    { key: "gap", label: "Feasible, no EDR", num: true, render: (r) => r.gap ? <b className="text-crit-fg">{r.gap}</b> : <span className="text-muted">0</span> },
    { key: "exposed", label: "Internet exposed", num: true, render: (r) => r.exposed ? <span><b className="text-serious-fg">{r.exposed}</b>
      {r.exposed_no_edr > 0 && <span className="ml-1 text-[11px] text-crit-fg">({r.exposed_no_edr} no EDR)</span>}</span> : <span className="text-muted">0</span> },
    { key: "risk", label: "Crit / high vulns", render: (r) => (r.crit || r.high) ? <span className="font-semibold text-crit-fg">{r.crit} / {r.high}</span> : <span className="text-muted">0</span> },
    { key: "lobs", label: "LOB", wrap: true, render: (r) => <span>{r.lobs || <span className="text-muted">–</span>}{r.lob_count > 1 && <Badge tone="warn" className="ml-1">mixed</Badge>}</span> },
    { key: "node_types", label: "Node types", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.node_types || "–"}</span> },
    { key: "gateways", label: "Gateway", hidden: group === "gateway", render: (r) => r.gateways ? <Mono>{r.gateways}</Mono> : <span className="text-muted">–</span> },
    { key: "vlans", label: "VLAN", hidden: group === "vlan" || !info?.has_vlan, render: (r) => r.vlans || <span className="text-muted">–</span> },
    { key: "msps", label: "MSP", hidden: true },
    { key: "range", label: "IPs seen", hidden: group !== "subnet", render: (r) => <span className="font-mono text-[11.5px] text-muted">{r.range}</span> },
  ];
  return (
    <div>
      <PageHeader title="Subnets & VLANs"
        sub="Every known asset (inventory, CrowdStrike, VA scans, NIAM) grouped by where it sits on the network: subnet, the default gateway CrowdStrike reports (agents behind one gateway share a layer-2 segment, i.e. a VLAN), or a VLAN column in your inventory." />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Segmented value={group as any} onChange={(v: string) => replaceAll({ ...(v !== "subnet" ? { group: v } : {}), ...(state.prefix ? { prefix: state.prefix } : {}) })}
          options={[["subnet", "By subnet"], ["gateway", "By gateway (VLAN)"], ["vlan", "By inventory VLAN"]] as any} />
        {group === "subnet" && <FilterSelect single label="Size" value={prefix} onChange={(v) => set({ prefix: !v || v === "24" ? undefined : v })} options={PREFIXES.map((p) => [p, `/${p}`])} />}
      </div>
      {info && group === "gateway" && !info.has_gateway && <Callout tone="info" className="mb-3">No CrowdStrike agent reports a default gateway yet (it comes with the next sync).</Callout>}
      {info && group === "vlan" && info.total <= 1 && <Callout tone="info" className="mb-3">No VLAN column found in the LOB inventories. Add a column named “VLAN” (or “VLAN ID”) to an inventory upload and it shows up here; until then, group by gateway.</Callout>}
      {s && (
        <KpiGrid className="mb-3 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
          <Kpi label={noun[0].toUpperCase() + noun.slice(1)} value={s.groups} tone="info" foot={`${fmtN(s.assets)} assets`} active={!state.gap && !state.exposed && !state.mixed}
            onClick={() => replaceAll(keep())} />
          <Kpi label="With EDR gaps" value={s.with_gap} tone="crit" foot={`${fmtN(s.gap)} feasible assets without EDR`} active={state.gap === "1"} onClick={() => set({ gap: state.gap === "1" ? undefined : "1", sort: "gap" })} />
          <Kpi label="With exposed assets" value={s.exposed_groups} tone="serious" foot={`${fmtN(s.exposed_no_edr)} exposed without EDR`} active={state.exposed === "1"} onClick={() => set({ exposed: state.exposed === "1" ? undefined : "1", sort: "exposed" })} />
          <Kpi label="Shared by several LOBs" value={s.mixed_lob} tone="warn" active={state.mixed === "1"} onClick={() => set({ mixed: state.mixed === "1" ? undefined : "1" })} />
          <Kpi label="EDR coverage" value={s.edr + s.gap ? `${Math.round((100 * s.edr) / (s.edr + s.gap))}%` : "–"} foot={`${fmtN(s.edr)} with EDR`} />
        </KpiGrid>
      )}
      <DataTable endpoint="/api/subnets" exportPath="/api/subnets/export" state={state} setState={set} fixed={params} noun={noun} storageKey={`subnets-${group}`}
        rowKey={(r: any) => r.key + r.label} onReset={() => replaceAll(keep())} sortable={false} columns={cols} onData={setInfo}
        renderExpanded={(r: any) => <Members group={group} prefix={prefix} k={group === "subnet" ? r.label : r.key} />}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, subnet, gateway, VLAN, LOB, MSP…" />
          <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v })} any="All" options={(meta?.lobs || []).map((l: any) => l.name)} />
          <FilterSelect single label="Sort" value={state.sort || "gap"} onChange={(v) => set({ sort: v })} options={[["gap", "Most EDR gaps"], ["exposed", "Most exposed"], ["risk", "Most critical vulns"],
            ["assets", "Most assets"], ["coverage", "Lowest coverage"], ["lobs", "Most LOBs"], ["label", "Name"]]} />
          <Checkbox checked={state.gap === "1"} onChange={(v) => set({ gap: v ? "1" : undefined })} label="EDR gaps only" />
        </>} />
    </div>
  );
}

/** The assets of one subnet / gateway / VLAN (expanded row). */
function Members({ group, prefix, k }: { group: string; prefix: string; k: string }) {
  const { data, error } = useQuery({ queryKey: ["subnet-members", group, prefix, k], queryFn: () => api<any>("/api/subnets/members", { params: { group, prefix, key: k } }) });
  if (!data) return <Loading error={error} />;
  return (
    <div className="max-h-[45vh] overflow-auto">
      <table className="w-full text-[12px]">
        <thead className="sticky top-0 bg-surface text-left text-[11px] text-muted"><tr>
          <th className="py-1 pr-3">IP</th><th className="pr-3">Name</th><th className="pr-3">LOB</th><th className="pr-3">Node type</th><th className="pr-3">EDR</th>
          <th className="pr-3">Internet</th><th className="pr-3">Crit / high</th><th className="pr-3">Gateway</th><th>VLAN</th></tr></thead>
        <tbody>
          {data.rows.map((r: any) => (
            <tr key={r.ip + r.name} className={cn("border-t border-border", r.gap && "bg-crit-soft/40")}>
              <td className="py-1 pr-3"><Link className="font-mono hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip)}`}>{r.ip}</Link></td>
              <td className="pr-3 font-medium">{r.name || <span className="text-muted">–</span>}</td>
              <td className="pr-3">{r.lobs || <span className="text-muted">–</span>}</td>
              <td className="pr-3">{r.node_type || "–"}</td>
              <td className="pr-3"><EdrBadge s={r.edr_status} />{r.gap && <span className="ml-1 text-[11px] text-crit-fg">feasible</span>}</td>
              <td className="pr-3">{r.exposed ? <Badge tone="crit">exposed</Badge> : null}</td>
              <td className="pr-3">{(r.crit || r.high) ? <span className="font-semibold text-crit-fg">{r.crit} / {r.high}</span> : <span className="text-muted">0</span>}</td>
              <td className="pr-3 font-mono">{r.gateway || <span className="text-muted">–</span>}</td>
              <td>{r.vlan || <span className="text-muted">–</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data.total > data.rows.length && <div className="mt-1 text-[11.5px] text-muted">First {fmtN(data.rows.length)} of {fmtN(data.total)} — export for all</div>}
    </div>
  );
}
