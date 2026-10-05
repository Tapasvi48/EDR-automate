"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Info } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { Badge, Card, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { EdrBadge } from "@/components/badges";

const ROLE: Record<string, [string, string]> = {
  exposed: ["crit", "Reached from internet"], public: ["violet", "Public / NAT IP"], public_src: ["violet", "Source NAT IP"],
  outbound: ["warn", "Goes out to internet"], snat: ["crit", "NATed to a public IP"], internet_src: ["neutral", "Internet source"], internal: ["neutral", "Internal flow"],
};
// asset type: what the matrix says this address is (one row per asset: a public NAT IP is shown on its private IP's row)
const AKIND: [string, string, string][] = [
  ["private_public", "Private + public / NAT IP", "crit"], ["private_only", "Private IP only", "info"],
  ["public_only", "Public IP only (ours)", "violet"], ["external", "Public IP, not ours", "neutral"],
  ["subnet", "Subnet / range", "neutral"], ["name", "Host / object name", "neutral"],
];
const VIEWS: [string, string, string][] = [
  ["exposed", "Ours & internet exposed", "crit"], ["outbound", "Ours & talking to internet", "warn"], ["public", "Our public / NAT IPs", "violet"],
  ["not_inventory", "Exposed but not in inventory", "serious"], ["unknown", "To check (names, unconfirmed public IPs)", "neutral"], ["external", "External / partner", "neutral"],
  ["all", "All addresses", "info"],
];

/** Every address in the communication matrix: is it ours, what role does it play, and do we know it (inventory / EDR)? */
export default function MatrixIps() {
  const [state, set, replaceAll] = useUrlState();
  return (
    <div>
      <PageHeader title="Matrix asset register"
        sub="One row per asset in the communication matrix: its private IP and public / NAT IP together, whether it is ours, what it does, and whether inventory and EDR know it." />
      <MatrixIpsPanel state={state} set={set} replaceAll={replaceAll} />
    </div>
  );
}

export function MatrixIpsPanel({ state, set, replaceAll, keep = {} }: { state: Record<string, string>; set: any; replaceAll: any; keep?: Record<string, string> }) {
  const view = state.view || "exposed";
  const [why, setWhy] = React.useState(false);
  const { data, error, refetch } = useQuery({ queryKey: ["comm-ips-counts"], queryFn: () => api<any>("/api/comm/ips", { params: { view: "all", size: "1" } }) });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const c = data.counts;
  const ipLink = (ip: string) => <Link key={ip} className="font-mono text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(ip)}`}>{ip}</Link>;
  const ipList = (v: string) => v ? <span className="flex flex-col">{v.split(", ").map(ipLink)}</span> : <span className="text-muted">–</span>;
  const cols: Column[] = [
    { key: "private_ip", label: "Private IP", render: (r) => r.kind === "ip" ? ipList(r.private_ip) : <span className="flex flex-col"><span className="font-medium">{r.address}</span>
      <span className="text-[11px] text-muted">{r.kind === "subnet" ? `subnet · ${r.assets} known asset(s) inside` : "host / object name"}</span></span> },
    { key: "public_ip", label: "Public / NAT IP", render: (r) => ipList(r.public_ip) },
    { key: "asset_kind", label: "Asset type", render: (r) => { const k = AKIND.find(([id]) => id === r.asset_kind); return <Badge tone={(k?.[2] || "neutral") as any}>{k?.[1] || r.asset_kind}</Badge>; } },
    { key: "address", label: "Address", hidden: true, render: (r) => (
      <span className="flex flex-col">
        {r.kind === "name" ? <span className="font-medium">{r.address}</span>
          : <Link className="font-mono text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.address)}`}>{r.address}</Link>}
        <span className="text-[11px] text-muted">{r.kind === "subnet" ? `subnet · ${r.assets} known asset(s) inside` : r.kind === "name" ? "host / object name" : "IP"}</span>
      </span>) },
    { key: "ours", label: "Ours?", render: (r) => r.ours ? <Badge tone="good" title={r.why}>Yes</Badge> : <Badge tone="neutral">{r.kind === "name" ? "Unknown" : "No"}</Badge> },
    { key: "roles", label: "Role in the matrix", wrap: true, render: (r) => <span className="flex flex-wrap gap-1">{r.roles.map((x: string) =>
      <Badge key={x} tone={(ROLE[x]?.[0] || "neutral") as any}>{ROLE[x]?.[1] || x}</Badge>)}</span> },
    { key: "name", label: "Known as", render: (r) => r.name || <span className="text-muted">–</span> },
    { key: "inv", label: "In inventory", render: (r) => r.kind === "subnet" ? <span className="text-[12px]">{r.in_inventory} of {r.assets}</span>
      : r.in_inventory ? <Badge tone="good">Yes</Badge> : r.ours ? <Badge tone="warn">No</Badge> : <span className="text-muted">–</span> },
    { key: "edr", label: "EDR", render: (r) => r.kind === "subnet" ? <span className="text-[12px]">{r.in_edr} with EDR</span> : r.edr_status ? <EdrBadge s={r.edr_status} /> : <span className="text-muted">–</span> },
    { key: "lobs", label: "LOB", wrap: true, render: (r) => <span className="text-[12px]">{r.lobs || "–"}</span> },
    { key: "applications", label: "Application / owner", wrap: true, render: (r) => <span className="text-[12px]">{r.applications || "–"}{r.owners ? <span className="block text-muted">{r.owners}</span> : null}</span> },
    { key: "ports", label: "Ports", wrap: true, render: (r) => <span className="font-mono text-[11.5px]">{r.ports || "–"}</span> },
    { key: "rules", label: "Rows", render: (r) => <span title={r.rule_ids}>{r.rules}</span> },
    { key: "sheets", label: "Workbook › sheet", wrap: true, hidden: true, render: (r) => <span className="text-[11.5px] text-muted">{r.sheets}</span> },
    { key: "why", label: "Why ours", hidden: true },
  ];
  return (
    <div>
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(165px,1fr))]">
        {VIEWS.slice(0, 5).map(([id, label, tone]) => <Kpi key={id} label={label} value={c[id]} tone={tone} active={view === id} onClick={() => replaceAll({ ...keep, view: id })} />)}
      </KpiGrid>
      <div className="mb-4 flex flex-wrap items-center gap-1.5 text-[12.5px]">
        <span className="mr-1 text-muted">Asset type</span>
        {AKIND.map(([id, label]) => (
          <button key={id} onClick={() => replaceAll({ ...keep, view: "all", asset_kind: state.asset_kind === id ? "" : id })}
            className={"rounded-full border px-2.5 py-0.5 transition-colors " + (state.asset_kind === id ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-border-strong")}>
            {label} <b className="tabular">{(c["kind_" + id] ?? 0).toLocaleString()}</b>
          </button>
        ))}
      </div>
      <Card className="mb-4">
        <button className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-[12.5px] font-medium" onClick={() => setWhy(!why)}>
          <Info className="size-4 text-accent-fg" /> How addresses are classified <span className="ml-auto text-muted">{why ? "hide" : "show"}</span></button>
        {why && (
          <div className="grid gap-4 border-t border-border px-4 py-3 text-[12.5px] md:grid-cols-2">
            <div>
              <b>Ours</b> when any of these holds:
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-fg-2">
                <li>a private address (10/8, 172.16/12, 192.168/16, CGNAT 100.64/10, IPv6 ULA fc00::/7)</li>
                <li>a public IP the matrix lists as a public / destination-NAT / source-NAT / pool IP, or as the destination of an inbound rule</li>
                <li>a public IP that is in an inventory, a VA scan or the NIAM dump</li>
                <li>a host / object name that matches an inventory or CrowdStrike host name</li>
              </ul>
            </div>
            <div>
              <b>Roles</b>, from each row:
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-fg-2">
                <li><b>Reached from internet</b>: destination of an internet-facing row (inbound rule from Internet / ISP / untrust / any, or a NAT, pool or exposure-register sheet)</li>
                <li><b>Public / NAT IP</b>: listed as the public or destination-NAT address</li>
                <li><b>NATed to a public IP</b>: source of a row with a Source NAT IP; it leaves through that public IP, so it counts as internet exposed (also when many hosts share the one NAT IP)</li>
                <li><b>Goes out to internet</b>: source of a rule whose destination is any, an internet zone or a public IP that is not ours</li>
                <li><b>Internet source</b>: source of an inbound rule (a partner or any)</li>
              </ul>
              <div className="mt-2 text-muted">Inventory and CrowdStrike rows whose IP (private or public) or name matches an exposed address get <b>Internet exposed = Yes</b> in their tables.</div>
            </div>
          </div>
        )}
      </Card>
      <DataTable key={view} endpoint="/api/comm/ips" exportPath="/api/comm/ips/export" state={{ ...state, view }} setState={set} noun="addresses" storageKey="comm-ips"
        rowKey={(r: any) => `${r.kind}|${r.address}`} onReset={() => replaceAll({ ...keep, view })} sortable={false} columns={cols}
        filters={<>
          <FilterSelect single label="Show" value={view} onChange={(v) => replaceAll({ ...keep, view: v || "exposed" })} options={VIEWS.map(([id, l]) => [id, l]) as [string, string][]} />
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Private / public IP, name, application, owner, sheet…" />
          <FilterSelect label="Asset type" value={state.asset_kind} onChange={(v) => set({ asset_kind: v })} any="All" options={AKIND.map(([id, l]) => [id, l]) as [string, string][]} />
          <FilterSelect label="Kind" value={state.kind} onChange={(v) => set({ kind: v })} any="All" options={[["ip", "IPs"], ["subnet", "Subnets / ranges"], ["name", "Host names"]]} />
        </>} />
    </div>
  );
}
