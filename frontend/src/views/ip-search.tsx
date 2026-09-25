"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Globe } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Button, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, SearchInput } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { ActualBadge, HostLink, HostStatus, Live, Mono, VerifBadge, When, YN } from "@/components/badges";

export default function IpSearch() {
  const [state, set] = useUrlState();
  const q = (state.q || "").trim();
  const { data: r, isFetching } = useQuery({ queryKey: ["ipsearch", q], queryFn: () => api<any>("/api/search/ip", { params: { q } }), enabled: !!q });
  const active = r?.current.filter((x: any) => x.console_state === "active") || [];
  const aidsInHistory = new Set((r?.history || []).map((x: any) => x.aid));
  return (
    <div>
      <PageHeader title="IP & NIC history search" sub="Search an exact IP, a prefix (10.20.3.), a CIDR range (10.20.0.0/16) or a hostname. Checks current IPs, every IP each agent has ever reported (sync snapshots + Falcon network-address history), removed hosts and all LOB inventories." />
      <div className="flex gap-2">
        <SearchInput big autoFocus className="flex-1" value={q} onChange={(v) => set({ q: v })} placeholder="10.20.34.17  ·  10.20.34.  ·  10.20.0.0/16  ·  CORP-WS-0369" />
        <Button className="h-11" disabled={!q} onClick={() => downloadExcel("/api/search/ip/export", { q })}><Download /> Excel</Button>
      </div>
      {!q && (
        <Card className="mt-5 p-8 text-center text-muted">
          <Globe className="mx-auto mb-2 size-8 opacity-60" />
          Find out which agent ever used an IP — even if it has since moved, been reinstalled or removed from the console.
        </Card>
      )}
      {q && !r && <Loading />}
      {r && (
        <div className={isFetching ? "opacity-70 transition-opacity" : ""}>
          <KpiGrid className="mt-5">
            <Kpi label={`Agent IDs ever on this ${r.mode === "hostname" ? "name" : "IP"}`} value={r.distinct_hosts} tone="info" />
            <Kpi label="Using it now (in console)" value={active.length} tone={active.length > 1 ? "serious" : "good"} foot={active.length > 1 ? "More than one active agent — duplicate" : undefined} />
            <Kpi label="Removed / hidden agents" value={r.current.length - active.length} tone="crit" />
            <Kpi label="Agents in NIC history" value={aidsInHistory.size} foot={`${r.history.length} IP records`} />
            <Kpi label="Inventory records" value={r.inventory.length} tone="violet" />
          </KpiGrid>
          <Card className="mt-4">
            <CardHeader title={`Hosts currently on this ${r.mode === "hostname" ? "hostname" : "IP"}`} hint="local, external or connection IP" />
            <SimpleTable rows={r.current} empty="No host currently uses this IP" columns={[
              { key: "hostname", label: "Hostname", render: (x: any) => <span><HostLink aid={x.aid}><b>{x.hostname || x.aid}</b></HostLink>{x.is_reinstall ? <Badge tone="violet" className="ml-1.5">REINSTALL</Badge> : null}</span> },
              { key: "aid", label: "Agent ID", render: (x: any) => <Mono>{x.aid}</Mono> },
              { key: "local_ip", label: "Local IP", render: (x: any) => <Mono>{x.local_ip}</Mono> },
              { key: "external_ip", label: "External IP", render: (x: any) => <Mono>{x.external_ip}</Mono> },
              { key: "status", label: "Status", render: (x: any) => <HostStatus r={x} /> },
              { key: "os_version", label: "OS" },
              { key: "first_seen", label: "First seen", render: (x: any) => fmtDt(x.first_seen) },
              { key: "last_seen", label: "Last seen", render: (x: any) => <When ts={x.last_seen} /> },
            ]} />
          </Card>
          <Card className="mt-4">
            <CardHeader title="NIC / IP history" hint={`${aidsInHistory.size} agent IDs · every time an agent reported this address`} />
            <SimpleTable rows={r.history} maxHeight="520px" empty="No history records" columns={[
              { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
              { key: "hostname", label: "Hostname", render: (x: any) => <HostLink aid={x.aid}>{x.hostname || x.aid}</HostLink> },
              { key: "kind", label: "Kind" },
              { key: "source", label: "Source", render: (x: any) => <Badge>{x.source}</Badge> },
              { key: "mac", label: "MAC", render: (x: any) => <Mono>{x.mac}</Mono> },
              { key: "f", label: "Used from", render: (x: any) => fmtDt(x.ip_first_seen) },
              { key: "l", label: "Used until", render: (x: any) => fmtDt(x.ip_last_seen) },
              { key: "cur", label: "Current IP", render: (x: any) => <span><Mono>{x.current_ip}</Mono>{x.current_ip !== x.ip && <Badge tone="warn" className="ml-1.5">moved</Badge>}</span> },
              { key: "st", label: "Host status", render: (x: any) => <HostStatus r={x} /> },
            ]} />
          </Card>
          <Card className="mt-4">
            <CardHeader title="LOB inventory records" />
            <SimpleTable rows={r.inventory} empty="Not in any LOB inventory" columns={[
              { key: "lob", label: "LOB", render: (x: any) => <Link className="text-accent-fg hover:underline" href={`/lob/?id=${x.lob_id}&q=${encodeURIComponent(x.ip || x.node_name)}`}>{x.lob}</Link> },
              { key: "ip", label: "IP", render: (x: any) => <Mono>{x.ip}</Mono> },
              { key: "node_name", label: "Node name" }, { key: "node_type", label: "Node type" },
              { key: "live", label: "Live", render: (x: any) => <Live v={x.live} /> },
              { key: "edr_installed", label: "EDR installed (inv)", render: (x: any) => <YN v={x.edr_installed} /> },
              { key: "edr_actual", label: "EDR actual", render: (x: any) => <ActualBadge v={x.edr_actual} /> },
              { key: "verification", label: "Verification", render: (x: any) => <VerifBadge v={x.verification} /> },
              { key: "cs", label: "Falcon host", render: (x: any) => x.matched_aid ? <HostLink aid={x.matched_aid}>{x.cs_hostname || x.matched_aid}</HostLink> : "–" },
            ]} />
          </Card>
        </div>
      )}
    </div>
  );
}
