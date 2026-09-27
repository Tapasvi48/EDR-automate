"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { Mono } from "@/components/badges";
import { RegistryTable } from "@/components/registry-table";

const RULES: [string, string, string][] = [
  ["inventory", "LOB inventory", "An “Internet Facing” / “Exposure” / “Zone” column says Yes, DMZ or Internet, or a “Public IP” / “NAT IP” column gives the node a public address."],
  ["crowdstrike", "CrowdStrike", "The agent reports a public (globally routable) IP on its own network interface — the host sits directly on the internet."],
  ["scan", "VA scan", "A scan covered a public IP: the asset's own public IP, or the public / NAT IP of an inventory node (its findings are what the internet can see)."],
  ["matrix", "Communication matrix", "An active Allow rule from Internet / ISP (inbound, source Any / a public IP, or an internet / ISP zone or link) reaches the asset's IP or subnet — on the rule's ports."],
  ["ip", "Public IP", "The asset's own IP (inventory, NIAM or scan) is globally routable."],
];

export default function Exposure() {
  const [state, set, replaceAll] = useUrlState();
  const [how, setHow] = React.useState(false);
  const { data: s, error, refetch } = useQuery({ queryKey: ["exposure-summary"], queryFn: () => api<any>("/api/exposure/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const only = (patch: Record<string, string>) => replaceAll(patch);
  return (
    <div>
      <PageHeader title="Internet exposed" sub="Assets reachable from the internet, with the evidence for each: LOB inventory, CrowdStrike, the communication matrix or a VA scan of a public IP." />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Exposed assets" value={s.exposed} tone="crit" active={!Object.keys(state).some((k) => !["page", "size", "sort", "dir"].includes(k))} onClick={() => only({})} />
        <Kpi label="From inventory" value={s.by_inventory} foot="facing column / public IP" active={state.exposure_src === "inventory"} onClick={() => only({ exposure_src: "inventory" })} />
        <Kpi label="From CrowdStrike" value={s.by_crowdstrike} foot="public IP on the host" active={state.exposure_src === "crowdstrike"} onClick={() => only({ exposure_src: "crowdstrike" })} />
        <Kpi label="From VA scan" value={s.by_scan} foot="public IP was scanned" active={state.exposure_src === "scan"} onClick={() => only({ exposure_src: "scan" })} />
        <Kpi label="From comm. matrix" value={s.by_matrix} foot="inbound Internet / ISP rule" active={state.exposure_src === "matrix"} onClick={() => only({ exposure_src: "matrix" })} />
        <Kpi label="No EDR agent" value={s.no_edr} tone="crit" foot="exposed and unprotected" active={state.edr_status === "Not Installed"} onClick={() => only({ edr_status: "Not Installed" })} />
        <Kpi label="Crit / high vulns" value={s.crit_high} tone="serious" active={state.vulns === "crit_high"} onClick={() => only({ vulns: "crit_high" })} />
        <Kpi label="Not in any inventory" value={s.not_in_inventory} tone="violet" active={state.missing === "inventory"} onClick={() => only({ missing: "inventory" })} />
      </KpiGrid>

      <Card className="mt-4">
        <button className="flex w-full items-center gap-2 px-4 py-3 text-left text-[13px] font-semibold" onClick={() => setHow(!how)}>
          How an asset is marked internet-exposed <ChevronDown className={cn("size-4 transition-transform", how && "rotate-180")} />
          <span className="ml-auto font-normal text-muted">any one of these is enough</span>
        </button>
        {how && (
          <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
            {RULES.map(([k, t, d]) => (
              <div key={k} className="rounded-lg border border-border bg-surface-2/40 p-3">
                <div className="text-[12.5px] font-semibold">{t}</div>
                <div className="mt-1 text-[12px] text-fg-2">{d}</div>
              </div>
            ))}
            <div className="rounded-lg border border-dashed border-border p-3 text-[12px] text-muted md:col-span-2">
              Planned: Falcon Exposure Management&apos;s own internet-exposure flag when the API client has that scope. Egress IPs shared through NAT (below) are not exposure on their own.
            </div>
          </div>
        )}
      </Card>

      <div className="mt-4">
        <RegistryTable state={state} set={set} reset={() => replaceAll({})} fixed={{ exposed: "1" }} storageKey="exposure" hideExposure />
      </div>

      <Card className="mt-4">
        <CardHeader title="Organisation public IPs seen by CrowdStrike" hint="egress / NAT addresses hosts connect to CrowdStrike from — the organisation's internet-facing IP space" />
        <SimpleTable rows={s.egress_ips} maxHeight="320px" empty="No public egress IP reported yet" columns={[
          { key: "ip", label: "Public IP", render: (r: any) => <Mono>{r.ip}</Mono> },
          { key: "hosts", label: "Hosts behind it", num: true, render: (r: any) => fmtN(r.hosts) },
          { key: "online", label: "Online now", num: true, render: (r: any) => fmtN(r.online) },
          { key: "sample", label: "For example", render: (r: any) => <span className="text-xs text-fg-2">{r.sample.join(", ")}</span> },
        ]} />
      </Card>
    </div>
  );
}
