"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Checkbox, Loading, PageHeader, SearchInput, Segmented } from "@/components/ui";
import { DataTable, SimpleTable } from "@/components/data-table";
import { HostLink, HostStatus, Mono, When } from "@/components/badges";

function Members({ by, value, includeRemoved }: { by: string; value: string; includeRemoved: string }) {
  const { data } = useQuery({ queryKey: ["dupm", by, value, includeRemoved], queryFn: () => api<any>("/api/duplicates/members", { params: { by, value, include_removed: includeRemoved } }) });
  if (!data) return <Loading />;
  const rows = data.rows;
  return (
    <div className="px-4 py-3">
      <div className="mb-2 text-xs text-muted">
        {rows.length} agents share this {by}. The most recently seen agent is usually the real one — older duplicates can be hidden in the Falcon console.
      </div>
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <SimpleTable rows={rows} columns={[
          { key: "hostname", label: "Hostname", render: (x: any) => <span><HostLink aid={x.aid}><b>{x.hostname}</b></HostLink>{x.is_reinstall ? <Badge tone="violet" className="ml-1.5">REINSTALL</Badge> : null}</span> },
          { key: "aid", label: "Agent ID", render: (x: any) => <Mono>{x.aid}</Mono> },
          { key: "local_ip", label: "IP", render: (x: any) => <Mono>{x.local_ip}</Mono> },
          { key: "st", label: "Status", render: (x: any) => <HostStatus r={x} /> },
          { key: "first_seen", label: "Installed", render: (x: any) => fmtDt(x.first_seen) },
          { key: "last_seen", label: "Last seen", render: (x: any) => <When ts={x.last_seen} /> },
          { key: "os_version", label: "OS" },
          { key: "agent_version", label: "Sensor", render: (x: any) => <Mono>{x.agent_version}</Mono> },
          { key: "serial_number", label: "Serial" },
          { key: "mac_address", label: "MAC", render: (x: any) => <Mono>{x.mac_address}</Mono> },
          { key: "rec", label: "Recommendation", render: (x: any) => x === rows[0] ? <Badge tone="good">Keep · most recent</Badge> : x.console_state === "active" ? <Badge tone="warn">Stale duplicate · hide</Badge> : <Badge>Already {x.console_state}</Badge> },
        ]} />
      </div>
    </div>
  );
}

export default function Duplicates() {
  const [state, set, replaceAll] = useUrlState({ by: "ip" });
  const by = state.by || "ip";
  const cols = [
    { key: "value", label: by === "ip" ? "IP address" : by === "hostname" ? "Hostname" : "Serial", render: (r: any) => <b className="font-mono text-[12.5px]">{r.value}</b> },
    { key: "n", label: "Agents", render: (r: any) => <Badge tone="serious">{r.n} agents</Badge> },
    { key: "active", label: "Active", num: true },
    { key: "online", label: "Online", num: true },
    { key: by === "ip" ? "hostnames" : "ips", label: by === "ip" ? "Hostnames" : "IPs", wrap: true },
    { key: "oldest_first_seen", label: "Oldest install", render: (r: any) => fmtDt(r.oldest_first_seen) },
    { key: "newest_first_seen", label: "Newest install", render: (r: any) => fmtDt(r.newest_first_seen) },
    { key: "latest_last_seen", label: "Latest seen", render: (r: any) => <When ts={r.latest_last_seen} /> },
  ];
  return (
    <div>
      <PageHeader title="Duplicate agents" sub="Multiple agent IDs sharing the same IP, hostname or serial — usually re-images, VDI clones or reinstalls where the old sensor record was never cleaned up. Expand a group to see every agent and which one to keep. Shared IPs such as NAT/VPN ranges can be excluded in Settings." />
      <DataTable
        key={by}
        endpoint="/api/duplicates"
        exportPath="/api/duplicates/export"
        columns={cols}
        state={{ ...state, by }}
        setState={set}
        sortable={false}
        defaultSize={100}
        noun="duplicate groups"
        rowKey={(r: any) => r.value}
        onReset={() => replaceAll({ by })}
        renderExpanded={(r: any) => <Members by={by} value={r.value} includeRemoved={state.include_removed || ""} />}
        filters={<>
          <Segmented value={by} onChange={(v) => replaceAll({ by: v })} options={[["ip", "Same IP"], ["hostname", "Same hostname"], ["serial", "Same serial"]]} />
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder={`Filter by ${by} prefix`} />
          <Checkbox checked={state.include_removed === "1"} onChange={(v) => set({ include_removed: v ? "1" : undefined })} label="Include removed / hidden agents" />
        </>}
      />
    </div>
  );
}
