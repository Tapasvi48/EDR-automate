"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Checkbox, Loading, PageHeader, SearchInput } from "@/components/ui";
import { DataTable, SimpleTable } from "@/components/data-table";
import { HostLink, HostStatus, Mono, When } from "@/components/badges";

type Kind = "duplicate" | "routing";

const TEXT: Record<Kind, { title: string; sub: string; noun: string; member: string }> = {
  duplicate: {
    title: "Duplicate agents",
    sub: "Agent IDs with the same connection IP and the same local IP where at most one is online — the same machine re-imaged, cloned or reinstalled while the old sensor record was never cleaned up. They are counted as one device. Expand a group to see which agent to keep.",
    noun: "duplicate groups",
    member: "The online (else most recently seen) agent is the real one — the others are stale records that can be hidden in the Falcon console.",
  },
  routing: {
    title: "Routing conflicts",
    sub: "Two or more agents that are online at the same time with the same connection IP and the same local IP — different live machines that look identical on the network (overlapping private ranges behind one NAT, cloned network config). Each agent is counted as its own device.",
    noun: "conflict groups",
    member: "Every online agent here is a separate live machine sharing the same connection and local IP. Fix the addressing or NAT so each one is distinguishable.",
  },
};

function Members({ kind, group, includeRemoved }: { kind: Kind; group: any; includeRemoved: string }) {
  const { data } = useQuery({
    queryKey: ["dupm", group.connection_ip, group.local_ip, includeRemoved],
    queryFn: () => api<any>("/api/duplicates/members", { params: { connection_ip: group.connection_ip, local_ip: group.local_ip, include_removed: includeRemoved } }),
  });
  if (!data) return <Loading />;
  const rows = data.rows;
  const rec = (x: any) => {
    if (x.console_state !== "active") return <Badge>Already {x.console_state}</Badge>;
    if (kind === "routing") return x.online_state === "online" ? <Badge tone="crit">Live · conflicting</Badge> : <Badge tone="warn">Offline</Badge>;
    return x === rows[0] ? <Badge tone="good">Keep · {x.online_state === "online" ? "online" : "most recent"}</Badge> : <Badge tone="warn">Stale duplicate · hide</Badge>;
  };
  return (
    <div className="px-4 py-3">
      <div className="mb-2 text-xs text-muted">{rows.length} agents · {TEXT[kind].member}</div>
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <SimpleTable rows={rows} columns={[
          { key: "hostname", label: "Hostname", render: (x: any) => <span><HostLink aid={x.aid}><b>{x.hostname}</b></HostLink>{x.is_reinstall ? <Badge tone="violet" className="ml-1.5">REINSTALL</Badge> : null}</span> },
          { key: "aid", label: "Agent ID", render: (x: any) => <Mono>{x.aid}</Mono> },
          { key: "st", label: "Status", render: (x: any) => <HostStatus r={x} /> },
          { key: "first_seen", label: "Installed", render: (x: any) => fmtDt(x.first_seen) },
          { key: "last_seen", label: "Last seen", render: (x: any) => <When ts={x.last_seen} /> },
          { key: "os_version", label: "OS" },
          { key: "agent_version", label: "Sensor", render: (x: any) => <Mono>{x.agent_version}</Mono> },
          { key: "serial_number", label: "Serial" },
          { key: "mac_address", label: "MAC", render: (x: any) => <Mono>{x.mac_address}</Mono> },
          { key: "rec", label: kind === "routing" ? "State" : "Recommendation", render: rec },
        ]} />
      </div>
    </div>
  );
}

export function PairGroups({ kind }: { kind: Kind }) {
  const [state, set, replaceAll] = useUrlState({});
  const t = TEXT[kind];
  const cols = [
    { key: "connection_ip", label: "Connection IP", render: (r: any) => <b className="font-mono text-[12.5px]">{r.connection_ip}</b> },
    { key: "local_ip", label: "Local IP", render: (r: any) => <b className="font-mono text-[12.5px]">{r.local_ip}</b> },
    { key: "n", label: "Agents", render: (r: any) => <Badge tone={kind === "routing" ? "crit" : "serious"}>{r.n} agents</Badge> },
    { key: "online", label: "Online", num: true },
    { key: "active", label: "In console", num: true },
    { key: "hostnames", label: "Hostnames", wrap: true },
    { key: "oldest_first_seen", label: "Oldest install", render: (r: any) => fmtDt(r.oldest_first_seen) },
    { key: "newest_first_seen", label: "Newest install", render: (r: any) => fmtDt(r.newest_first_seen) },
    { key: "latest_last_seen", label: "Latest seen", render: (r: any) => <When ts={r.latest_last_seen} /> },
  ];
  return (
    <div>
      <PageHeader title={t.title} sub={<>{t.sub} Shared ranges such as NAT/VPN pools can be excluded in Settings.</>} />
      <DataTable
        endpoint="/api/duplicates"
        exportPath="/api/duplicates/export"
        columns={cols}
        state={state}
        setState={set}
        fixed={{ kind }}
        sortable={false}
        defaultSize={100}
        noun={t.noun}
        rowKey={(r: any) => r.value}
        onReset={() => replaceAll({})}
        renderExpanded={(r: any) => <Members kind={kind} group={r} includeRemoved={state.include_removed || ""} />}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Filter by connection or local IP prefix" />
          <Checkbox checked={state.include_removed === "1"} onChange={(v) => set({ include_removed: v ? "1" : undefined })} label="Include removed / hidden agents" />
        </>}
      />
    </div>
  );
}

export default function Duplicates() {
  return <PairGroups kind="duplicate" />;
}
