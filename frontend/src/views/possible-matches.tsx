"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { Callout, FilterSelect, PageHeader, SearchInput } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { HostLink, Mono, When } from "@/components/badges";

/** Inventory nodes that may be a CrowdStrike agent: the IP is on one of the agent's NICs and the hostnames are close
 *  (abc / abc1, with no other abc<n> anywhere). For review only - these are not counted as installed anywhere. */
export default function PossibleMatches() {
  const [state, set, replaceAll] = useUrlState();
  const { data: meta } = useQuery({ queryKey: ["lobs-list"], queryFn: () => api<any>("/api/feasibility") });
  const cols: Column[] = [
    { key: "lob", label: "LOB", render: (r) => <b>{r.lob}</b> },
    { key: "ip", label: "Inventory IP", render: (r) => <Mono>{r.ip}</Mono> },
    { key: "node_name", label: "Inventory name", render: (r) => <b>{r.node_name}</b> },
    { key: "cs_hostname", label: "CrowdStrike host", render: (r) => <HostLink aid={r.aid}>{r.cs_hostname}</HostLink> },
    { key: "cs_connection_ip", label: "Connection IP", render: (r) => <Mono>{r.cs_connection_ip}</Mono> },
    { key: "cs_local_ip", label: "Local IP", render: (r) => <Mono>{r.cs_local_ip}</Mono> },
    { key: "online_state", label: "State", render: (r) => r.online_state || "–" },
    { key: "last_seen", label: "Last seen", render: (r) => (r.last_seen ? <When ts={r.last_seen} /> : "–") },
    { key: "reason", label: "Why it may match", wrap: true, render: (r) => <span className="text-[12px] text-fg-2">{r.reason}</span> },
  ];
  return (
    <div>
      <PageHeader title="Possible matches"
        sub="Inventory nodes whose IP sits on a CrowdStrike agent's NIC (not its connection IP) and whose hostname is only close to the agent's — e.g. abc and abc1, when no abc2 / abc3 exists in CrowdStrike or the inventories." />
      <Callout className="mb-4">For review only: these are <b>not</b> counted as installed anywhere. If one is right, fix the node name or IP in the inventory so it matches exactly.</Callout>
      <DataTable endpoint="/api/match-candidates" exportPath="/api/match-candidates/export" columns={cols} state={state} setState={set}
        storageKey="possible-matches" noun="possible matches" rowKey={(r: any) => `${r.lob_id}|${r.item_key}|${r.aid}`} onReset={() => replaceAll({})}
        filters={<>
          <SearchInput className="w-[260px]" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP or hostname" />
          <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v })} any="All" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />
        </>} />
    </div>
  );
}
