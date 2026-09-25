"use client";
import { useUrlState } from "@/lib/hooks";
import { Input, PageHeader, SearchInput, Select } from "@/components/ui";
import { DataTable } from "@/components/data-table";
import { EVENT_LABEL, EventBadge, EventDetails, HostLink, Mono, When } from "@/components/badges";

export default function ActivityLog() {
  const [state, set, replaceAll] = useUrlState();
  return (
    <div>
      <PageHeader title="Activity log" sub="Changes detected between syncs: new installs, removals, hides, restores, IP and hostname changes, sensor updates and reinstalls." />
      <DataTable
        endpoint="/api/events" exportPath="/api/events/export" state={state} setState={set} sortable={false} noun="events"
        rowKey={(r: any) => r.ts + r.aid + r.event}
        onReset={() => replaceAll({})}
        columns={[
          { key: "ts", label: "Time", render: (r: any) => <When ts={r.ts} /> },
          { key: "event", label: "Event", render: (r: any) => <EventBadge e={r.event} /> },
          { key: "hostname", label: "Host", render: (r: any) => <HostLink aid={r.aid}><b>{r.hostname || r.aid}</b></HostLink> },
          { key: "local_ip", label: "IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
          { key: "details", label: "Details", wrap: true, render: (r: any) => <EventDetails e={r} /> },
        ]}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Hostname, IP or AID" />
          <Select value={state.event} onChange={(v) => set({ event: v })} placeholder="All events" options={Object.entries(EVENT_LABEL)} />
          <span className="text-xs text-fg-2">From</span><Input type="date" value={state.from || ""} onChange={(e) => set({ from: e.target.value })} />
          <span className="text-xs text-fg-2">To</span><Input type="date" value={state.to || ""} onChange={(e) => set({ to: e.target.value })} />
        </>}
      />
    </div>
  );
}
