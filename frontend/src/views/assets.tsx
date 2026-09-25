"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { Kpi, KpiGrid, PageHeader } from "@/components/ui";
import { HostTable } from "@/components/host-table";
import { NotConnected } from "@/components/sync-progress";

const TILE_KEYS = ["status", "unmapped", "rfm", "outdated"];

export default function Assets() {
  const [state, set, replaceAll] = useUrlState();
  const { data } = useQuery({ queryKey: ["overview"], queryFn: () => api<any>("/api/overview") });
  const k = data?.kpi;
  const only = (patch: Record<string, string>) => set({ ...Object.fromEntries(TILE_KEYS.map((x) => [x, undefined])), ...patch });
  const none = !TILE_KEYS.some((x) => state[x]);
  // one row per device: agents sharing an IP are merged (unless you explicitly look at duplicates)
  const fixed: Record<string, string> = state.duplicate === "1" ? { state: "active" } : { state: "active", dedupe: "1" };
  return (
    <div>
      <PageHeader
        title="All assets"
        sub={<>Every device currently in the CrowdStrike console. Agents that share an IP are counted once{k && k.agents > k.active ? ` (${fmtN(k.agents - k.active)} duplicate agents merged — see Duplicates)` : ""}. Removed and hidden agents are under Offline &amp; stale.</>}
      />
      <NotConnected />
      {k && (
        <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
          <Kpi label="In console" value={k.active} tone="info" active={none} onClick={() => only({})} />
          <Kpi label="Online" value={k.online} foot={`${pct(k.online, k.active)}%`} tone="good" active={state.status === "online"} onClick={() => only({ status: "online" })} />
          <Kpi label="Offline" value={k.offline} foot={`${pct(k.offline, k.active)}%`} tone="crit" active={state.status === "offline"} onClick={() => only({ status: "offline" })} />
          <Kpi label="Not in any LOB" value={k.unmapped} foot="unmapped devices" tone="violet" active={state.unmapped === "1"} onClick={() => only({ unmapped: "1" })} />
          <Kpi label="RFM" value={k.rfm} foot="reduced functionality" tone="warn" active={state.rfm === "1"} onClick={() => only({ rfm: "1" })} />
          <Kpi label="Outdated sensor" value={k.outdated_sensor} foot="older than N-2" tone="warn" active={state.outdated === "1"} onClick={() => only({ outdated: "1" })} />
        </KpiGrid>
      )}
      <HostTable state={state} set={set} reset={() => replaceAll({})} fixed={fixed} />
    </div>
  );
}
