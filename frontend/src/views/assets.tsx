"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { Kpi, KpiGrid, PageHeader, Segmented } from "@/components/ui";
import { HostTable } from "@/components/host-table";
import { NotConnected } from "@/components/sync-progress";

const TILE_KEYS = ["status", "unmapped", "rfm", "outdated", "history"];

export default function Assets() {
  const [state, set, replaceAll] = useUrlState();
  const { data } = useQuery({ queryKey: ["overview"], queryFn: () => api<any>("/api/overview") });
  const k = data?.kpi;
  const rd = data?.removed_devices || { devices: 0, from_console: 0, import_only: 0 };
  const gone = rd.devices || 0;
  const only = (patch: Record<string, string>) => set({ ...Object.fromEntries(TILE_KEYS.map((x) => [x, undefined])), ...patch });
  const none = !TILE_KEYS.some((x) => state[x]);
  // one row per device: agents sharing a connection IP are merged (unless you explicitly look at duplicates)
  const fixed: Record<string, string> = state.duplicate === "1" ? { state: "active" } : { state: "active", dedupe: "1" };
  return (
    <div>
      <PageHeader
        title="CrowdStrike assets"
        sub={<>Every host in the CrowdStrike console, one row per device (devices that left the console are counted as offline and listed under EDR history). Duplicate agents (same connection + local IP, at most one online) are counted once{k && k.agents > k.active ? ` (${fmtN(k.agents - k.active)} duplicate agents merged — see Duplicates)` : ""}.</>}
      />
      <NotConnected />
      {k && (
        <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
          <Kpi label="Total hosts" value={k.active + gone} tone="info" foot={`${fmtN(k.active)} in console · ${fmtN(gone)} in EDR history`} active={none} onClick={() => only({})} />
          <Kpi label="Online" value={k.online} foot={`${pct(k.online, k.active + gone)}% of hosts`} tone="good" active={state.status === "online"} onClick={() => only({ status: "online" })} />
          <Kpi label="Offline" value={k.offline + gone} foot={`${fmtN(k.offline)} in console · ${fmtN(gone)} left the console`} tone="warn" active={state.status === "offline"} onClick={() => only({ status: "offline" })} />
          <Kpi label="EDR history" value={gone} foot={`${fmtN(rd.from_console)} removed · ${fmtN(rd.import_only)} old EDR import`} tone="serious" href="/edr-history/" />
          <Kpi label="Not in inventory" value={k.unmapped} foot="no LOB inventory row matches the agent" tone="violet" active={state.unmapped === "1"} onClick={() => only({ unmapped: "1" })} />
          <Kpi label="RFM" value={k.rfm} foot="reduced functionality" tone="warn" active={state.rfm === "1"} onClick={() => only({ rfm: "1" })} />
          <Kpi label="Outdated sensor" value={k.outdated_sensor} foot="older than N-2" tone="warn" active={state.outdated === "1"} onClick={() => only({ outdated: "1" })} />
        </KpiGrid>
      )}
      {k && state.status === "offline" && (
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <Segmented value={state.history || "1"} onChange={(v) => set({ history: v === "1" ? undefined : v })}
            options={[["1", `All offline (${fmtN(k.offline + gone)})`], ["0", `In the console (${fmtN(k.offline)})`], ["only", `EDR history (${fmtN(gone)})`]]} />
          <span className="text-[12px] text-muted">EDR history = agents that left the console (removed, or only in the old EDR sheet), one per device</span>
        </div>
      )}
      <HostTable state={state} set={set} reset={() => replaceAll({})} fixed={fixed} />
    </div>
  );
}
