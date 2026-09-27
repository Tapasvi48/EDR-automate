"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { Button, Kpi, KpiGrid, PageHeader } from "@/components/ui";
import { fmtN } from "@/lib/format";
import { HostTable } from "@/components/host-table";
import { MappedUpload } from "@/components/mapped-upload";

const VIEWS: Record<string, Record<string, string>> = {
  "": { state: "gone" },
  console: { state: "gone", gone_source: "console" },
  import: { state: "gone", gone_source: "import" },
};

export default function EdrHistory() {
  const [state, set, replaceAll] = useUrlState();
  const { data: meta } = useMeta();
  const { data: s } = useQuery({ queryKey: ["edr-history"], queryFn: () => api<any>("/api/edr-history/summary") });
  const [upload, setUpload] = React.useState(false);
  const days = meta?.settings.auto_remove_days || "90";
  const view = ["console", "import"].includes(state.view) ? state.view : "";
  const pick = (v: string) => set({ view: view === v ? undefined : v });
  return (
    <div>
      <PageHeader title="EDR history"
        sub={`Devices that had CrowdStrike but whose agent is no longer live: removed from the console (our syncs saw them go — auto-removed after ${days} days offline, or deleted) or known only from an uploaded old EDR inventory. One row per device: duplicate agent IDs of a machine are merged, and a device back in the console with a new agent is not listed. Everywhere else these devices count as Offline.`}
        actions={<Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload old EDR inventory</Button>} />
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(220px,1fr))]">
        <Kpi label="Devices in EDR history" value={s?.devices ?? "–"} tone="info" foot={s ? `${fmtN(s.agents)} agent IDs, duplicates merged` : undefined} active={!view} onClick={() => replaceAll({})} />
        <Kpi label="Removed from console" value={s?.from_console ?? "–"} tone="serious" foot={s ? `${fmtN(s.auto)} auto-removed > ${days} days · ${fmtN(s.deleted)} deleted` : undefined} active={view === "console"} onClick={() => pick("console")} />
        <Kpi label="Old EDR import only" value={s?.import_only ?? "–"} foot="known only from an uploaded old inventory" active={view === "import"} onClick={() => pick("import")} />
      </KpiGrid>
      <HostTable state={state} set={set} reset={() => replaceAll({})} fixed={VIEWS[view]} omit={["view"]}
        defaults={{ sort: "removed_at", dir: "desc" }} storageKey="edrhistory2" removalFilter />
      {upload && <MappedUpload kind="edr" open onOpenChange={setUpload} />}
    </div>
  );
}
