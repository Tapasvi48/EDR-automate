"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { Kpi, KpiGrid, PageHeader } from "@/components/ui";
import { RegistryTable } from "@/components/registry-table";

/** Every IP known to the console — LOB inventories, CrowdStrike, VA scans and the NIAM dump — one row per IP. */
export default function Inventory() {
  const [state, set, replaceAll] = useUrlState();
  const { data: s } = useQuery({ queryKey: ["registry-summary"], queryFn: () => api<any>("/api/registry/summary") });
  const on = (k: string, v: string) => state[k] === v;
  return (
    <div>
      <PageHeader title="All inventory" />
      {s && (
        <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
          <Kpi label="Total assets" value={s.total} tone="info" foot={`${fmtN(s.inventory)} in LOB inventories`} active={!Object.keys(state).some((k) => !["page", "size", "sort", "dir"].includes(k))} onClick={() => replaceAll({})} />
          <Kpi label="EDR installed" value={s.applicable ? `${pct(s.installed, s.applicable)}%` : "–"} tone="good"
            foot={`${fmtN(s.installed)} of ${fmtN(s.applicable)} applicable${s.applicable_not_inv ? ` · incl. ${fmtN(s.applicable_not_inv)} EDR-only` : ""}`}
            active={on("edr_applicable", "1")} onClick={() => replaceAll({ edr_applicable: "1" })} />
          <Kpi label="NIAM integrated" value={s.total ? `${pct(s.niam, s.total)}%` : "–"} foot={`${fmtN(s.niam)} of ${fmtN(s.total)} · ${fmtN(s.not_in_niam)} missing`} active={on("missing", "niam")} onClick={() => replaceAll({ missing: "niam" })} />
          <Kpi label="VA scanned" value={s.total ? `${pct(s.scan, s.total)}%` : "–"} foot={`${fmtN(s.scan)} of ${fmtN(s.total)} assets`} active={on("missing", "scan")} onClick={() => replaceAll({ missing: "scan" })} />
          <Kpi label="Unidentified" value={s.unidentified} tone="violet" foot="no inventory, no EDR · not in applicable" active={on("feasibility", "Unidentified")} onClick={() => replaceAll({ feasibility: "Unidentified" })} />
          <Kpi label="Not EDR feasible" value={s.not_feasible} foot={`OS, node type, LOB or domain${s.to_be_decided ? ` · ${fmtN(s.to_be_decided)} to be decided` : ""}`} active={on("feasibility", "No")} onClick={() => replaceAll({ feasibility: "No" })} />
          <Kpi label="Internet exposed" value={s.exposed} tone="crit" active={on("exposed", "1")} onClick={() => replaceAll({ exposed: "1" })} />
        </KpiGrid>
      )}
      <RegistryTable state={state} set={set} reset={() => replaceAll({})} />
    </div>
  );
}
