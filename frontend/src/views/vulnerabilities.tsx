"use client";
import { useUrlState } from "@/lib/hooks";
import { PageHeader, Tabs } from "@/components/ui";
import { VulnPanel } from "@/components/vuln-views";
import { VaPublicPanel } from "@/components/va-public";

export default function Vulnerabilities() {
  const [state, set, replaceAll] = useUrlState();
  return (
    <div>
      <PageHeader title="Vulnerabilities"
        sub="Nessus scan findings for every LOB, matched to the LOB inventory (MSP, node type) and to CrowdStrike (EDR status). Findings missing from a later scan of the same IP are marked fixed." />
      <Tabs value={state.section || "findings"} onChange={(v) => replaceAll(v === "findings" ? {} : { section: v })}
        tabs={[{ id: "findings", label: "Scan findings" }, { id: "vapub", label: "VA public inventory" }]} />
      <div className="mt-4">
        {state.section === "vapub" ? <VaPublicPanel state={state} set={set} replaceAll={replaceAll} /> : <VulnPanel state={state} set={set} replaceAll={replaceAll} />}
      </div>
    </div>
  );
}
