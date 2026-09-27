"use client";
import { useUrlState } from "@/lib/hooks";
import { PageHeader } from "@/components/ui";
import { VulnPanel } from "@/components/vuln-views";

export default function Vulnerabilities() {
  const [state, set, replaceAll] = useUrlState();
  return (
    <div>
      <PageHeader title="Vulnerabilities"
        sub="Nessus scan findings for every LOB, matched to the LOB inventory (MSP, node type) and to CrowdStrike (EDR status). Findings missing from a later scan of the same IP are marked fixed." />
      <VulnPanel state={state} set={set} replaceAll={replaceAll} />
    </div>
  );
}
