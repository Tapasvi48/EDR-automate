"use client";
import * as React from "react";
import { useUrlState } from "@/lib/hooks";
import { PageHeader } from "@/components/ui";
import { IocChecker, IocRecent } from "@/components/ai/ioc";

/** IOC check: IPs, domains, URLs and hashes against CrowdStrike threat intelligence, custom IOCs and our own data. */
export default function Ioc() {
  const [state] = useUrlState();
  return (
    <div>
      <PageHeader title="IOC check" sub="Is an IP, domain, URL or file hash known bad, is it one of ours, and have we seen it? CrowdStrike threat intel and custom IOCs straight from the CrowdStrike API (no Falcon MCP needed), plus detections, NDR alerts, assets, WHOIS, InternetDB, GreyNoise and VirusTotal. Hunt any value across all endpoints in one click." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <IocChecker initial={state.v || ""} autoRun={!!state.v} />
        <IocRecent />
      </div>
    </div>
  );
}
