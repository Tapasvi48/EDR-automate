"use client";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Callout, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Tabs } from "@/components/ui";
import { DataTable, type Column } from "@/components/data-table";
import { Mono } from "@/components/badges";

const SEV_TONE: Record<string, any> = { Critical: "crit", Important: "serious", Moderate: "warn", Low: "neutral" };

/** Red Hat Satellite across the fleet: which hosts have security fixes waiting, and which errata matter most. */
export default function Patches() {
  const [state, set, replaceAll] = useUrlState();
  const tab = state.tab || "hosts";
  const { data: s, error, refetch } = useQuery({ queryKey: ["satellite-summary"], queryFn: () => api<any>("/api/satellite/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const on = (k: string, v: string) => state[k] === v;
  const hostCols: Column[] = [
    { key: "name", label: "Host", render: (r) => <Link className="font-medium hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip || r.name)}`}>{r.name}</Link> },
    { key: "ip", label: "IP", sort: false, render: (r) => <Mono>{r.ip}</Mono> },
    { key: "lob", label: "LOB", sort: false },
    { key: "os", label: "OS", sort: false },
    { key: "packages", label: "Packages", render: (r) => fmtN(r.packages ?? 0) },
    { key: "upgradable", label: "Upgradable", render: (r) => r.upgradable ? <b className="text-warn-fg">{fmtN(r.upgradable)}</b> : <span className="text-muted">0</span> },
    { key: "errata_security", label: "Security errata", render: (r) => fmtN(r.errata_security ?? 0) },
    { key: "installable_security", label: "Fix available now", render: (r) => r.installable_security ? <Badge tone="crit">{fmtN(r.installable_security)}</Badge> : <span className="text-good-fg">0</span> },
    { key: "compliance", label: "MBSS", render: (r) => r.compliance_pct == null ? <span className="text-muted">no report</span>
      : <b className={r.compliance_pct >= 90 ? "text-good-fg" : r.compliance_pct >= 75 ? "text-warn-fg" : "text-crit-fg"}>{r.compliance_pct}%</b> },
    { key: "last_checkin", label: "Checked in", sort: false, render: (r) => r.last_checkin ? fmtRel(r.last_checkin) : "–" },
  ];
  const errCols: Column[] = [
    { key: "errata_id", label: "Erratum", sort: false, render: (r) => <b className="font-mono text-[12px]">{r.errata_id}</b> },
    { key: "severity", label: "Severity", sort: false, render: (r) => r.severity ? <Badge tone={SEV_TONE[r.severity] || "neutral"}>{r.severity}</Badge> : <span className="text-muted">{r.type}</span> },
    { key: "title", label: "Title", sort: false, wrap: true },
    { key: "cves", label: "CVEs", sort: false, wrap: true, render: (r) => <span className="text-[12px]">{r.cves}</span> },
    { key: "hosts", label: "Hosts affected", sort: false, render: (r) => fmtN(r.hosts) },
    { key: "installable", label: "Installable now on", sort: false, render: (r) => <span className={r.installable ? "font-semibold text-good-fg" : "text-muted"}>{fmtN(r.installable)} hosts</span> },
    { key: "issued", label: "Issued", sort: false },
  ];
  return (
    <div>
      <PageHeader title="Patches & errata" sub="From Red Hat Satellite: packages and security errata per Linux host, and which fixes can be installed right now (remediation available). Findings on Vulnerabilities and Asset 360 show the erratum that fixes them." />
      {!s.configured && <Callout tone="warn" className="mb-4">Red Hat Satellite is not connected. Set it up under <Link className="underline" href="/connectors/">Integrations</Link>.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Satellite hosts" value={s.hosts} tone="info" foot={`of ${fmtN(s.rhel_family_nodes)} RHEL-family inventory nodes`} onClick={() => replaceAll({ tab: "hosts" })} active={tab === "hosts" && !state.state} />
        <Kpi label="Fix available now" value={s.fix_now_hosts} tone="crit" foot={`${fmtN(s.fix_now)} security errata installable`} active={on("state", "fix_now")} onClick={() => replaceAll({ tab: "hosts", state: "fix_now" })} />
        <Kpi label="Security errata" value={s.security} foot="applicable, fleet-wide" onClick={() => replaceAll({ tab: "errata", type: "security" })} active={tab === "errata"} />
        <Kpi label="Upgradable packages" value={s.upgradable_hosts} tone="warn" foot="hosts with updates pending" active={on("state", "upgradable")} onClick={() => replaceAll({ tab: "hosts", state: "upgradable" })} />
        <Kpi label="MBSS compliance" value={s.compliance_pct == null ? "–" : `${s.compliance_pct}%`} tone="good" foot={<Link className="hover:underline" href="/mbss/">{fmtN(s.noncompliant)} hosts with failed rules</Link>} />
      </KpiGrid>
      <Tabs value={tab} onChange={(v) => replaceAll({ tab: v })} tabs={[{ id: "hosts", label: "Hosts", count: s.hosts }, { id: "errata", label: "Errata" }]} />
      {tab === "hosts" ? (
        <DataTable key="h" endpoint="/api/satellite/hosts" columns={hostCols} state={state} setState={set} omit={["tab"]} storageKey="sat-hosts" noun="hosts"
          rowKey={(r: any) => String(r.host_id)} onReset={() => replaceAll({ tab })}
          filters={<>
            <SearchInput className="w-[260px]" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Host, IP or OS" />
            <FilterSelect label="Show" value={state.state} onChange={(v) => set({ state: v })} any="All hosts"
              options={[["fix_now", "Fix available now"], ["upgradable", "Upgradable packages"], ["noncompliant", "Failed MBSS rules"], ["no_report", "No OpenSCAP report"]]} />
          </>} />
      ) : (
        <DataTable key="e" endpoint="/api/satellite/errata" columns={errCols} state={state} setState={set} omit={["tab"]} storageKey="sat-errata" noun="errata"
          rowKey={(r: any) => r.errata_id} onReset={() => replaceAll({ tab })}
          filters={<>
            <SearchInput className="w-[260px]" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Erratum, title or CVE" />
            <FilterSelect label="Type" value={state.type} onChange={(v) => set({ type: v })} any="All" options={[["security", "Security"], ["bugfix", "Bug fix"], ["enhancement", "Enhancement"]]} />
            <FilterSelect label="Severity" value={state.severity} onChange={(v) => set({ severity: v })} any="All" options={["Critical", "Important", "Moderate", "Low"]} />
          </>} />
      )}
      {s.fetched_at && <div className="mt-2 text-[11.5px] text-muted">Satellite data from {fmtDt(s.fetched_at)}</div>}
    </div>
  );
}
