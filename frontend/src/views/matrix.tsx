"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Upload } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtRel } from "@/lib/format";
import { Badge, Button, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput } from "@/components/ui";
import { DataTable } from "@/components/data-table";
import { Mono } from "@/components/badges";
import { MappedUpload } from "@/components/mapped-upload";

export default function Matrix() {
  const [state, set, replaceAll] = useUrlState();
  const [upload, setUpload] = React.useState(false);
  const { data: s, error, refetch } = useQuery({ queryKey: ["comm-summary"], queryFn: () => api<any>("/api/comm/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  return (
    <div>
      <PageHeader title="Communication matrix"
        sub="Firewall / NAT flows: which sources may reach which destinations, through which firewall, NAT and ISP link. Allow rules from Internet / ISP make their destinations internet-exposed on those ports; every rule shows as a flow in Asset 360."
        actions={<>
          <Button onClick={() => downloadExcel("/api/file-templates/comm_matrix")}><Download /> Template</Button>
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload matrix</Button>
        </>} />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
        <Kpi label="Rules" value={s.rules} tone="info" foot={s.last_upload ? `uploaded ${fmtRel(s.last_upload.uploaded_at)}` : "no matrix uploaded"} active={!state.inbound} onClick={() => replaceAll({})} />
        <Kpi label="Inbound from internet" value={s.inbound} tone="crit" foot="Internet / ISP → internal" active={state.inbound === "1"} onClick={() => replaceAll({ inbound: "1" })} />
        <Kpi label="Assets exposed by rules" value={s.exposed_assets} tone="serious" href="/exposure/?exposure_src=matrix" />
        <Kpi label="Expired rules" value={s.expired} foot="past Valid Till, ignored" />
      </KpiGrid>
      <div className="mt-4">
        <DataTable endpoint="/api/comm/rules" exportPath="/api/comm/rules/export" state={state} setState={set} noun="rules" storageKey="comm"
          rowKey={(r: any) => String(r.id)} onReset={() => replaceAll({})} sortable={false}
          filters={<>
            <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Rule, IP, subnet, NAT IP, port, CR…" />
            <FilterSelect label="Direction" value={state.direction} onChange={(v) => set({ direction: v })} options={["Inbound", "Outbound", "Internal"]} />
            <FilterSelect label="Firewall" value={state.firewall} onChange={(v) => set({ firewall: v })} any="All" options={s.firewalls} />
            <FilterSelect label="From internet" value={state.inbound} onChange={(v) => set({ inbound: v })} options={[["1", "Only inbound from internet"]]} />
          </>}
          columns={[
            { key: "rule_id", label: "Rule", render: (r: any) => <span className="flex items-center gap-1.5"><b>{r.rule_id}</b>{r.inbound_internet ? <Badge tone="crit">internet</Badge> : null}{!r.active && <Badge>expired</Badge>}</span> },
            { key: "direction", label: "Direction" },
            { key: "src", label: "Source", wrap: true, render: (r: any) => <span className="text-[12px]"><span className="text-muted">{r.src_zone ? `${r.src_zone} · ` : ""}</span><Mono>{r.src}</Mono>{r.isp ? <span className="text-muted"> · {r.isp}</span> : null}</span> },
            { key: "dst_nat", label: "Public / NAT IP", render: (r: any) => <Mono>{r.dst_nat}</Mono> },
            { key: "dst", label: "Destination", wrap: true, render: (r: any) => <span className="text-[12px]"><span className="text-muted">{r.dst_zone ? `${r.dst_zone} · ` : ""}</span>{r.dst.split(/[\s,;]+/).filter(Boolean).slice(0, 3).map((d: string) => <Link key={d} className="mr-1 font-mono text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(d)}`}>{d}</Link>)}</span> },
            { key: "svc", label: "Service", render: (r: any) => <span>{(r.protocol || "any").toUpperCase()} {r.ports || "any"}{r.service ? <span className="text-[11.5px] text-muted"> · {r.service}</span> : null}</span> },
            { key: "firewall", label: "Firewall", render: (r: any) => <span>{r.firewall}{r.fw_rule ? <span className="text-[11.5px] text-muted"> · {r.fw_rule}</span> : null}</span> },
            { key: "action", label: "Action" },
            { key: "cr", label: "CR", hidden: true },
            { key: "valid_till", label: "Valid till", hidden: true },
            { key: "src_nat", label: "Source NAT", hidden: true },
            { key: "remarks", label: "Remarks", hidden: true, wrap: true },
          ]} />
      </div>
      {upload && <MappedUpload kind="comm" open onOpenChange={setUpload} />}
    </div>
  );
}
