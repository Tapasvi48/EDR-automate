"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Upload } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, FilterSelect, Kpi, KpiGrid, Loading, PageHeader, SearchInput } from "@/components/ui";
import { DataTable } from "@/components/data-table";
import { MappedUpload } from "@/components/mapped-upload";

const STATE_TONE: Record<string, any> = { Active: "good", Expiring: "warn", Expired: "neutral" };

export default function Exceptions() {
  const [state, set, replaceAll] = useUrlState();
  const [upload, setUpload] = React.useState(false);
  const { data: s, error, refetch } = useQuery({ queryKey: ["sod-summary"], queryFn: () => api<any>("/api/sod/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  return (
    <div>
      <PageHeader title="Exceptions (SOD)"
        sub="Approved vulnerability exceptions. Matching findings are Accepted: still listed, but left out of open counts, risk scores and exposure. They reopen automatically when the exception expires or is removed."
        actions={<>
          <Button onClick={() => downloadExcel("/api/file-templates/sod")}><Download /> Template</Button>
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload register</Button>
        </>} />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
        <Kpi label="Active exceptions" value={s.active} tone="good" foot={s.last_upload ? `register uploaded ${fmtRel(s.last_upload.uploaded_at)}` : "no register uploaded"} active={state.status === "Active"} onClick={() => replaceAll({ status: "Active" })} />
        <Kpi label="Expire in 30 days" value={s.expiring} tone="warn" foot="findings will reopen" active={state.status === "Expiring"} onClick={() => replaceAll({ status: "Expiring" })} />
        <Kpi label="Expired" value={s.expired} foot="kept for audit, not applied" active={state.status === "Expired"} onClick={() => replaceAll({ status: "Expired" })} />
        <Kpi label="Not matching anything" value={s.unused} tone="violet" foot="active but no finding matches" active={state.unused === "1"} onClick={() => replaceAll({ unused: "1" })} />
        <Kpi label="Findings accepted" value={s.accepted} tone="info" foot={`${fmtN(s.accepted_crit)} critical · ${fmtN(s.accepted_high)} high · ${fmtN(s.accepted_hosts)} hosts`} href="/vulnerabilities/?vtab=findings&status=accepted" />
      </KpiGrid>
      <div className="mt-4">
        <DataTable endpoint="/api/sod/exceptions" exportPath="/api/sod/exceptions/export" state={state} setState={set} noun="exceptions" storageKey="sod"
          rowKey={(r: any) => String(r.id)} onReset={() => replaceAll({})} sortable={false}
          filters={<>
            <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Exception, IP, plugin, CVE, approver…" />
            <FilterSelect label="Status" value={state.status} onChange={(v) => set({ status: v })} options={["Active", "Expiring", "Expired"]} />
          </>}
          columns={[
            { key: "exception_id", label: "Exception", render: (r: any) => <b>{r.exception_id}</b> },
            { key: "state", label: "Status", render: (r: any) => <Badge tone={STATE_TONE[r.state]}>{r.state}</Badge> },
            { key: "scope", label: "Scope", render: (r: any) => <span>{r.scope}{r.target || r.lob ? <span className="ml-1 font-mono text-[12px] text-fg-2">{r.target || r.lob}</span> : null}</span> },
            { key: "vuln", label: "Vulnerability", wrap: true, render: (r: any) => <span className="text-[12.5px]">{[r.plugin_id && `Plugin ${r.plugin_id}`, r.cve, r.name].filter(Boolean).join(" · ")}{r.port ? ` · port ${r.port}` : ""}</span> },
            { key: "matched", label: "Findings accepted", num: true, render: (r: any) => r.matched ? <Link className="font-semibold text-accent-fg hover:underline" href={`/vulnerabilities/?vtab=findings&status=accepted&q=${encodeURIComponent(r.plugin_id || r.cve || r.name || "")}`}>{fmtN(r.matched)}</Link> : <span className="text-muted">0</span> },
            { key: "valid_till", label: "Valid till" },
            { key: "approved_by", label: "Approved by" },
            { key: "justification", label: "Justification", wrap: true, render: (r: any) => <span className="text-[12px] text-fg-2">{r.justification}</span> },
            { key: "control", label: "Compensating control", hidden: true, wrap: true },
            { key: "ticket", label: "Ticket / CR", hidden: true },
            { key: "approval_date", label: "Approved on", hidden: true },
          ]} />
      </div>
      {upload && <MappedUpload kind="sod" open onOpenChange={setUpload} />}
    </div>
  );
}
