"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Cloud, Database, KeyRound, Network, Radio, ScanSearch, Server, ShieldAlert, Ticket, Trash2, Upload, Users } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, SearchInput, Segmented, Select, useConfirm } from "@/components/ui";
import { DataTable, SimpleTable } from "@/components/data-table";
import { EdrBadge, HostLink, Mono, SevCounts } from "@/components/badges";
import { MappedUpload } from "@/components/mapped-upload";
import { ShowOnly } from "@/components/vuln-views";

const EDR_OPTS: [string, string][] = [["Online", "EDR online"], ["Offline", "EDR offline"], ["Not Installed", "No EDR"]];

/** Integrations that could be added next (shown as a roadmap under the live ones). */
const IDEAS: { icon: React.ElementType; name: string; what: string }[] = [
  { icon: Database, name: "CMDB (ServiceNow / BMC)", what: "Pull CIs with owner, app and criticality; flag assets in CMDB with no EDR and EDR agents with no CI." },
  { icon: Users, name: "Active Directory / Entra ID", what: "Computer objects and last logon: machines in AD without EDR, stale AD objects still carrying agents." },
  { icon: ScanSearch, name: "Tenable / Qualys API", what: "Pull scan results on a schedule instead of uploading Nessus exports." },
  { icon: Cloud, name: "Cloud inventories (AWS / Azure / GCP)", what: "Running instances vs EDR: coverage of cloud workloads per account / subscription." },
  { icon: Server, name: "vCenter / Nutanix", what: "Every VM with power state: powered-on VMs with no sensor, orphaned agents of deleted VMs." },
  { icon: Network, name: "DHCP / IPAM (Infoblox)", what: "IP-to-MAC history to resolve IP reuse and match hosts that change address." },
  { icon: Ticket, name: "ITSM tickets", what: "Raise a ticket per MSP for pending installs, offline agents and critical vulnerabilities; track closure." },
  { icon: KeyRound, name: "PAM / jump-server lists", what: "Privileged-access targets without EDR — the highest-risk gap." },
  { icon: Boxes, name: "Other EDR / AV consoles", what: "Machines protected by another product during migration, so they don't count as gaps." },
];

export default function Integrations() {
  const [state, set, replaceAll] = useUrlState();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [upload, setUpload] = React.useState(false);
  const { data: s, error, refetch } = useQuery({ queryKey: ["niam-summary"], queryFn: () => api<any>("/api/niam/summary") });
  const uploads = useQuery({ queryKey: ["niam-uploads"], queryFn: () => api<any>("/api/niam/uploads") });
  const view = state.view || "nodes";
  const pick = (patch: Record<string, string>) => replaceAll({ view: "nodes", ...patch });
  const clear = async () => {
    if (!(await confirm({ title: "Remove NIAM data?", body: "Deletes every NIAM node and upload. Inventory, EDR and vulnerability data are not affected.", ok: "Remove", danger: true }))) return;
    await api("/api/niam", { method: "DELETE" });
    toast.success("NIAM data removed");
    qc.invalidateQueries();
  };

  return (
    <div>
      <PageHeader title="Integrations" sub="Extra data sources matched against LOB inventories, CrowdStrike and vulnerability scans. Every match works with IPv4 and IPv6 in any spelling." />

      <Card className="mb-4">
        <div className="flex flex-wrap items-center gap-4 p-5">
          <div className="grid size-11 place-items-center rounded-xl bg-accent-soft text-accent-fg"><Radio className="size-5" /></div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-[15px] font-semibold">NIAM dump <Badge tone={s?.nodes ? "good" : "neutral"}>{s?.nodes ? "active" : "no data yet"}</Badge></div>
            <div className="text-[12.5px] text-muted">
              Host (IP) → NE ID. Shows each network element&apos;s EDR status, LOB / MSP and open vulnerabilities; the NE ID also appears in Asset 360 search.
              {s?.last_upload && <> Last upload {fmtRel(s.last_upload.uploaded_at)} · {s.last_upload.filename}</>}
            </div>
          </div>
          {!!s?.nodes && <Button variant="ghost" size="icon" title="Remove NIAM data" onClick={clear}><Trash2 /></Button>}
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload NIAM dump</Button>
        </div>
      </Card>

      {!s ? <Loading error={error} retry={() => refetch()} /> : s.nodes > 0 && (
        <>
          <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
            <Kpi label="NIAM nodes" value={s.nodes} tone="info" foot={`${fmtN(s.ne_ids)} NE IDs`} onClick={() => replaceAll({})} />
            <Kpi label="EDR installed" value={s.online + s.offline} tone="good" foot={`${fmtN(s.online)} online · ${fmtN(s.offline)} offline`} onClick={() => pick({ edr_status: "Online|Offline" })} />
            <Kpi label="No EDR" value={s.no_edr} tone="crit" foot={`${fmtN(s.never_installed)} never · ${fmtN(s.edr_removed)} removed`} onClick={() => pick({ no_edr: "1" })} />
            <Kpi label="Not in any inventory" value={s.not_in_inventory} tone="violet" onClick={() => pick({ in_inventory: "0" })} />
            <Kpi label="Crit / high vulns" value={s.crit_high} tone="serious" onClick={() => pick({ crit_high: "1" })} />
            <Kpi label="Crit / high · no EDR" value={s.crit_high_no_edr} tone="crit" foot="highest risk" onClick={() => pick({ crit_high: "1", no_edr: "1" })} />
            {s.gone > 0 && <Kpi label="Dropped from NIAM" value={s.gone} foot="in an earlier dump only" onClick={() => pick({ present: "0" })} />}
          </KpiGrid>

          <div className="my-4">
            <Segmented value={view as "nodes" | "lob" | "uploads"} onChange={(v) => replaceAll({ view: v })}
              options={[["nodes", "Nodes"], ["lob", "By LOB"], ["uploads", `Uploads (${uploads.data?.rows.length ?? 0})`]]} />
          </div>
          {view === "nodes" && <NiamNodes state={state} set={set} reset={() => replaceAll({})} />}
          {view === "lob" && (
            <Card>
              <SimpleTable rows={s.by_lob} columns={[
                { key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> },
                { key: "nodes", label: "Nodes", num: true, render: (r: any) => fmtN(r.nodes) },
                { key: "edr", label: "EDR installed", num: true, render: (r: any) => <span className="text-good-fg">{fmtN(r.edr)}</span> },
                { key: "no_edr", label: "No EDR", num: true, render: (r: any) => r.no_edr ? <b className="text-crit-fg">{fmtN(r.no_edr)}</b> : "0" },
                { key: "pct", label: "Coverage", num: true, render: (r: any) => r.nodes ? `${Math.round((100 * r.edr) / r.nodes)}%` : "–" },
                { key: "crit_high", label: "With crit / high vulns", num: true, render: (r: any) => fmtN(r.crit_high) },
              ]} />
            </Card>
          )}
          {view === "uploads" && (
            <Card>
              <SimpleTable rows={uploads.data?.rows || []} empty="No uploads" columns={[
                { key: "uploaded_at", label: "Uploaded", render: (r: any) => fmtDt(r.uploaded_at) },
                { key: "filename", label: "File" }, { key: "uploaded_by", label: "By" }, { key: "note", label: "Note", wrap: true },
                { key: "rows", label: "Nodes", num: true, render: (r: any) => fmtN(r.rows) },
                { key: "delta", label: "Changes", render: (r: any) => <span className="tabular"><span className="text-accent-fg">+{fmtN(r.added)}</span> · <span className="text-crit-fg">−{fmtN(r.removed)}</span> · <span className="text-warn-fg">~{fmtN(r.changed)}</span></span> },
              ]} />
            </Card>
          )}
        </>
      )}

      <Card className="mt-6">
        <CardHeader title="More integrations that fit this console" hint="not built yet — tell us which ones you need" />
        <div className="grid gap-3 px-4 pb-4 md:grid-cols-2 xl:grid-cols-3">
          {IDEAS.map(({ icon: Icon, name, what }) => (
            <div key={name} className="flex gap-3 rounded-xl border border-border bg-surface-2/50 p-3">
              <Icon className="mt-0.5 size-4 shrink-0 text-fg-2" />
              <div><div className="text-[13px] font-semibold">{name}</div><div className="text-[12px] text-muted">{what}</div></div>
            </div>
          ))}
        </div>
      </Card>
      {upload && <MappedUpload kind="niam" open onOpenChange={setUpload} />}
    </div>
  );
}

function NiamNodes({ state, set, reset }: { state: Record<string, string>; set: any; reset: () => void }) {
  return (
    <DataTable endpoint="/api/niam/nodes" exportPath="/api/niam/nodes/export" state={state} setState={set} omit={["view"]} noun="nodes"
      storageKey="niam" rowKey={(r: any) => String(r.id)} onReset={reset}
      columns={[
        { key: "ne_id", label: "NE ID", render: (r: any) => <b>{r.ne_id}</b> },
        { key: "ip", label: "Host / IP", render: (r: any) => r.ip ? <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip)}`}>{r.ip}</Link> : <Mono>{r.host}</Mono> },
        { key: "ne_name", label: "NE name", sort: false, render: (r: any) => r.extra?.["NE Name"] || "" },
        { key: "ne_type", label: "NE type", sort: false, render: (r: any) => r.extra?.["NE Type"] || "" },
        { key: "edr_status", label: "EDR", render: (r: any) => <EdrBadge s={r.edr_status} /> },
        { key: "hostname", label: "Falcon host", sort: false, render: (r: any) => r.aid && !String(r.aid).startsWith("import-") ? <HostLink aid={r.aid}>{r.hostname}</HostLink> : (r.hostname || <span className="text-muted">–</span>) },
        { key: "lobs", label: "LOB", render: (r: any) => r.lobs || <span className="text-violet-fg">Not in inventory</span> },
        { key: "msps", label: "MSP", sort: false },
        { key: "crit", label: "Crit / High / Med / Low", render: (r: any) => <SevCounts c={r.crit} h={r.high} m={r.med} l={r.low} /> },
        { key: "last_scan", label: "Last scan", render: (r: any) => fmtDt(r.last_scan) },
        { key: "edr_last_seen", label: "EDR last seen", hidden: true, render: (r: any) => fmtDt(r.edr_last_seen) },
        { key: "node_name", label: "Inventory node", sort: false, hidden: true },
        { key: "vendor", label: "Vendor", sort: false, hidden: true, render: (r: any) => r.extra?.Vendor || "" },
        { key: "circle", label: "Circle / region", sort: false, hidden: true, render: (r: any) => r.extra?.["Circle / Region"] || r.extra?.Circle || "" },
        { key: "last_seen_at", label: "Last in NIAM", hidden: true, render: (r: any) => fmtDt(r.last_seen_at) },
      ]}
      filters={<>
        <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="NE ID, IP, CIDR, name… (paste many)" />
        <Select value={state.edr_status} onChange={(v) => set({ edr_status: v })} placeholder="Any EDR status" options={EDR_OPTS} />
        <Select value={state.present ?? ""} onChange={(v) => set({ present: v || undefined })} placeholder="In latest dump" options={[["0", "Dropped from NIAM"], ["all", "Latest + dropped"]]} />
        <ShowOnly state={state} set={set} flags={[["no_edr", "1", "No active EDR"], ["in_inventory", "0", "Not in any inventory"], ["crit_high", "1", "Crit / high vulns"], ["vulnerable", "1", "Any open vulns"]]} />
      </>} />
  );
}
