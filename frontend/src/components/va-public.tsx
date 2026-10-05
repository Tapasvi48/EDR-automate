"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Upload } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, FilterSelect, Kpi, KpiGrid, Loading, SearchInput } from "./ui";
import { DataTable, type Column } from "./data-table";
import { MappedUpload } from "./mapped-upload";

const STATUS: [string, string, string][] = [["differs", "Differs", "crit"], ["match", "Matches", "good"], ["not_known", "Not in inventory or matrix", "warn"]];

/** VA public inventory: every row of the uploaded sheet, checked against the LOB inventory and the communication matrix. */
export function VaPublicPanel({ state, set, replaceAll }: { state: Record<string, string>; set: any; replaceAll: any }) {
  const [upload, setUpload] = React.useState(false);
  const { data, error, refetch } = useQuery({ queryKey: ["vapub-counts"], queryFn: () => api<any>("/api/vapub/rows", { params: { size: "1" } }) });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const c = data.counts;
  const keep = { section: "vapub" };
  const ip = (v: string) => v ? <span className="flex flex-col">{v.split(", ").map((x) =>
    <Link key={x} className="font-mono text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(x)}`}>{x}</Link>)}</span> : <span className="text-muted">–</span>;
  const cols: Column[] = [
    { key: "public_ip", label: "Public IP", render: (r) => ip(r.public_ips || r.public_ip) },
    { key: "private_ip", label: "Private IP", render: (r) => ip(r.private_ips || r.private_ip) },
    { key: "status", label: "Check", render: (r) => { const s = STATUS.find(([id]) => id === r.status); return <Badge tone={(s?.[2] || "neutral") as any}>{s?.[1] || r.status}</Badge>; } },
    { key: "diff_text", label: "Differences", wrap: true, render: (r) => r.diffs?.length ? (
      <ul className="space-y-0.5 text-[12px]">{r.diffs.map((d: any, i: number) => (
        <li key={i}><b>{d.field}</b>: VA <span className="font-mono">{d.va || "–"}</span> · {d.source} <span className="font-mono text-crit-fg">{d.other}</span></li>))}</ul>)
      : <span className="text-muted">–</span> },
    { key: "inv_node_name", label: "In LOB inventory", render: (r) => r.in_inventory
      ? <span className="text-[12px]"><b>{r.inv_node_name || r.inventory_ip}</b><span className="block text-muted">{[r.inv_lob, r.inv_msp].filter(Boolean).join(" · ")}</span></span>
      : <Badge tone="warn">No</Badge> },
    { key: "in_matrix", label: "In matrix", render: (r) => r.in_matrix ? <Badge tone="good">Yes</Badge> : <Badge tone="neutral">No</Badge> },
    { key: "lob", label: "LOB" }, { key: "msp", label: "MS Partner" }, { key: "node_type", label: "Node Type" }, { key: "domain", label: "Domain", hidden: true },
    { key: "application", label: "Application", wrap: true }, { key: "os", label: "OS (inventory)", hidden: true },
    { key: "subnet", label: "Subnet", hidden: true }, { key: "p2p", label: "P2P or Public" }, { key: "path", label: "Firewall or ISP" },
    { key: "gateway", label: "Firewall/Gateway IP", hidden: true }, { key: "dmz", label: "DMZ" },
    { key: "owner", label: "Bharti owner", wrap: true, hidden: true }, { key: "spoc", label: "MS Partner SPOC", wrap: true, hidden: true },
    { key: "niam", label: "NIAM" },
  ];
  return (
    <div>
      <Card className="mb-4 flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
        {data.upload ? <span>Current sheet <b>{data.upload.filename}</b> · {fmtN(data.upload.rows)} rows · {fmtDt(data.upload.uploaded_at)}{data.upload.uploaded_by ? ` · ${data.upload.uploaded_by}` : ""}</span>
          : <span className="text-muted">No VA public inventory uploaded yet.</span>}
        <span className="ml-auto flex gap-2">
          <Button onClick={() => downloadExcel("/api/file-templates/va_public")}><Download /> Template</Button>
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload sheet</Button>
        </span>
      </Card>
      <KpiGrid className="mb-3 grid-cols-[repeat(auto-fill,minmax(165px,1fr))]">
        <Kpi label="Rows" value={c.all} active={!state.status && !state.diff && !state.has_private && !state.in_inventory} onClick={() => replaceAll(keep)} />
        {STATUS.map(([id, label, tone]) => <Kpi key={id} label={label} value={c[id]} tone={tone} active={state.status === id} onClick={() => replaceAll({ ...keep, status: id })} />)}
        <Kpi label="No private IP on the sheet" value={c.no_private} tone="warn" active={state.has_private === "0"} onClick={() => replaceAll({ ...keep, has_private: "0" })} />
        <Kpi label="Not in any LOB inventory" value={c.not_in_inventory} tone="serious" active={state.in_inventory === "0"} onClick={() => replaceAll({ ...keep, in_inventory: "0" })} />
      </KpiGrid>
      {Object.keys(c.fields || {}).length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-1.5 text-[12.5px]">
          <span className="mr-1 text-muted">Differs in</span>
          {Object.entries(c.fields).map(([f, n]) => (
            <button key={f} onClick={() => replaceAll({ ...keep, diff: state.diff === f ? "" : f })}
              className={cn("rounded-full border px-2.5 py-0.5 transition-colors", state.diff === f ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-border-strong")}>
              {f} <b className="tabular">{fmtN(n as number)}</b>
            </button>
          ))}
        </div>
      )}
      <DataTable endpoint="/api/vapub/rows" exportPath="/api/vapub/rows/export" state={state} setState={set} omit={["section"]} noun="rows" storageKey="vapub"
        rowKey={(r: any) => String(r.id)} onReset={() => replaceAll(keep)} sortable={false} columns={cols}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, LOB, MSP, application, owner…" />
          <FilterSelect label="Check" value={state.status} onChange={(v) => set({ status: v })} any="All" options={STATUS.map(([id, l]) => [id, l]) as [string, string][]} />
          <FilterSelect label="Differs in" value={state.diff} onChange={(v) => set({ diff: v })} any="Any" options={Object.keys(c.fields || {}).map((f) => [f, f]) as [string, string][]} />
          <FilterSelect single label="Private IP" value={state.has_private} onChange={(v) => set({ has_private: v })} any="Any" options={[["1", "On the sheet"], ["0", "Missing"]]} />
          <FilterSelect single label="LOB inventory" value={state.in_inventory} onChange={(v) => set({ in_inventory: v })} any="Any" options={[["1", "Listed"], ["0", "Not listed"]]} />
          <FilterSelect single label="Matrix" value={state.in_matrix} onChange={(v) => set({ in_matrix: v })} any="Any" options={[["1", "In the matrix"], ["0", "Not in the matrix"]]} />
        </>} />
      {upload && <MappedUpload kind="vapub" open onOpenChange={setUpload} />}
    </div>
  );
}
