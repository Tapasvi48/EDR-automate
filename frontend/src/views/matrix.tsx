"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Globe2, Lock, RotateCcw, Trash2, Upload } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, FilterSelect, Kpi, KpiGrid, Loading, Menu, PageHeader, SearchInput, Tabs, useConfirm } from "@/components/ui";
import { DataTable, SimpleTable } from "@/components/data-table";
import { MatrixUpload } from "@/components/matrix-upload";
import { MatrixIpsPanel } from "./matrix-ips";

// MX-00xx pattern sheets: the code as the short name; exposing patterns red, the others neutral
const MX_EXPOSING = new Set(["mx01", "mx02", "mx03", "mx04", "mx07", "mx08", "mx09", "mx10", "mx11"]);
const MX = Object.fromEntries(Array.from({ length: 14 }, (_, i) => `mx${String(i + 1).padStart(2, "0")}`).map((k) => [k, `MX-00${k.slice(2)}`]));
const TYPE_TONE: Record<string, any> = { rules: "info", public_pool: "violet", nat_map: "warn", sod_nat: "serious", exposure: "crit",
  zones: "info", pubpriv: "warn", pubonly: "violet", register: "crit", snat: "serious", sod: "serious", fwpolicy: "info",
  ...Object.fromEntries(Object.keys(MX).map((k) => [k, MX_EXPOSING.has(k) ? "crit" : "outline"])) };
const SHORT: Record<string, string> = { rules: "Rule", public_pool: "Pool", nat_map: "NAT", sod_nat: "SOD NAT", exposure: "Register",
  zones: "Rule", pubpriv: "Public+private", pubonly: "Public IP", register: "Register", snat: "Source NAT", sod: "SOD NAT", fwpolicy: "Policy", ...MX };

/** Addresses of one cell, one chip each (the cell's delimiters already split and expanded by the server). */
function Chips({ items, link, max = 6, tone }: { items?: string[]; link?: boolean; max?: number; tone?: string }) {
  const [all, setAll] = React.useState(false);
  if (!items?.length) return <span className="text-muted">–</span>;
  const shown = all ? items : items.slice(0, max);
  return (
    <span className="flex max-w-[300px] flex-wrap gap-1">
      {shown.map((a) => {
        const cls = cn("rounded-md border px-1.5 py-px font-mono text-[11px]", a === "Any" ? "border-crit/40 bg-crit-soft text-crit-fg" : tone || "border-border bg-surface-2 text-fg-2");
        return link && a !== "Any" && !a.startsWith("+") ? <Link key={a} href={`/ip-search/?q=${encodeURIComponent(a)}`} className={cn(cls, "hover:border-accent hover:text-accent-fg")}>{a}</Link>
          : <span key={a} className={cls}>{a}</span>;
      })}
      {items.length > max && <button className="text-[11px] text-accent-fg hover:underline" onClick={() => setAll(!all)}>{all ? "less" : `+${items.length - max}`}</button>}
    </span>
  );
}

function Zone({ z }: { z?: string }) {
  return z ? <span className="mb-0.5 block text-[10.5px] font-semibold uppercase tracking-wide text-muted">{z}</span> : null;
}

export default function Matrix() {
  const [state, set, replaceAll] = useUrlState();
  const [upload, setUpload] = React.useState(false);
  const tab = state.tab || "rows";
  const { data: s, error, refetch } = useQuery({ queryKey: ["comm-summary"], queryFn: () => api<any>("/api/comm/summary") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  return (
    <div>
      <PageHeader title="Communication matrix"
        sub="Firewall rules, public IP pools, NAT lists and exposure registers in one view. Every cell is split into its addresses; internet-facing rows expose the assets they point at."
        actions={<>
          <Button onClick={() => downloadExcel("/api/comm/template")}><Download /> Template</Button>
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload workbook</Button>
        </>} />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Rows" value={s.rules} tone="info" foot={s.last_upload ? `last upload ${fmtRel(s.last_upload.uploaded_at)}` : "nothing uploaded"} active={tab === "rows" && !state.inbound} onClick={() => replaceAll({})} />
        <Kpi label="Internet-facing rows" value={s.inbound} tone="crit" active={state.inbound === "1"} onClick={() => replaceAll({ inbound: "1" })} />
        <Kpi label="Marked by hand" value={s.manual} tone="warn" foot="internet-facing set manually" active={state.manual === "1"} onClick={() => replaceAll({ manual: "1" })} />
        <Kpi label="Assets exposed" value={s.exposed_assets} tone="serious" foot="through the matrix" href="/exposure/?exposure_src=matrix" />
        <Kpi label="Sheets loaded" value={s.workbooks?.length || 0} foot={`${new Set((s.workbooks || []).map((w: any) => w[0])).size} workbook(s)`} active={tab === "sheets"} onClick={() => replaceAll({ tab: "sheets" })} />
      </KpiGrid>
      <div className="mt-4">
        <Tabs value={tab} onChange={(v) => replaceAll(v === "rows" ? {} : { tab: v })} tabs={[
          { id: "rows", label: "Rows", count: s.rules }, { id: "ips", label: "Assets (private + public IP)" }, { id: "sheets", label: "Sheets", count: s.workbooks?.length || 0 }]} />
        {tab === "rows" && <RowsTab s={s} state={state} set={set} replaceAll={replaceAll} />}
        {tab === "ips" && <MatrixIpsPanel state={state} set={set} replaceAll={replaceAll} keep={{ tab: "ips" }} />}
        {tab === "sheets" && <SheetsTab replaceAll={replaceAll} />}
      </div>
      {upload && <MatrixUpload open onOpenChange={setUpload} />}
    </div>
  );
}

function InternetCell({ r }: { r: any }) {
  const qc = useQueryClient();
  const mark = async (v: number | null) => {
    try {
      await api(`/api/comm/rules/${r.id}`, { method: "PATCH", body: { inbound: v } });
      toast.success(v === null ? "Back to automatic" : v ? "Marked internet-facing" : "Marked not internet-facing");
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); }
  };
  return (
    <Menu width={250} trigger={
      <button className="flex items-center gap-1" title="Change">
        {r.inbound_internet ? <Badge tone="crit">Internet</Badge> : <Badge tone="neutral">Internal</Badge>}
        {r.manual && <span className="text-[10px] text-warn-fg" title="set by hand">✎</span>}
      </button>} items={[
      { label: "Internet-facing", icon: <Globe2 />, hint: "the destination / public IP is reachable from the internet", onSelect: () => mark(1) },
      { label: "Not internet-facing", icon: <Lock />, hint: "internal flow only", onSelect: () => mark(0) },
      ...(r.manual ? ["sep" as const, { label: "Back to automatic", icon: <RotateCcw />, hint: `automatic value: ${r.inbound_auto ? "internet-facing" : "internal"}`, onSelect: () => mark(null) }] : []),
    ]} />
  );
}

function RowsTab({ s, state, set, replaceAll }: { s: any; state: Record<string, string>; set: any; replaceAll: any }) {
  const sheets = (s.workbooks || []).map((w: any) => [w[1], w[1] ? `${w[1]}${w[0] ? ` · ${w[0]}` : ""}` : "(no sheet)"]).filter((x: any) => x[0]);
  return (
    <DataTable endpoint="/api/comm/rules" exportPath="/api/comm/rules/export" state={state} setState={set} noun="rows" storageKey="comm-v2"
      rowKey={(r: any) => String(r.id)} onReset={() => replaceAll({})} sortable={false}
      filters={<>
        <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, subnet, name, port, application, owner…" />
        <FilterSelect single label="Internet" value={state.inbound} onChange={(v) => set({ inbound: v })} any="Any" options={[["1", "Internet-facing"], ["0", "Internal"]]} />
        <FilterSelect label="Type" value={state.sheet_type} onChange={(v) => set({ sheet_type: v })} any="All" options={Object.entries(s.sheet_types || {}) as [string, string][]} />
        {sheets.length > 1 && <FilterSelect label="Sheet" value={state.sheet} onChange={(v) => set({ sheet: v })} any="All" options={sheets} />}
        {s.firewalls?.length > 0 && <FilterSelect label="Firewall" value={state.firewall} onChange={(v) => set({ firewall: v })} any="All" options={s.firewalls} />}
      </>}
      columns={[
        { key: "inbound", label: "Internet", render: (r: any) => <InternetCell r={r} /> },
        { key: "rule_id", label: "Row", render: (r: any) => (
          <span className="flex flex-col gap-0.5">
            <span className="flex items-center gap-1.5"><Badge tone={TYPE_TONE[r.sheet_type || "rules"]}>{SHORT[r.sheet_type || "rules"]}</Badge><b className="text-[12px]">{r.rule_id}</b>{!r.active && <Badge>expired</Badge>}</span>
            {r.name && <span className="text-[11.5px] text-muted">{r.name}</span>}
          </span>) },
        { key: "src", label: "Source", wrap: true, render: (r: any) => <span><Zone z={r.src_zone} /><Chips items={r.src_list} link />{r.src_nat_list?.length ? <span className="mt-1 flex items-center gap-1 text-[10.5px] text-muted">NAT <Chips items={r.src_nat_list} /></span> : null}</span> },
        { key: "dst_nat", label: "Public / NAT IP", wrap: true, render: (r: any) => <Chips items={r.dst_nat_list} link tone="border-violet/40 bg-violet-soft text-violet-fg" /> },
        { key: "dst", label: "Destination", wrap: true, render: (r: any) => <span><Zone z={r.dst_zone} /><Chips items={r.dst_list} link /></span> },
        { key: "ports", label: "Ports", wrap: true, render: (r: any) => <Chips items={r.port_list} max={4} /> },
        { key: "application", label: "Application / owner", wrap: true, render: (r: any) => <span className="text-[12px]">{r.application || r.service || <span className="text-muted">–</span>}{r.app_owner ? <span className="block text-muted">{r.app_owner}</span> : null}</span> },
        { key: "firewall", label: "Firewall", render: (r: any) => <span className="text-[12px]">{r.firewall || "–"}{r.fw_rule ? <span className="block text-muted">{r.fw_rule}</span> : null}</span> },
        { key: "sheet", label: "Sheet", render: (r: any) => r.sheet ? <span className="text-[11.5px] text-muted" title={r.workbook}>{r.sheet}</span> : "–" },
        { key: "cr", label: "CR / SOD", hidden: true }, { key: "valid_till", label: "Valid till", hidden: true },
        { key: "lob", label: "LOB", hidden: true }, { key: "location", label: "Location", hidden: true }, { key: "remarks", label: "Remarks", hidden: true, wrap: true },
      ]} />
  );
}

function SheetsTab({ replaceAll }: { replaceAll: any }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { data, error, refetch } = useQuery({ queryKey: ["comm-sheets"], queryFn: () => api<any>("/api/comm/sheets") });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const del = async (workbook: string, sheet?: string) => {
    const what = sheet ? `sheet “${sheet}” of ${workbook || "the matrix"}` : `the whole workbook “${workbook || "(no name)"}”`;
    if (!(await confirm({ title: "Delete from the communication matrix?", danger: true, ok: "Delete",
      body: <>This deletes every row of {what}. Exposure is recomputed; assets exposed only by these rows stop being exposed. Manual marks on the rows are kept and apply again if you re-upload.</> }))) return;
    try {
      const r = await api<any>("/api/comm/sheet", { method: "DELETE", params: { workbook, sheet: sheet || "" } });
      toast.success(r.message);
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); }
  };
  const books = Array.from(new Set(data.rows.map((r: any) => r.workbook))) as string[];
  return (
    <div className="space-y-4">
      {!books.length && <Card className="p-8 text-center text-muted">Nothing uploaded yet.</Card>}
      {books.map((b) => {
        const rows = data.rows.filter((r: any) => r.workbook === b);
        return (
          <Card key={b || "none"}>
            <CardHeader title={<span className="flex items-center gap-2">{b || "(uploaded before workbooks were tracked)"}<span className="text-[12px] font-normal text-muted">{rows.length} sheet(s) · {fmtN(rows.reduce((a: number, r: any) => a + r.rows, 0))} rows</span></span>}
              right={<Button size="sm" variant="danger" onClick={() => del(b)}><Trash2 /> Delete workbook</Button>} />
            <SimpleTable rows={rows} columns={[
              { key: "sheet", label: "Sheet", render: (r: any) => <b>{r.sheet || "–"}</b> },
              { key: "type_label", label: "Type", render: (r: any) => <Badge tone={TYPE_TONE[r.sheet_type]}>{r.type_label}</Badge> },
              { key: "rows", label: "Rows", num: true, render: (r: any) => fmtN(r.rows) },
              { key: "inbound", label: "Internet-facing", num: true, render: (r: any) => r.inbound ? <b className="text-crit-fg">{fmtN(r.inbound)}</b> : "0" },
              { key: "manual", label: "Marked by hand", num: true, render: (r: any) => r.manual || <span className="text-muted">0</span> },
              { key: "uploaded_at", label: "Uploaded", render: (r: any) => r.uploaded_at ? <span title={fmtDt(r.uploaded_at)}>{fmtRel(r.uploaded_at)}{r.uploaded_by ? ` · ${r.uploaded_by}` : ""}</span> : "–" },
              { key: "act", label: "", render: (r: any) => (
                <span className="flex justify-end gap-1.5">
                  <Button size="sm" variant="ghost" onClick={() => replaceAll({ sheet: r.sheet })}>View rows</Button>
                  <Button size="sm" variant="danger" onClick={() => del(r.workbook, r.sheet)}><Trash2 /> Delete</Button>
                </span>) },
            ]} />
          </Card>
        );
      })}
    </div>
  );
}
