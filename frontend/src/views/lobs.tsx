"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus, Upload } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtN, fmtRel, pct } from "@/lib/format";
import { StackBar, type Seg } from "@/components/charts";
import { Badge, Button, Card, Field, Input, Kpi, KpiGrid, Loading, Modal, PageHeader, Select } from "@/components/ui";
import { UploadWizard } from "@/components/upload-wizard";

export function LobForm({ open, onOpenChange, lob }: { open: boolean; onOpenChange: (v: boolean) => void; lob?: any }) {
  const qc = useQueryClient();
  const router = useRouter();
  const { data: meta } = useMeta();
  const [f, setF] = React.useState({ name: "", description: "", owner: "", default_template_id: "" });
  React.useEffect(() => {
    const standard = meta?.templates.find((t) => t.name === "Standard");
    if (open) setF({ name: lob?.name || "", description: lob?.description || "", owner: lob?.owner || "",
      default_template_id: lob ? (lob.default_template_id ? String(lob.default_template_id) : "") : standard ? String(standard.id) : "" });
  }, [open, lob, meta]);
  const save = async () => {
    try {
      const body = { ...f, default_template_id: f.default_template_id ? +f.default_template_id : null };
      if (lob) await api(`/api/lobs/${lob.id}`, { method: "PUT", body });
      else {
        const r = await api<any>("/api/lobs", { method: "POST", body });
        router.push(`/lob/?id=${r.id}`);
      }
      toast.success(lob ? "LOB updated" : "LOB created");
      qc.invalidateQueries();
      onOpenChange(false);
    } catch (e: any) {
      toast.error(e.message);
    }
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title={lob ? "Edit LOB" : "New line of business"}
      footer={<><Button onClick={() => onOpenChange(false)}>Cancel</Button><Button variant="primary" onClick={save} disabled={!f.name.trim()}>{lob ? "Save" : "Create LOB"}</Button></>}>
      <div className="grid gap-3">
        <Field label="Name"><Input autoFocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Retail Banking" /></Field>
        <Field label="Description"><Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <Field label="Owner / contact"><Input value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} placeholder="team@company.com" /></Field>
        <Field label="Default inventory template" hint="Uploads for this LOB auto-map columns with this template.">
          <Select className="max-w-none" value={f.default_template_id} onChange={(v) => setF({ ...f, default_template_id: v })} placeholder="Auto-detect columns" options={(meta?.templates || []).map((t) => ({ value: t.id, label: t.name }))} />
        </Field>
      </div>
    </Modal>
  );
}

export default function Lobs() {
  const router = useRouter();
  const { data, error: dataErr, refetch: dataRetry } = useQuery({ queryKey: ["lobs"], queryFn: () => api<any>("/api/lobs") });
  const { data: meta } = useMeta();
  const { data: vs } = useQuery({ queryKey: ["vuln-summary", ""], queryFn: () => api<any>("/api/vulns/summary") });
  const vByLob: Record<number, any> = Object.fromEntries((vs?.by_lob || []).map((r: any) => [r.id, r]));
  const [creating, setCreating] = React.useState(false);
  const [uploadFor, setUploadFor] = React.useState<any>(null);
  if (!data) return <Loading error={dataErr} retry={() => dataRetry()} />;
  const rows = data.rows;
  const t = rows.reduce((a: any, l: any) => {
    ["nodes", "applicable", "installed", "offline", "pending", "unlisted", "not_feasible", "non_live", "in_niam", "live_nodes", "scanned_live"].forEach((k) => (a[k] = (a[k] || 0) + (l[k] || 0)));
    return a;
  }, {} as Record<string, number>);
  const vulnTot = (vs?.by_lob || []).reduce((a: number, r: any) => a + (r.crit || 0) + (r.high || 0), 0);
  return (
    <div>
      <PageHeader
        title="LOB inventory"
        sub="Each line of business (and its MSPs) uploads an asset inventory. Every upload is an immutable version; the current version is matched to Falcon to measure real EDR coverage."
        actions={<>
          <Link href="/coverage/"><Button>Coverage gaps</Button></Link>
          <Button variant="primary" onClick={() => setCreating(true)}><Plus /> New LOB</Button>
        </>}
      />
      {rows.length > 0 && (
        <KpiGrid className="mb-5 grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
          <Kpi label="LOBs" value={rows.length} foot={`${fmtN(meta?.msps.length || 0)} MSPs`} />
          <Kpi label="Inventory nodes" value={t.nodes} tone="info" href="/inventory/" />
          <Kpi label="EDR coverage" value={t.applicable ? `${pct(t.installed, t.applicable)}%` : "–"} tone="good" foot={`${fmtN(t.installed)} of ${fmtN(t.applicable)} EDR applicable`} href="/inventory/?gap=edr" />
          <Kpi label="NIAM coverage" value={t.nodes ? `${pct(t.in_niam, t.nodes)}%` : "–"} tone="info" foot={`${fmtN(t.in_niam)} of ${fmtN(t.nodes)} nodes in NIAM`} href="/inventory/?gap=niam" />
          <Kpi label="Scan coverage" value={t.live_nodes ? `${pct(t.scanned_live, t.live_nodes)}%` : "–"} tone="violet" foot={`${fmtN(t.scanned_live)} of ${fmtN(t.live_nodes)} live nodes scanned`} href="/inventory/?gap=scan" />
          <Kpi label="Open crit + high" value={vulnTot} tone="crit" foot="vulnerabilities" href="/vulnerabilities/" />
        </KpiGrid>
      )}
      {!rows.length && (
        <Card className="p-10 text-center">
          <Building2 className="mx-auto mb-3 size-10 text-muted" />
          <div className="text-[15px] font-semibold">No LOBs yet</div>
          <div className="mb-4 text-muted">Create a line of business, add its MSPs, then upload the inventory spreadsheet.</div>
          <Button variant="primary" onClick={() => setCreating(true)}><Plus /> New LOB</Button>
        </Card>
      )}
      <div className="grid gap-4 grid-cols-[repeat(auto-fill,minmax(340px,1fr))]">
        {rows.map((l: any) => {
          const msps = (meta?.msps || []).filter((m) => m.lob_id === l.id);
          return (
            <Card key={l.id} className="cursor-pointer p-4 transition-all hover:-translate-y-px hover:border-accent" onClick={() => router.push(`/lob/?id=${l.id}`)}>
              <div className="flex items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[16px] font-semibold">{l.name}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {msps.length ? msps.map((m) => <Badge key={m.id} tone="outline">{m.name}</Badge>) : <span className="text-xs text-muted">No MSPs yet</span>}
                  </div>
                </div>
                {l.current_version ? <Badge tone="info">v{l.current_version}</Badge> : <Badge>No inventory</Badge>}
              </div>
              <div className="mt-4 space-y-3">
                <Metric label="EDR coverage" pctv={l.coverage} sub={`${fmtN(l.installed)} of ${fmtN(l.applicable)} EDR applicable`}
                  parts={[{ label: "Online", n: l.online, color: "var(--good)" }, { label: "Offline", n: l.offline, color: "var(--warn)" }, { label: "Not installed", n: l.pending, color: "var(--crit)" }]} />
                <Metric label="NIAM coverage" pctv={l.niam_coverage} sub={`${fmtN(l.in_niam)} of ${fmtN(l.nodes)} nodes in NIAM`}
                  parts={[{ label: "In NIAM", n: l.in_niam, color: "var(--good)" }, { label: "Not in NIAM", n: l.not_in_niam, color: "var(--crit)" }]} />
                <Metric label="Scan coverage" pctv={l.scan_coverage} sub={`${fmtN(l.scanned_live)} of ${fmtN(l.live_nodes)} live nodes scanned`}
                  parts={[{ label: "Scanned", n: l.scanned_live, color: "var(--s1)" }, { label: "Never scanned", n: l.never_scanned, color: "var(--border-strong)" }]} />
              </div>
              <div className="mt-4 grid grid-cols-4 gap-2 text-center">
                <Cell label="Nodes" value={fmtN(l.nodes)} />
                <Cell label="Critical" value={fmtN(vByLob[l.id]?.crit || 0)} tone={vByLob[l.id]?.crit ? "crit" : undefined} />
                <Cell label="High" value={fmtN(vByLob[l.id]?.high || 0)} tone={vByLob[l.id]?.high ? "serious" : undefined} />
                <Cell label="Not in inventory" value={fmtN(l.unlisted)} tone={l.unlisted ? "violet" : undefined} />
              </div>
              <div className="mt-4 flex items-center gap-2 border-t border-border pt-3 text-xs text-muted">
                {l.uploaded_at ? `Updated ${fmtRel(l.uploaded_at)}` : "Never uploaded"}
                <Button size="sm" className="ml-auto" onClick={(e) => { e.stopPropagation(); setUploadFor(l); }}><Upload /> Upload</Button>
              </div>
            </Card>
          );
        })}
      </div>
      <LobForm open={creating} onOpenChange={setCreating} />
      {uploadFor && <UploadWizard lob={uploadFor} open onOpenChange={(o) => !o && setUploadFor(null)} />}
    </div>
  );
}

function Cell({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  const c = { crit: "text-crit-fg", serious: "text-serious-fg", warn: "text-warn-fg", good: "text-good-fg", violet: "text-violet-fg" }[tone || ""] || "";
  return (
    <div className="rounded-lg bg-surface-2 px-2 py-1.5">
      <div className={"text-[15px] font-semibold tabular " + c}>{value}</div>
      <div className="text-[10.5px] text-muted">{label}</div>
    </div>
  );
}

function Metric({ label, pctv, sub, parts }: { label: string; pctv: number | null; sub: string; parts: Seg[] }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-[12.5px]">
        <span className="font-medium text-fg-2">{label}</span>
        <span><b className="text-[15px] tabular">{pctv === null || pctv === undefined ? "–" : `${pctv}%`}</b></span>
      </div>
      <StackBar className="mt-1" height={7} parts={parts} />
      <div className="mt-0.5 text-[11px] text-muted">{sub}</div>
    </div>
  );
}
