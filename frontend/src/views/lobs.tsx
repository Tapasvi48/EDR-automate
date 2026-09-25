"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus, Upload } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, Card, Field, Input, Kpi, KpiGrid, Loading, Meter, Modal, PageHeader, Select } from "@/components/ui";
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
  const { data } = useQuery({ queryKey: ["lobs"], queryFn: () => api<any>("/api/lobs") });
  const { data: meta } = useMeta();
  const [creating, setCreating] = React.useState(false);
  const [uploadFor, setUploadFor] = React.useState<any>(null);
  if (!data) return <Loading />;
  const rows = data.rows;
  const t = rows.reduce((a: any, l: any) => {
    ["nodes", "applicable", "installed", "offline", "pending", "unlisted", "not_feasible", "non_live"].forEach((k) => (a[k] = (a[k] || 0) + (l[k] || 0)));
    return a;
  }, {} as Record<string, number>);
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
        <KpiGrid className="mb-5 grid-cols-[repeat(auto-fill,minmax(150px,1fr))]">
          <Kpi label="LOBs" value={rows.length} foot={`${fmtN(meta?.msps.length || 0)} MSPs`} />
          <Kpi label="Inventory nodes" value={t.nodes} tone="info" href="/coverage/" />
          <Kpi label="Applicable" value={t.applicable} foot={`${fmtN(t.not_feasible)} not feasible · ${fmtN(t.non_live)} non live`} href="/coverage/?applicable=1" />
          <Kpi label="Installed" value={t.installed} tone="good" foot={t.applicable ? `${Math.round((1000 * t.installed) / t.applicable) / 10}% coverage` : undefined} href="/coverage/?installed=1" />
          <Kpi label="Pending" value={t.pending} tone="crit" foot="not installed / removed / hidden" href="/coverage/?pending=1" />
          <Kpi label="Offline" value={t.offline} tone="warn" href="/coverage/?coverage_status=Offline" />
          <Kpi label="Not in inventory" value={t.unlisted} tone="violet" foot="agents on EDR, missing from inventory" href="/assets/?unlisted=1" />
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
              <div className="mt-4 flex items-end gap-3">
                <div className="text-[30px] font-bold leading-none tracking-tight">{l.coverage === null ? "–" : `${l.coverage}%`}</div>
                <div className="pb-0.5 text-xs text-muted">EDR coverage · {fmtN(l.installed)} of {fmtN(l.applicable)} applicable</div>
              </div>
              <div className="mt-2"><Meter value={l.coverage || 0} /></div>
              <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                <Cell label="Nodes" value={fmtN(l.nodes)} />
                <Cell label="Applicable" value={fmtN(l.applicable)} />
                <Cell label="Installed" value={fmtN(l.installed)} tone="good" />
                <Cell label="Offline" value={fmtN(l.offline)} tone={l.offline ? "warn" : undefined} />
                <Cell label="Pending" value={fmtN(l.pending)} tone={l.pending ? "crit" : undefined} />
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
