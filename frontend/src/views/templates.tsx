"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { ArrowDown, ArrowUp, BadgeCheck, Building2, Download, FileClock, FileSpreadsheet, FileUp, Pencil, Plus, Radio, RotateCcw, ShieldAlert, Tags, Trash2, Upload, Waypoints } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { api, downloadExcel } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtDt } from "@/lib/format";
import { Badge, Button, Callout, Card, Field, Input, Loading, Modal, PageHeader, Select, useConfirm } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";

function Editor({ t, open, onOpenChange }: { t: any; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const { data: meta } = useMeta();
  const [f, setF] = React.useState<any>({ name: "", description: "", key_field: "ip", mapping: {} });
  const [headers, setHeaders] = React.useState<string[]>([]);
  React.useEffect(() => { if (open) { setF(t ? { ...t, mapping: { ...t.mapping } } : { name: "", description: "", key_field: "ip", mapping: {} }); setHeaders([]); } }, [open, t]);
  const loadSample = async (file?: File) => {
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    try {
      const r = await api<any>("/api/uploads", { method: "POST", body: fd });
      setHeaders(r.headers);
      setF((x: any) => ({ ...x, mapping: { ...r.mapping, ...Object.fromEntries(Object.entries(x.mapping).filter(([, v]) => v)) } }));
      toast.success(`Loaded ${r.headers.length} columns from ${r.filename}`);
    } catch (e: any) { toast.error(e.message); }
  };
  const save = async () => {
    try {
      await api(t ? `/api/templates/${t.id}` : "/api/templates", { method: t ? "PUT" : "POST", body: f });
      toast.success("Template saved");
      qc.invalidateQueries();
      onOpenChange(false);
    } catch (e: any) { toast.error(e.message); }
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={t ? "Edit template" : "New inventory template"}
      footer={<><Button onClick={() => onOpenChange(false)}>Cancel</Button><Button variant="primary" onClick={save} disabled={!f.name?.trim()}>Save template</Button></>}>
      <div className="grid gap-3 md:grid-cols-3">
        <Field label="Template name"><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="Key field" hint="Identifies the same row across versions"><Select className="max-w-none" value={f.key_field} onChange={(v) => setF({ ...f, key_field: v })} options={Object.entries(meta?.key_fields || {})} /></Field>
        <Field label="Description"><Input value={f.description || ""} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
      </div>
      <div className="mt-4 flex items-center gap-3 rounded-lg bg-surface-2 p-3 text-[12.5px]">
        <FileUp className="size-4 text-muted" />
        <span className="text-fg-2">Type the column header for each field, or load headers from a sample file to pick from a list.</span>
        <label className="ml-auto cursor-pointer"><span className="inline-flex h-7 items-center rounded-lg border border-border-strong bg-surface px-2.5 text-xs font-medium">Load sample file</span>
          <input type="file" className="hidden" accept=".xlsx,.xlsm,.csv" onChange={(e) => loadSample(e.target.files?.[0])} /></label>
      </div>
      <table className="mt-3 w-full text-[13px]">
        <thead><tr className="text-left text-xs text-fg-2"><th className="py-2">Standard field</th><th className="py-2">Column header in the LOB file</th></tr></thead>
        <tbody>
          {(meta?.inventory_fields || []).map(([k, l]) => (
            <tr key={k} className="border-t border-border">
              <td className="w-56 py-2 font-medium">{l}</td>
              <td className="py-1.5">
                {headers.length ? (
                  <Select className="w-full max-w-none" value={f.mapping[k] || ""} onChange={(v) => setF({ ...f, mapping: { ...f.mapping, [k]: v } })} placeholder="— not mapped —" options={headers} />
                ) : (
                  <Input className="w-full" value={f.mapping[k] || ""} placeholder="(not mapped)" onChange={(e) => setF({ ...f, mapping: { ...f.mapping, [k]: e.target.value } })} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Modal>
  );
}

const GROUPS: [string, string[]][] = [
  ["Inventory & assets", ["inventory", "niam", "old_edr", "agent_tags", "comm_matrix", "va_public"]],
  ["Vulnerability", ["vulnerability", "sod"]],
];
const ICONS: Record<string, React.ElementType> = { inventory: Building2, niam: Radio, old_edr: FileClock, agent_tags: Tags, comm_matrix: Waypoints,
  vulnerability: ShieldAlert, sod: BadgeCheck, va_public: ShieldAlert };
const UPLOAD_AT: Record<string, string> = { inventory: "/lobs/", niam: "/upload/", old_edr: "/health/", agent_tags: "/upload/",
  comm_matrix: "/matrix/", va_public: "/vulnerabilities/?section=vapub", vulnerability: "/upload/", sod: "/exceptions/" };

function FileTemplates() {
  const { data } = useQuery({ queryKey: ["file-templates"], queryFn: () => api<any>("/api/file-templates") });
  const [editing, setEditing] = React.useState<string | null>(null);
  const byKind = Object.fromEntries((data?.rows || []).map((t: any) => [t.kind, t]));
  return (
    <div className="space-y-6">
      {GROUPS.map(([g, kinds]) => (
        <div key={g}>
          <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">{g}</div>
          <Card className="divide-y divide-border">
            {kinds.filter((k) => byKind[k]).map((k) => {
              const t = byKind[k];
              const Icon = ICONS[k] || FileSpreadsheet;
              return (
                <div key={k} className="flex flex-wrap items-center gap-4 px-4 py-3.5">
                  <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent-fg"><Icon className="size-5" /></div>
                  <div className="min-w-[260px] flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[14px] font-semibold">{t.title}</span>
                      {t.edited && <Badge tone="violet">edited</Badge>}
                      <span className="text-[11.5px] text-muted">{t.columns.length} columns · {t.required.length} required</span>
                    </div>
                    <div className="mt-0.5 text-[12px] text-muted">{t.description}</div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {t.columns.map((c: string) => (
                        <span key={c} className={cn("rounded-md border px-1.5 py-0.5 text-[11px]", t.required.includes(c) ? "border-accent/50 bg-accent-soft text-accent-fg" : "border-border text-fg-2")}>{c}</span>
                      ))}
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    <Button size="sm" onClick={() => setEditing(k)}><Pencil /> Edit</Button>
                    <Button size="sm" onClick={() => downloadExcel(`/api/file-templates/${k}`)}><Download /> Download</Button>
                    <Link href={UPLOAD_AT[k]}><Button size="sm" variant="ghost"><Upload /> Upload</Button></Link>
                  </div>
                </div>
              );
            })}
          </Card>
        </div>
      ))}
      <div className="flex items-center gap-2 text-[11.5px] text-muted">
        <span className="rounded-md border border-accent/50 bg-accent-soft px-1.5 py-0.5 text-accent-fg">Required</span>
        <span className="rounded-md border border-border px-1.5 py-0.5">Optional</span>
        Edited column names are recognised automatically when you upload a file.
      </div>
      {editing && <TemplateEditor kind={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

type Col = { field: string | null; name: string; required: boolean; meaning: string; example: string; example2?: string };

function TemplateEditor({ kind, onClose }: { kind: string; onClose: () => void }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { data } = useQuery({ queryKey: ["file-template", kind], queryFn: () => api<any>(`/api/file-templates/${kind}/config`) });
  const [cols, setCols] = React.useState<Col[] | null>(null);
  const [desc, setDesc] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => { if (data && !cols) { setCols(data.columns); setDesc(data.description); } }, [data, cols]);
  if (!data || !cols) return null;
  const fieldLabel: Record<string, string> = Object.fromEntries(data.defaults.columns.filter((c: any) => c.field).map((c: any) => [c.field, c.name]));
  const reqFields = new Set(data.defaults.columns.filter((c: any) => c.field && c.required).map((c: any) => c.field));
  const unused = data.defaults.columns.filter((c: any) => c.field && !cols.some((x) => x.field === c.field));
  const upd = (i: number, patch: Partial<Col>) => setCols(cols.map((c, j) => (j === i ? { ...c, ...patch } : c)));
  const move = (i: number, d: number) => { const n = [...cols]; const [x] = n.splice(i, 1); n.splice(i + d, 0, x); setCols(n); };
  const save = async () => {
    setBusy(true);
    try {
      await api(`/api/file-templates/${kind}/config`, { method: "PUT", body: { description: desc, columns: cols } });
      toast.success("Template saved"); qc.invalidateQueries(); onClose();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const reset = async () => {
    if (!(await confirm({ title: "Reset to the built-in template?", body: "Your column names, descriptions and extra columns for this template are removed.", ok: "Reset" }))) return;
    await api(`/api/file-templates/${kind}/config`, { method: "DELETE" });
    toast.success("Template reset"); qc.invalidateQueries(); onClose();
  };
  const cell = "h-8 w-full rounded-md border border-border-strong bg-surface px-2 text-[12.5px]";
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} wide title={`Edit template · ${data.title}`}
      footer={<>
        {data.edited && <Button variant="ghost" className="mr-auto" onClick={reset}><RotateCcw /> Reset to default</Button>}
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={busy} onClick={save}>Save template</Button>
      </>}>
      <Field label="Description"><Input value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
      <div className="mt-4 max-h-[55vh] overflow-auto rounded-xl border border-border scroll-thin">
        <table className="w-full text-[12.5px]">
          <thead className="sticky top-0 z-10 bg-surface-2 text-left text-xs text-fg-2">
            <tr><th className="w-14 px-2 py-2" /><th className="px-2">Column name in the file</th><th className="px-2">Used as</th><th className="px-2">Required</th><th className="px-2">What to put in it</th><th className="px-2">Example</th><th /></tr>
          </thead>
          <tbody>
            {cols.map((c, i) => {
              const locked = !!c.field && reqFields.has(c.field);
              return (
                <tr key={i} className="border-t border-border align-middle">
                  <td className="px-1.5">
                    <div className="flex">
                      <button disabled={i === 0} onClick={() => move(i, -1)} className="rounded p-1 hover:bg-surface-3 disabled:opacity-30"><ArrowUp className="size-3.5" /></button>
                      <button disabled={i === cols.length - 1} onClick={() => move(i, 1)} className="rounded p-1 hover:bg-surface-3 disabled:opacity-30"><ArrowDown className="size-3.5" /></button>
                    </div>
                  </td>
                  <td className="px-1.5 py-1"><input className={cell} value={c.name} onChange={(e) => upd(i, { name: e.target.value })} /></td>
                  <td className="whitespace-nowrap px-2 text-[11.5px]">{c.field ? <Badge tone="info">{fieldLabel[c.field] || c.field}</Badge> : <span className="text-muted">extra column (kept as is)</span>}</td>
                  <td className="px-2 text-center">
                    <input type="checkbox" className="accent-[var(--accent)]" checked={c.required} disabled={!!c.field} onChange={(e) => upd(i, { required: e.target.checked })}
                      title={c.field ? "Fixed by the console" : "Marked required in the guide"} />
                  </td>
                  <td className="px-1.5 py-1"><input className={cell} value={c.meaning} onChange={(e) => upd(i, { meaning: e.target.value })} /></td>
                  <td className="px-1.5 py-1"><input className={cell} value={c.example} onChange={(e) => upd(i, { example: e.target.value })} /></td>
                  <td className="px-1.5">
                    <button disabled={locked} title={locked ? "Required by the console" : "Remove column"} onClick={() => setCols(cols.filter((_, j) => j !== i))}
                      className="rounded p-1 text-fg-2 hover:bg-surface-3 hover:text-crit-fg disabled:opacity-30"><Trash2 className="size-3.5" /></button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => setCols([...cols, { field: null, name: "New column", required: false, meaning: "", example: "" }])}><Plus /> Add extra column</Button>
        {unused.length > 0 && (
          <Select value="" placeholder="Add back a standard column…" onChange={(f) => { const d = data.defaults.columns.find((x: any) => x.field === f); if (d) setCols([...cols, d]); }}
            options={unused.map((c: any) => ({ value: c.field, label: c.name }))} />
        )}
        <span className="text-[11.5px] text-muted">Rename a column to your own header and uploads with that header map to the same field.</span>
      </div>
    </Modal>
  );
}

export default function Templates() {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { data: meta } = useMeta();
  const { data, error: dataErr, refetch: dataRetry } = useQuery({ queryKey: ["templates"], queryFn: () => api<any>("/api/templates") });
  const [edit, setEdit] = React.useState<{ t: any } | null>(null);
  if (!data) return <Loading error={dataErr} retry={() => dataRetry()} />;
  const fields = meta?.inventory_fields || [];
  const del = async (t: any) => {
    if (!(await confirm({ title: `Delete template “${t.name}”?`, body: "LOBs using it as default fall back to auto-detection. Existing versions are unaffected.", ok: "Delete", danger: true }))) return;
    await api(`/api/templates/${t.id}`, { method: "DELETE" });
    qc.invalidateQueries();
  };
  return (
    <div>
      <PageHeader title="Templates" sub="A ready-to-fill Excel file for every upload (example rows and a column guide). Edit any template to use your own column names — uploads recognise them." />
      <FileTemplates />
      <div className="mb-3 mt-6 flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-[15px] font-semibold">Inventory column mappings</div>
          <div className="text-[12.5px] text-muted">Map a LOB&apos;s own spreadsheet columns to the standard fields. Assign one as a LOB&apos;s default and uploads map automatically.</div>
        </div>
        <Button variant="primary" onClick={() => setEdit({ t: null })}><Plus /> New mapping</Button>
      </div>
      <Callout className="mb-4"><b>Standard</b> is the default for every LOB: a sheet with the columns IP, Node Name, MSP, Node Type, Domain, Live/Non Live, OS, EDR Feasible, EDR Installed and Remarks maps automatically. MSP is optional. Columns it doesn&apos;t recognise are auto-detected from common names (e.g. “Server IP”, “Hostname”, “CrowdStrike Installed”, “Comments”). Values such as <i>Y / yes / installed / true</i> are normalised to <b>Yes</b>; <i>prod / live / active</i> to <b>Live</b>.</Callout>
      <Card>
        <SimpleTable rows={data.rows} empty="No templates yet — create one, or tick “Save as template” during an upload." columns={[
          { key: "name", label: "Template", render: (r: any) => <div><b>{r.name}</b>{r.name === "Standard" && <Badge tone="info" className="ml-1.5">Built-in default</Badge>}<div className="text-xs text-muted">{r.description}</div></div> },
          { key: "key_field", label: "Key", render: (r: any) => <Badge tone="info">{meta?.key_fields[r.key_field] || r.key_field}</Badge> },
          { key: "mapping", label: "Column mapping", wrap: true, render: (r: any) => <div className="flex flex-wrap gap-1">{fields.filter(([f]) => r.mapping[f]).map(([f, l]) => <Badge key={f} tone="outline">{l} ← {r.mapping[f]}</Badge>)}</div> },
          { key: "used_by", label: "Default for", render: (r: any) => r.used_by || <span className="text-muted">–</span> },
          { key: "updated_at", label: "Updated", render: (r: any) => fmtDt(r.updated_at) },
          { key: "act", label: "", render: (r: any) => (
            <div className="flex gap-1">
              <Button size="sm" onClick={() => setEdit({ t: r })}><Pencil /> Edit</Button>
              <Button size="sm" title="Download as empty spreadsheet" onClick={() => downloadExcel(`/api/templates/${r.id}/download`)}><Download /></Button>
              {r.name !== "Standard" && <Button size="sm" variant="danger" onClick={() => del(r)}><Trash2 /></Button>}
            </div>
          ) },
        ]} />
      </Card>
      <Editor t={edit?.t} open={!!edit} onOpenChange={(o) => !o && setEdit(null)} />
    </div>
  );
}
