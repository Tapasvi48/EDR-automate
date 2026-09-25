"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp, Pencil, Plus, Trash2 } from "lucide-react";
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

export default function Templates() {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { data: meta } = useMeta();
  const { data } = useQuery({ queryKey: ["templates"], queryFn: () => api<any>("/api/templates") });
  const [edit, setEdit] = React.useState<{ t: any } | null>(null);
  if (!data) return <Loading />;
  const fields = meta?.inventory_fields || [];
  const del = async (t: any) => {
    if (!(await confirm({ title: `Delete template “${t.name}”?`, body: "LOBs using it as default fall back to auto-detection. Existing versions are unaffected.", ok: "Delete", danger: true }))) return;
    await api(`/api/templates/${t.id}`, { method: "DELETE" });
    qc.invalidateQueries();
  };
  return (
    <div>
      <PageHeader title="Inventory templates"
        sub="A template maps the columns of a LOB's spreadsheet to the standard fields (IP, Node Name, Node Type, Domain, Live/Non Live, OS, EDR Feasible, EDR Installed, Remarks). Assign one as a LOB's default and uploads map automatically — you can still adjust the mapping at upload time."
        actions={<>
          <Button onClick={() => downloadExcel("/api/templates/blank/download")}><Download /> Download Standard template (.xlsx)</Button>
          <Button variant="primary" onClick={() => setEdit({ t: null })}><Plus /> New template</Button>
        </>} />
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
