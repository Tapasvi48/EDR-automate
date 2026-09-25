"use client";
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, FileSpreadsheet, Info, UploadCloud } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Checkbox, Field, Input, Modal, Select, Spinner, Tabs } from "./ui";
import { SimpleTable } from "./data-table";
import { Live, Mono, YN } from "./badges";

const STEPS = ["Choose file", "Map columns", "Review changes", "Done"];

export function UploadWizard({ lob, open, onOpenChange, mspId }: { lob: { id: number; name: string }; open: boolean; onOpenChange: (v: boolean) => void; mspId?: number | null }) {
  const qc = useQueryClient();
  const { data: meta } = useMeta();
  const [step, setStep] = React.useState(0);
  const [busy, setBusy] = React.useState(false);
  const [parsed, setParsed] = React.useState<any>(null);
  const [mapping, setMapping] = React.useState<Record<string, string>>({});
  const [keyField, setKeyField] = React.useState("ip");
  const [templateId, setTemplateId] = React.useState("");
  const [saveTpl, setSaveTpl] = React.useState(false);
  const [tplName, setTplName] = React.useState("");
  const [setDefault, setSetDefault] = React.useState(true);
  const [note, setNote] = React.useState("");
  const [uploadedBy, setUploadedBy] = React.useState(() => { try { return localStorage.getItem("uploader") || ""; } catch { return ""; } });
  const [preview, setPreview] = React.useState<any>(null);
  const [result, setResult] = React.useState<any>(null);
  const [drag, setDrag] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);
  const [scope, setScope] = React.useState(mspId ? String(mspId) : "");
  const lobMsps = (meta?.msps || []).filter((m) => m.lob_id === lob.id);
  const scopeName = lobMsps.find((m) => String(m.id) === scope)?.name;
  const fields = (meta?.inventory_fields || []).filter(([f]) => !(scope && f === "msp"));

  const applyParse = (r: any) => {
    setParsed(r);
    setMapping(r.mapping || {});
    setKeyField(r.key_field || "ip");
    setTemplateId(r.template_id ? String(r.template_id) : "");
  };
  const onFile = async (f?: File) => {
    if (!f) return;
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const up = await api<any>("/api/uploads", { method: "POST", body: fd });
      const r = await api<any>(`/api/uploads/${up.token}/parse`, { method: "POST", body: { lob_id: lob.id } });
      applyParse(r);
      setTplName(`${lob.name} inventory`);
      setStep(1);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };
  const reparse = async (patch: { sheet?: string; header_row?: number; template_id?: string }) => {
    setBusy(true);
    try {
      const r = await api<any>(`/api/uploads/${parsed.token}/parse`, {
        method: "POST",
        body: { sheet: patch.sheet ?? parsed.sheet, header_row: patch.header_row ?? parsed.header_row, template_id: patch.template_id !== undefined ? (patch.template_id ? +patch.template_id : null) : (templateId ? +templateId : null), lob_id: lob.id },
      });
      applyParse(r);
      if (patch.template_id !== undefined) setTemplateId(patch.template_id);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };
  const body = () => ({ token: parsed.token, sheet: parsed.sheet, header_row: parsed.header_row, mapping: scope ? { ...mapping, msp: "" } : mapping, key_field: keyField, scope_msp_id: scope ? +scope : null });
  const doPreview = async () => {
    setBusy(true);
    try {
      setPreview(await api(`/api/lobs/${lob.id}/upload/preview`, { method: "POST", body: body() }));
      setStep(2);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };
  const commit = async () => {
    setBusy(true);
    try {
      try { localStorage.setItem("uploader", uploadedBy); } catch {}
      const r = await api(`/api/lobs/${lob.id}/upload/commit`, {
        method: "POST",
        body: { ...body(), note, uploaded_by: uploadedBy, template_id: templateId ? +templateId : null, save_template_name: saveTpl ? tplName : "", set_default_template: saveTpl ? setDefault : !!templateId && setDefault },
      });
      setResult(r);
      setStep(3);
      qc.invalidateQueries();
      toast.success(`Version v${r.version_no} created`);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };

  const usedHeaders = new Set(Object.values(mapping).filter(Boolean));
  const extraHeaders = (parsed?.headers || []).filter((h: string) => !usedHeaders.has(h));
  const samples = (h: string) => {
    if (!parsed || !h) return [];
    const i = parsed.headers.indexOf(h);
    return parsed.sample.map((r: string[]) => r[i]).filter(Boolean).slice(0, 3);
  };
  const keyOk = keyField === "node_name" ? !!mapping.node_name : keyField === "ip" ? !!(mapping.ip || mapping.node_name) : !!(mapping.ip && mapping.node_name);

  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={<span>Upload inventory · <span className="text-accent-fg">{lob.name}</span></span>}
      footer={
        <>
          {step === 1 && <><Button onClick={() => setStep(0)}>Back</Button><Button variant="primary" loading={busy} disabled={!keyOk} onClick={doPreview}>Review changes</Button></>}
          {step === 2 && <><Button onClick={() => setStep(1)}>Back to mapping</Button><Button variant="primary" loading={busy} onClick={commit}><Check /> Commit as new version</Button></>}
          {step === 3 && <Button variant="primary" onClick={() => onOpenChange(false)}>Close</Button>}
        </>
      }>
      <div className="mb-5 grid grid-cols-4 gap-2">
        {STEPS.map((s, i) => (
          <div key={s} className={cn("rounded-lg border px-3 py-2 text-xs font-semibold", i === step ? "border-accent bg-accent-soft text-accent-fg" : i < step ? "border-border text-good-fg" : "border-border text-muted")}>
            {i < step ? "✓ " : `${i + 1}. `}{s}
          </div>
        ))}
      </div>

      {step === 0 && (
        <div>
          {lobMsps.length > 0 && (
            <div className="mb-4 flex items-center gap-3">
              <span className="text-[13px] font-medium">Upload for</span>
              <Select value={scope} onChange={setScope} placeholder={`Whole ${lob.name} (all MSPs)`} options={lobMsps.map((m) => ({ value: m.id, label: `MSP: ${m.name}` }))} />
              <span className="text-xs text-muted">{scope ? "only this MSP's nodes will be replaced" : "the file replaces the whole LOB inventory"}</span>
            </div>
          )}
          <div
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
            className={cn("cursor-pointer rounded-2xl border-2 border-dashed px-6 py-14 text-center transition-colors", drag ? "border-accent bg-accent-soft" : "border-border-strong bg-surface-2 hover:border-accent")}
          >
            {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
            <div className="mt-3 text-[15px] font-semibold">Drop the inventory file here or click to browse</div>
            <div className="mt-1 text-xs text-muted">.xlsx, .xlsm or .csv · header row is detected automatically · extra columns are kept</div>
            <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
          </div>
          <Callout className="mt-4">
            <b>How versioning works:</b> rows are matched to the previous version by the <b>key field</b> (IP by default). New keys are tagged <Badge tone="info">NEW</Badge>, missing keys are recorded as removed, and any changed field is logged with its old and new value. Every upload is an immutable version — you can view, compare or restore any earlier version.
          </Callout>
        </div>
      )}

      {step === 1 && parsed && (
        <div className={busy ? "pointer-events-none opacity-60" : ""}>
          <div className="mb-4 flex flex-wrap items-end gap-3">
            <div className="flex items-center gap-2 rounded-lg bg-surface-2 px-3 py-2 text-[13px]"><FileSpreadsheet className="size-4 text-good" /><b>{parsed.filename}</b><span className="text-muted">· {fmtN(parsed.row_count)} data rows</span></div>
            {parsed.sheets.length > 1 && <Field label="Sheet"><Select value={parsed.sheet} onChange={(v) => reparse({ sheet: v })} options={parsed.sheets} /></Field>}
            <Field label="Header row"><Input type="number" min={1} className="w-20" value={parsed.header_row} onChange={(e) => e.target.value && reparse({ header_row: +e.target.value })} /></Field>
            <Field label="Template"><Select value={templateId} onChange={(v) => reparse({ template_id: v })} placeholder="Auto-detect columns" options={(meta?.templates || []).map((t) => ({ value: t.id, label: t.name }))} /></Field>
            <Field label="Key field (row identity across versions)"><Select value={keyField} onChange={setKeyField} options={Object.entries(meta?.key_fields || {})} /></Field>
            <Field label="This file contains"><Select value={scope} onChange={setScope} placeholder="All MSPs (use MSP column)" options={lobMsps.map((m) => ({ value: m.id, label: `Only ${m.name}'s nodes` }))} /></Field>
          </div>
          {scope ? (
            <Callout className="mb-4">Every row is assigned to <b>{scopeName}</b>. Only {scopeName}&apos;s nodes are replaced — other MSPs&apos; rows are carried over unchanged into the new version.</Callout>
          ) : !mapping.msp && lobMsps.length > 0 ? (
            <Callout tone="warn" className="mb-4">No MSP column is mapped, so every row will be <b>Unassigned</b>. Map the MSP column, or pick one MSP above if this file belongs to a single MSP.</Callout>
          ) : null}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <div className="overflow-hidden rounded-xl border border-border">
              <table className="w-full text-[12.8px]">
                <thead><tr className="bg-surface-2 text-left text-xs text-fg-2"><th className="px-3 py-2">Standard field</th><th className="px-3 py-2">Column in your file</th><th className="px-3 py-2">Sample values</th></tr></thead>
                <tbody>
                  {fields.map(([f, label]) => (
                    <tr key={f} className="border-t border-border">
                      <td className="px-3 py-2 font-medium">{label}{(f === "ip" || f === "node_name") && <span className="ml-1 text-crit-fg">*</span>}</td>
                      <td className="px-3 py-1.5">
                        <select className={cn("h-8 w-full rounded-md border bg-surface px-2", mapping[f] ? "border-good" : "border-border-strong")} value={mapping[f] || ""} onChange={(e) => setMapping({ ...mapping, [f]: e.target.value })}>
                          <option value="">— not mapped —</option>
                          {parsed.headers.map((h: string) => <option key={h} value={h}>{h}{usedHeaders.has(h) && mapping[f] !== h ? " (used)" : ""}</option>)}
                        </select>
                      </td>
                      <td className="max-w-[260px] truncate px-3 py-2 text-xs text-muted">{samples(mapping[f]).join(" · ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="space-y-3">
              {!keyOk && <Callout tone="crit">Map the column(s) needed for the key field before continuing.</Callout>}
              <div className="rounded-xl border border-border p-3">
                <div className="mb-1.5 text-xs font-semibold text-fg-2">Unmapped columns — kept as extra fields ({extraHeaders.length})</div>
                <div className="flex flex-wrap gap-1">{extraHeaders.length ? extraHeaders.map((h: string) => <Badge key={h} tone="outline">{h}</Badge>) : <span className="text-xs text-muted">None</span>}</div>
              </div>
              <div className="rounded-xl border border-border p-3">
                <Checkbox checked={saveTpl} onChange={setSaveTpl} label="Save this mapping as a template" />
                {saveTpl && <Input className="mt-2 w-full" value={tplName} onChange={(e) => setTplName(e.target.value)} placeholder="Template name" />}
                {(saveTpl || templateId) && <div className="mt-2"><Checkbox checked={setDefault} onChange={setSetDefault} label={`Use as default template for ${lob.name}`} /></div>}
              </div>
              <Field label="Uploaded by"><Input value={uploadedBy} onChange={(e) => setUploadedBy(e.target.value)} placeholder="Your name" /></Field>
              <Field label="Version note"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Q3 CMDB refresh" /></Field>
            </div>
          </div>
          <div className="mt-4">
            <div className="mb-1.5 text-xs font-semibold text-fg-2">File preview (first rows)</div>
            <div className="overflow-auto rounded-xl border border-border scroll-thin">
              <table className="w-full text-[12px]">
                <thead><tr>{parsed.headers.map((h: string) => <th key={h} className={cn("whitespace-nowrap bg-surface-2 px-2.5 py-1.5 text-left font-semibold", usedHeaders.has(h) ? "text-good-fg" : "text-muted")}>{h}</th>)}</tr></thead>
                <tbody>{parsed.sample.slice(0, 5).map((r: string[], i: number) => <tr key={i} className="border-t border-border">{r.map((v, j) => <td key={j} className="max-w-[200px] truncate whitespace-nowrap px-2.5 py-1">{v}</td>)}</tr>)}</tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {step === 2 && preview && <Preview p={preview} />}

      {step === 3 && result && (
        <div className="py-6 text-center">
          <div className="mx-auto mb-3 grid size-12 place-items-center rounded-full bg-good-soft"><Check className="size-6 text-good-fg" /></div>
          <div className="text-[17px] font-semibold">Version v{result.version_no} created</div>
          <div className="mt-1 text-muted">{fmtN(result.total)} items · <span className="text-accent-fg">+{fmtN(result.added)} new</span> · <span className="text-crit-fg">−{fmtN(result.removed)} removed</span> · <span className="text-warn-fg">{fmtN(result.modified)} modified</span> · {fmtN(result.unchanged)} unchanged</div>
          <div className="mt-1 text-xs text-muted">EDR verification has been recalculated against the current Falcon data.</div>
          {result.warnings?.length > 0 && <Callout tone="warn" className="mx-auto mt-4 max-w-xl text-left">{result.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
        </div>
      )}
    </Modal>
  );
}

export function Preview({ p }: { p: any }) {
  const [tab, setTab] = React.useState(p.modified ? "modified" : p.added ? "added" : "removed");
  const itemCols = [
    { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip}</Mono> }, { key: "node_name", label: "Node name" },
    { key: "node_type", label: "Node type" }, { key: "domain", label: "Domain" }, { key: "live", label: "Live", render: (r: any) => <Live v={r.live} /> },
    { key: "os", label: "OS" }, { key: "edr_feasible", label: "EDR feasible", render: (r: any) => <YN v={r.edr_feasible} /> },
    { key: "edr_installed", label: "EDR installed", render: (r: any) => <YN v={r.edr_installed} /> }, { key: "remarks", label: "Remarks" },
  ];
  return (
    <div>
      {p.is_first_version && <Callout className="mb-3"><Info className="mr-1 inline size-4" />This is the first inventory for this LOB — every row will be tagged NEW.</Callout>}
      {p.scope_msp && <Callout className="mb-3">Only <b>{p.scope_msp}</b>&apos;s nodes are compared and replaced. Other MSPs are unchanged.</Callout>}
      {p.new_msps?.length > 0 && <Callout className="mb-3">New MSPs will be created: <b>{p.new_msps.join(", ")}</b></Callout>}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Box label="Rows in file" value={p.total} />
        <Box label="New (added)" value={p.added} tone="text-accent-fg" />
        <Box label="Removed" value={p.removed} tone="text-crit-fg" />
        <Box label="Modified" value={p.modified} tone="text-warn-fg" />
        <Box label="Unchanged" value={p.unchanged} />
      </div>
      {p.warnings?.length > 0 && <Callout tone="warn" className="mt-3">{p.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
      <div className="mt-4">
        <Tabs value={tab} onChange={setTab} tabs={[{ id: "modified", label: "Modified", count: p.modified }, { id: "added", label: "New", count: p.added }, { id: "removed", label: "Removed", count: p.removed }]} />
        {tab === "modified" && (
          <SimpleTable rows={p.samples.modified} maxHeight="44vh" empty="No modified rows" columns={[
            { key: "key", label: "Key", render: (r: any) => <Mono>{r.key}</Mono> }, { key: "node_name", label: "Node name" },
            { key: "changes", label: "Changes", wrap: true, render: (r: any) => (
              <div className="flex flex-col gap-0.5">{r.changes.map((c: any, i: number) => (
                <div key={i}><span className="text-fg-2">{c.field}:</span> <span className="text-crit-fg line-through">{c.old || "∅"}</span> → <b className="text-good-fg">{c.new || "∅"}</b></div>
              ))}</div>
            ) },
          ]} />
        )}
        {tab === "added" && <SimpleTable rows={p.samples.added} maxHeight="44vh" empty="No new rows" columns={itemCols} />}
        {tab === "removed" && <SimpleTable rows={p.samples.removed} maxHeight="44vh" empty="No removed rows" columns={itemCols} />}
        {(p.added > p.samples.added.length || p.modified > p.samples.modified.length || p.removed > p.samples.removed.length) && (
          <div className="mt-2 text-xs text-muted">Showing the first 200 of each. The full change log is available after commit.</div>
        )}
      </div>
    </div>
  );
}
function Box({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
      <div className="text-[11.5px] text-muted">{label}</div>
      <div className={cn("text-[22px] font-semibold tabular", tone)}>{fmtN(value)}</div>
    </div>
  );
}
