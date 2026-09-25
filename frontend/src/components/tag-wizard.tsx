"use client";
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, Tags, UploadCloud } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Field, Modal, Select, Spinner } from "./ui";
import { SimpleTable } from "./data-table";
import { Mono } from "./badges";

const guess = (headers: string[], words: string[]) =>
  headers.find((h) => words.some((w) => h.toLowerCase().replace(/[^a-z]/g, "").includes(w))) || "";

/** Upload a sheet of Agent IDs (or hostnames / IPs) + MSP to tag agents to a LOB / MSP. */
export function TagWizard({ lob, mspId, open, onOpenChange }: { lob: { id: number; name: string }; mspId?: number | null; open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const { data: meta } = useMeta();
  const lobMsps = (meta?.msps || []).filter((m) => m.lob_id === lob.id);
  const [msp, setMsp] = React.useState(mspId ? String(mspId) : "");
  const [replace, setReplace] = React.useState("");
  const [parsed, setParsed] = React.useState<any>(null);
  const [idCol, setIdCol] = React.useState("");
  const [mspCol, setMspCol] = React.useState("");
  const [preview, setPreview] = React.useState<any>(null);
  const [busy, setBusy] = React.useState(false);
  const [done, setDone] = React.useState<any>(null);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const onFile = async (f?: File) => {
    if (!f) return;
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await api<any>("/api/uploads", { method: "POST", body: fd });
      setParsed(r);
      setIdCol(guess(r.headers, ["aid", "agentid", "deviceid", "sensorid", "hostname", "host", "ip"]) || r.headers[0]);
      setMspCol(guess(r.headers, ["msp", "vendor", "managedby", "partner"]));
      setPreview(null);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  };
  const body = () => ({ token: parsed.token, sheet: parsed.sheet, header_row: parsed.header_row, id_col: idCol, msp_col: msp ? null : mspCol || null, msp_id: msp ? +msp : null, replace: replace || null });
  const doPreview = async () => {
    setBusy(true);
    try { setPreview(await api(`/api/lobs/${lob.id}/tags/preview`, { method: "POST", body: body() })); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true);
    try {
      const r = await api(`/api/lobs/${lob.id}/tags/commit`, { method: "POST", body: body() });
      setDone(r);
      qc.invalidateQueries();
      toast.success(`${fmtN(r.tagged)} agents tagged to ${lob.name}`);
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const mspName = lobMsps.find((m) => String(m.id) === msp)?.name;

  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={<span className="flex items-center gap-2"><Tags className="size-4" /> Tag agents to {lob.name}</span>}
      footer={done ? <Button variant="primary" onClick={() => onOpenChange(false)}>Close</Button> : <>
        <Button onClick={() => onOpenChange(false)}>Cancel</Button>
        {parsed && !preview && <Button variant="primary" loading={busy} disabled={!idCol} onClick={doPreview}>Check agents</Button>}
        {preview && <Button variant="primary" loading={busy} disabled={!preview.resolved} onClick={commit}><Check /> Tag {fmtN(preview.resolved)} agents</Button>}
      </>}>
      {done ? (
        <div className="py-8 text-center">
          <div className="mx-auto mb-3 grid size-12 place-items-center rounded-full bg-good-soft"><Check className="size-6 text-good-fg" /></div>
          <div className="text-[17px] font-semibold">{fmtN(done.tagged)} agents tagged</div>
          <div className="mt-1 text-muted">{fmtN(done.unlisted)} are not in {lob.name}&apos;s inventory and now show as <b>Not in inventory</b>.</div>
        </div>
      ) : (
        <>
          <Callout className="mb-4">
            Use this for agents that report to Falcon for this LOB but are not in its inventory yet. Upload a sheet with an <b>Agent ID</b> column (hostname or IP also work) and optionally an <b>MSP</b> column.
            Tagged agents count toward the LOB/MSP; the ones missing from the inventory are reported as <b>Not in inventory</b>.
          </Callout>
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <Field label="MSP"><Select className="max-w-none" value={msp} onChange={(v) => { setMsp(v); setPreview(null); }} placeholder="From MSP column in file" options={lobMsps.map((m) => ({ value: m.id, label: m.name }))} /></Field>
            <Field label="Existing tags"><Select className="max-w-none" value={replace} onChange={(v) => { setReplace(v); setPreview(null); }} placeholder="Keep existing tags, add / update these"
              options={[...(msp ? [["msp", `Replace all tags of ${mspName}`] as [string, string]] : []), ["lob", `Replace all tags of ${lob.name}`]]} /></Field>
          </div>
          {!parsed ? (
            <div onClick={() => fileRef.current?.click()}
              onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); onFile(e.dataTransfer.files[0]); }}
              className="cursor-pointer rounded-2xl border-2 border-dashed border-border-strong bg-surface-2 px-6 py-12 text-center hover:border-accent">
              {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
              <div className="mt-3 text-[15px] font-semibold">Drop the AID sheet here or click to browse</div>
              <div className="mt-1 text-xs text-muted">.xlsx or .csv</div>
              <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
            </div>
          ) : (
            <>
              <div className="mb-4 flex flex-wrap items-end gap-3">
                <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13px]"><b>{parsed.filename}</b> <span className="text-muted">· {fmtN(parsed.row_count)} rows</span></div>
                <Field label="Agent ID / hostname / IP column"><Select value={idCol} onChange={(v) => { setIdCol(v); setPreview(null); }} options={parsed.headers} /></Field>
                {!msp && <Field label="MSP column"><Select value={mspCol} onChange={(v) => { setMspCol(v); setPreview(null); }} placeholder="— none (Unassigned) —" options={parsed.headers} /></Field>}
                <Button size="sm" variant="ghost" onClick={() => { setParsed(null); setPreview(null); }}>Choose another file</Button>
              </div>
              {preview && (
                <>
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                    {[["Rows", preview.total, ""], ["Matched in Falcon", preview.resolved, "text-good-fg"], ["Not found", preview.unresolved, "text-crit-fg"], ["Already in inventory", preview.in_inventory, ""], ["Not in inventory", preview.unlisted, "text-violet-fg"]].map(([l, n, c]) => (
                      <div key={l as string} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                        <div className="text-[11.5px] text-muted">{l}</div>
                        <div className={cn("text-[22px] font-semibold tabular", c as string)}>{fmtN(n)}</div>
                      </div>
                    ))}
                  </div>
                  {preview.new_msps?.length > 0 && <Callout className="mt-3">New MSPs will be created: <b>{preview.new_msps.join(", ")}</b></Callout>}
                  <div className="mt-3 overflow-hidden rounded-xl border border-border">
                    <SimpleTable rows={preview.rows} maxHeight="38vh" columns={[
                      { key: "value", label: "Value", render: (r: any) => <Mono>{r.value}</Mono> },
                      { key: "aid", label: "Agent ID", render: (r: any) => <Mono>{r.aid || "–"}</Mono> },
                      { key: "msp", label: "MSP", render: (r: any) => r.msp || <span className="text-muted">Unassigned</span> },
                      { key: "status", label: "Result", render: (r: any) => <Badge tone={r.status === "Not in inventory" ? "violet" : r.status === "Already in inventory" ? "good" : "crit"}>{r.status}</Badge> },
                    ]} />
                  </div>
                </>
              )}
            </>
          )}
        </>
      )}
    </Modal>
  );
}
