"use client";
import * as React from "react";
import { toast } from "sonner";
import { Download, FileSearch, UploadCloud } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Field, Input, Modal, Select, Spinner } from "./ui";
import { SimpleTable } from "./data-table";

const TONE: Record<string, any> = { Online: "good", Offline: "warn", Inactive: "warn", "Removed from console": "serious", "Old EDR import": "violet",
  "IP used by another host": "neutral", "Not found": "crit" };

/** EDR lookup: any Excel / CSV with an IP and / or hostname column, matched to every CrowdStrike asset (console, removed,
 *  old EDR import) the same way LOB inventories are; the same file comes back with EDR columns appended. Nothing is saved. */
export function EdrLookup({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const [p, setP] = React.useState<any>(null);
  const [ipCol, setIpCol] = React.useState("");
  const [hnCol, setHnCol] = React.useState("");
  const [mode, setMode] = React.useState("both");
  const [preview, setPreview] = React.useState<any>(null);
  const [busy, setBusy] = React.useState(false);
  const [drag, setDrag] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);
  const run = async (fn: () => Promise<void>) => { setBusy(true); try { await fn(); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); } };
  const take = (r: any) => { setP(r); setIpCol(r.ip_col || ""); setHnCol(r.host_col || ""); setMode(r.mode || "both"); setPreview(null); };
  const onFile = (f?: File) => f && run(async () => {
    const fd = new FormData();
    fd.append("file", f);
    const up = await api<any>("/api/uploads", { method: "POST", body: fd });
    take(await api<any>("/api/edr-lookup/parse", { method: "POST", body: { token: up.token } }));
  });
  const reparse = (patch: any) => run(async () => take(await api<any>("/api/edr-lookup/parse", { method: "POST",
    body: { token: p.token, sheet: p.sheet, header_row: p.header_row, ...patch } })));
  const params = () => ({ token: p.token, sheet: p.sheet, header_row: String(p.header_row), ip_col: mode === "hostname" ? "" : ipCol,
    host_col: mode === "ip" ? "" : hnCol, mode });
  const ready = p && ((mode === "ip" && ipCol) || (mode === "hostname" && hnCol) || (mode === "both" && (ipCol || hnCol)));
  const colOpts = [{ value: "", label: "— none —" }, ...(p?.headers || []).map((h: string) => ({ value: h, label: h }))];
  const sample = (h: string) => { if (!p || !h) return ""; const i = p.headers.indexOf(h); return p.sample.map((r: string[]) => r[i]).filter(Boolean).slice(0, 2).join(" · "); };
  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={<span className="flex items-center gap-2"><FileSearch className="size-4" /> EDR lookup: match a list with CrowdStrike</span>}
      footer={<>
        <Button onClick={() => onOpenChange(false)}>Close</Button>
        {p && <Button loading={busy} disabled={!ready} onClick={() => run(async () => setPreview(await api("/api/edr-lookup/preview", { method: "POST", body: params() })))}>Check</Button>}
        {p && <Button variant="primary" disabled={!ready || busy} onClick={() => { downloadExcel("/api/edr-lookup/export", params()); toast.message("Preparing the Excel file…"); }}><Download /> Download Excel with EDR status</Button>}
      </>}>
      <Callout className="mb-4">Upload any Excel / CSV with an <b>IP</b> and / or a <b>hostname</b> column. Each row is matched to every CrowdStrike asset —
        agents in the console, agents removed from it and the old EDR inventory import — the same way LOB inventories are matched, and the same file
        comes back with <b>EDR Status, match method, CrowdStrike hostname, AID, OS, platform, sensor version, last seen</b> and the agent's IPs appended.
        Nothing is saved; inventories are not changed.</Callout>
      {!p ? (
        <div onClick={() => fileRef.current?.click()} onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
          className={cn("cursor-pointer rounded-2xl border-2 border-dashed px-6 py-12 text-center transition-colors", drag ? "border-accent bg-accent-soft" : "border-border-strong bg-surface-2 hover:border-accent")}>
          {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
          <div className="mt-3 text-[15px] font-semibold">Drop the list here</div>
          <div className="mt-1 text-xs text-muted">.xlsx, .xlsm or .csv · header row detected automatically</div>
          <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
        </div>
      ) : (
        <div className={cn("space-y-3", busy && "pointer-events-none opacity-60")}>
          <div className="flex flex-wrap items-end gap-3">
            <div className="rounded-lg bg-surface-2 px-3 py-2 text-[13px]"><b>{p.filename}</b> <span className="text-muted">· {fmtN(p.row_count)} rows</span></div>
            {p.sheets.length > 1 && <Field label="Sheet"><Select value={p.sheet} onChange={(v) => reparse({ sheet: v })} options={p.sheets} /></Field>}
            <Field label="Header row"><Input type="number" min={1} className="w-20" value={p.header_row} onChange={(e) => e.target.value && reparse({ header_row: +e.target.value })} /></Field>
            <Button size="sm" variant="ghost" onClick={() => { setP(null); setPreview(null); }}>Choose another file</Button>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <Field label="Match by"><Select className="max-w-none" value={mode} onChange={(v) => { setMode(v); setPreview(null); }} options={p.modes} /></Field>
            {mode !== "hostname" && <Field label="IP column" hint={sample(ipCol)}><Select className="max-w-none" value={ipCol} onChange={(v) => { setIpCol(v); setPreview(null); }} options={colOpts} /></Field>}
            {mode !== "ip" && <Field label="Hostname column" hint={sample(hnCol)}><Select className="max-w-none" value={hnCol} onChange={(v) => { setHnCol(v); setPreview(null); }} options={colOpts} /></Field>}
          </div>
          {preview && (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-[13px]">
                <span className="text-muted">{fmtN(preview.rows)} rows:</span>
                {preview.counts.map(([k, n]: [string, number]) => <Badge key={k} tone={TONE[k] || "neutral"}>{k} {fmtN(n)}</Badge>)}
              </div>
              <div className="overflow-hidden rounded-xl border border-border">
                <SimpleTable rows={preview.sample} maxHeight="34vh" columns={[
                  { key: "ip", label: "IP (file)" }, { key: "hostname", label: "Hostname (file)" },
                  { key: "edr_status", label: "EDR status", render: (r: any) => <Badge tone={TONE[r.edr_status] || "neutral"}>{r.edr_status}</Badge> },
                  { key: "edr_match", label: "Matched by" }, { key: "cs_hostname", label: "CrowdStrike host" }, { key: "cs_os", label: "OS" },
                  { key: "cs_last_seen", label: "Last seen" }]} />
              </div>
              <div className="text-[12px] text-muted">First 30 rows shown; the download has every row.</div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
