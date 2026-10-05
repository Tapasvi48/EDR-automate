"use client";
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Check, FileSpreadsheet, Sheet as SheetIcon, UploadCloud } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Checkbox, Field, Input, Modal, Segmented, Select, Spinner } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";

type SheetCfg = { sheet: string; include: boolean; type: string; header_row: number; headers: string[]; sample: string[][]; row_count: number; mapping: Record<string, string>; error?: string };

/** Communication-matrix workbook upload: every sheet of the workbook, each with its own type (firewall rules, public IP pool,
 *  NAT map, SOD / NAT rules, exposure register) and its own column mapping to the template fields. */
export function MatrixUpload({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const [wb, setWb] = React.useState<any>(null);
  const [sheets, setSheets] = React.useState<SheetCfg[]>([]);
  const [cur, setCur] = React.useState(0);
  const [mode, setMode] = React.useState<"workbook" | "all">("workbook");
  const [note, setNote] = React.useState("");
  const [preview, setPreview] = React.useState<any>(null);
  const [done, setDone] = React.useState<any>(null);
  const [busy, setBusy] = React.useState(false);
  const [drag, setDrag] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const onFile = (f?: File) => f && run(async () => {
    const fd = new FormData();
    fd.append("file", f);
    const up = await api<any>("/api/uploads", { method: "POST", body: fd });
    const r = await api<any>("/api/comm/workbook", { method: "POST", body: { token: up.token } });
    setWb(r);
    setSheets(r.sheets);
    setCur(Math.max(0, r.sheets.findIndex((s: SheetCfg) => s.include)));
    setPreview(null);
  });
  const patch = (i: number, p: Partial<SheetCfg>) => { setSheets((xs) => xs.map((x, j) => (j === i ? { ...x, ...p } : x))); setPreview(null); };
  const reread = (i: number, p: { type?: string; header_row?: number }) => run(async () => {
    const s = sheets[i];
    const r = await api<any>("/api/comm/workbook/sheet", { method: "POST", body: { token: wb.token, sheet: s.sheet, header_row: p.header_row ?? s.header_row, type: p.type ?? s.type } });
    patch(i, { ...r, include: s.include });
  });
  const body = () => ({ token: wb.token, mode, note, sheets: sheets.map(({ sheet, include, type, header_row, mapping }) => ({ sheet, include, type, header_row, mapping })) });
  const doPreview = () => run(async () => setPreview(await api("/api/comm/workbook/preview", { method: "POST", body: body() })));
  const doCommit = () => run(async () => {
    let uploadedBy = "";
    try { uploadedBy = localStorage.getItem("uploader") || ""; } catch {}
    const r = await api<any>("/api/comm/workbook/commit", { method: "POST", body: { ...body(), uploaded_by: uploadedBy } });
    setDone(r);
    qc.invalidateQueries();
    toast.success(r.message);
  });

  const types: any[] = wb?.types || [];
  const fields: any[] = wb?.fields || [];
  const s = sheets[cur];
  const tdef = types.find((t) => t.id === s?.type);
  const missing = (x: SheetCfg) => (types.find((t) => t.id === x.type)?.need || []).filter((g: string[]) => !g.some((k) => x.mapping[k]));
  const included = sheets.filter((x) => x.include);
  const ready = included.length > 0 && included.every((x) => !missing(x).length);
  const sample = (h: string) => {
    if (!s || !h) return "";
    const i = s.headers.indexOf(h);
    return s.sample.map((r) => r[i]).filter(Boolean).slice(0, 2).join(" · ");
  };
  const needKeys = new Set((tdef?.need || []).flat());
  // a pattern lists its own fields (with what each means for it); fields it does not list are not read
  const orderedFields: any[] = tdef?.fields?.length ? tdef.fields
    : [...fields.filter((f) => needKeys.has(f.key)), ...fields.filter((f) => !needKeys.has(f.key))];

  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={<span className="flex items-center gap-2"><FileSpreadsheet className="size-4" /> Upload communication matrix workbook</span>}
      footer={done ? <Button variant="primary" onClick={() => onOpenChange(false)}>Close</Button> : <>
        <Button onClick={() => onOpenChange(false)}>Cancel</Button>
        {wb && !preview && <Button variant="primary" loading={busy} disabled={!ready} onClick={doPreview}>Check</Button>}
        {preview && <Button variant="primary" loading={busy} onClick={doCommit}><Check /> Load {fmtN(preview.rows)} rows</Button>}
      </>}>
      {done ? (
        <div className="py-8 text-center">
          <div className="mx-auto mb-3 grid size-12 place-items-center rounded-full bg-good-soft"><Check className="size-6 text-good-fg" /></div>
          <div className="text-[16px] font-semibold">{done.message}</div>
          <div className="mt-3 flex flex-wrap justify-center gap-2 text-[12.5px]">{(done.per_sheet || []).map((p: any) => <Badge key={p.sheet} tone="info">{p.sheet}: {fmtN(p.rows)}</Badge>)}</div>
        </div>
      ) : !wb ? (
        <>
          <Callout className="mb-4">Each sheet is one of seven types: <b>Firewall rules</b> (Source Zone / ISP / Destination Zone, every row
            checked on its own), <b>Public IP + private IP</b>, <b>Only public IP</b>, the <b>Public IP · Internal IP register</b> (Public IP, Internal IP, Port, Service Details, Destination IP, REMARK), <b>Source NAT</b> (source_ip, destination_ip, Port / Protocol, Source Natted IP), <b>SOD NAT</b> (SODdetails, dest_nat_ip, destination_ip, fwl, location, nat_ip, port, protocol, rule, source_ip), or a <b>Firewall policy</b> export (Rule Name, zones, IP/Object, Action, NAT Translated IP, VPN Peer …). The type is guessed from the columns; change it in the
            sheet list if needed, then match the columns to the fields shown for that type.
            Addresses may be single IPs, lists (, ; / or new lines), ranges (10.1.1.10-20), subnets, last-octet shorthand (10.1.55.194/195/200),
            IPv6 prefixes, object names like h-10.1.1.5 or 10.1.1.5_nat, and host names.</Callout>
          <div onClick={() => fileRef.current?.click()} onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
            className={cn("cursor-pointer rounded-2xl border-2 border-dashed px-6 py-12 text-center transition-colors", drag ? "border-accent bg-accent-soft" : "border-border-strong bg-surface-2 hover:border-accent")}>
            {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
            <div className="mt-3 text-[15px] font-semibold">Drop the matrix workbook here</div>
            <div className="mt-1 text-xs text-muted">.xlsx, .xlsm or .csv · every sheet is read</div>
            <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
          </div>
        </>
      ) : preview ? (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[["Rows", preview.rows, ""], ["Internet-facing", preview.inbound, "text-crit-fg"], ["Addresses parsed", preview.addresses, "text-accent-fg"],
              [mode === "all" ? "Current rows replaced" : "Earlier rows of this workbook replaced", mode === "all" ? preview.current : preview.replaces_workbook, ""]].map(([l, n, cl]) => (
              <div key={l as string} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                <div className="text-[11.5px] text-muted">{l}</div><div className={cn("text-[22px] font-semibold tabular", cl as string)}>{fmtN(n as number)}</div>
              </div>
            ))}
          </div>
          <SimpleTable rows={preview.per_sheet} columns={[
            { key: "sheet", label: "Sheet", render: (r: any) => <b>{r.sheet}</b> },
            { key: "type", label: "Type", render: (r: any) => types.find((t) => t.id === r.type)?.label || r.type },
            { key: "rows", label: "Rows", num: true }, { key: "inbound", label: "Internet-facing", num: true },
          ]} />
          {preview.warnings?.length > 0 && <Callout tone="warn">{preview.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
          <div className="overflow-hidden rounded-xl border border-border">
            <SimpleTable rows={preview.sample} maxHeight="30vh" columns={[
              { key: "sheet", label: "Sheet" }, { key: "rule_id", label: "Row" }, { key: "src", label: "Source", wrap: true },
              { key: "dst_nat", label: "Public IP", wrap: true }, { key: "dst", label: "Destination / private", wrap: true },
              { key: "ports", label: "Ports" }, { key: "app_owner", label: "Owner" },
              { key: "inbound_internet", label: "Internet", render: (r: any) => r.inbound_internet ? <Badge tone="crit">yes</Badge> : "" },
            ]} />
          </div>
          <Button size="sm" variant="ghost" onClick={() => setPreview(null)}>← Back to sheets</Button>
        </div>
      ) : (
        <div className={cn("space-y-3", busy && "pointer-events-none opacity-60")}>
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex items-center gap-2 rounded-lg bg-surface-2 px-3 py-2 text-[13px]"><FileSpreadsheet className="size-4 text-good" /><b>{wb.filename}</b>
              <span className="text-muted">· {sheets.length} sheet(s)</span></div>
            <Field label="Replace"><Segmented value={mode} onChange={setMode} options={[["workbook", "This workbook's rows"], ["all", "Whole matrix"]]} /></Field>
            <Field label="Note (optional)"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Matrix after CR-2026-1102" /></Field>
            <Button size="sm" variant="ghost" onClick={() => { setWb(null); setSheets([]); }}>Choose another file</Button>
          </div>
          <div className="grid gap-3 md:grid-cols-[230px_minmax(0,1fr)]">
            <div className="space-y-1 rounded-xl border border-border p-1.5">
              {sheets.map((x, i) => {
                const miss = x.include && missing(x).length > 0;
                return (
                  <div key={x.sheet} onClick={() => setCur(i)}
                    className={cn("flex cursor-pointer items-start gap-2 rounded-lg px-2 py-1.5", i === cur ? "bg-accent-soft" : "hover:bg-surface-2")}>
                    <input type="checkbox" className="mt-1" checked={x.include} disabled={!!x.error} onClick={(e) => e.stopPropagation()} onChange={(e) => patch(i, { include: e.target.checked })} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1 truncate text-[12.5px] font-medium"><SheetIcon className="size-3.5 shrink-0 text-muted" />{x.sheet}</div>
                      {x.error ? <div className="truncate text-[11px] text-muted">{x.error}</div> : <>
                        <div className="text-[11px] text-muted">{fmtN(x.row_count)} rows</div>
                        <select aria-label={`Type of sheet ${x.sheet}`} className="mt-1 h-7 w-full rounded-md border border-border-strong bg-surface px-1.5 text-[11.5px]"
                          value={x.type} onClick={(e) => e.stopPropagation()} onChange={(e) => { setCur(i); reread(i, { type: e.target.value }); }}>
                          {types.map((t) => <option key={t.id} value={t.id} title={t.hint}>{t.label}</option>)}
                        </select>
                      </>}
                      {miss && <div className="text-[11px] text-crit-fg">map required columns</div>}
                    </div>
                  </div>
                );
              })}
            </div>
            {s && !s.error ? (
              <div className="min-w-0 space-y-3">
                <div className="flex flex-wrap items-end gap-3">
                  <Field label={`Type of sheet “${s.sheet}”`}>
                    <Select className="max-w-none" value={s.type} onChange={(v) => reread(cur, { type: v })} options={types.map((t) => ({ value: t.id, label: t.label }))} />
                  </Field>
                  <Field label="Header row"><Input type="number" min={1} className="w-20" value={s.header_row} onChange={(e) => e.target.value && reread(cur, { header_row: +e.target.value })} /></Field>
                  <Checkbox checked={s.include} onChange={(v) => patch(cur, { include: v })} label="Include this sheet" />
                </div>
                {tdef && <div className="text-[11.5px] text-muted">{tdef.hint}</div>}
                <div className="max-h-[46vh] overflow-auto rounded-xl border border-border scroll-thin">
                  <table className="w-full text-[12.5px]">
                    <thead className="sticky top-0 bg-surface-2"><tr className="text-left text-xs text-fg-2"><th className="px-3 py-2">Template field</th><th className="px-3 py-2">Column in this sheet</th><th className="px-3 py-2">Sample</th></tr></thead>
                    <tbody>
                      {orderedFields.map((f) => {
                        const need = needKeys.has(f.key);
                        return (
                          <tr key={f.key} className="border-t border-border">
                            <td className="px-3 py-1.5">
                              <div className="font-medium">{f.label}{need && <span className="ml-1 text-crit-fg" title="this sheet type needs one of the starred fields">*</span>}</div>
                              {f.desc && <div className="text-[11px] leading-snug text-muted">{f.desc}</div>}
                            </td>
                            <td className="px-3 py-1">
                              <select className={cn("h-8 w-full rounded-md border bg-surface px-2", s.mapping[f.key] ? "border-good" : "border-border-strong")}
                                value={s.mapping[f.key] || ""} onChange={(e) => patch(cur, { mapping: { ...s.mapping, [f.key]: e.target.value } })}>
                                <option value="">— not mapped —</option>
                                {s.headers.map((h) => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </td>
                            <td className="max-w-[260px] truncate px-3 py-1.5 text-xs text-muted">{sample(s.mapping[f.key])}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {missing(s).length > 0 && <div className="text-[12px] text-crit-fg">Map at least one of the starred fields.</div>}
              </div>
            ) : <div className="grid place-items-center text-[13px] text-muted">{s?.error || "Pick a sheet"}</div>}
          </div>
        </div>
      )}
    </Modal>
  );
}
