"use client";
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Check, FileSpreadsheet, Radio, ShieldAlert, UploadCloud } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button, Callout, Field, Input, Modal, Select, Spinner } from "./ui";
import { SimpleTable } from "./data-table";
import { Mono, SeverityBadge } from "./badges";

type Kind = "vulns" | "edr" | "niam" | "sod" | "comm" | "ndr";
const TEXT: Record<Kind, { title: string; drop: string; help: React.ReactNode; commit: string }> = {
  vulns: {
    title: "Upload vulnerability scan",
    drop: "Drop the Nessus / scanner export here",
    help: <>Expected columns: <b>IP Address, Vulnerability Name, Severity</b> (plus Protocol, Port, Plugin ID, CVE, dates… — anything a Nessus export has). For every IP in this file, findings that no longer appear are marked <b>fixed</b>; IPs not in the file keep their previous findings, so partial scans are safe.</>,
    commit: "Import scan",
  },
  edr: {
    title: "Upload old EDR inventory",
    drop: "Drop the old CrowdStrike host export here",
    help: <>An older host export from the Falcon console (Hostname, Host ID / AID, Local IP, OS, Sensor version, First / Last Seen…). Agents that are <b>no longer in the live console</b> are kept as <b>Old EDR import</b> under EDR history, and are used when matching inventory, vulnerabilities and searches. Agents still live are skipped.</>,
    commit: "Import agents",
  },
  niam: {
    title: "Upload NIAM dump",
    drop: "Drop the NIAM export here",
    help: <>Two columns are needed: <b>Host</b> (the node IP — IPv4 or IPv6, any spelling) and <b>NE ID</b>. Other columns (NE name, type, vendor, circle…) are kept. Each upload is a full snapshot: nodes missing from the new dump are marked <b>dropped</b>, not deleted. Every node is matched to LOB inventories, CrowdStrike and vulnerability scans.</>,
    commit: "Import NIAM dump",
  },
  sod: {
    title: "Upload vulnerability exceptions (SOD)",
    drop: "Drop the SOD / exception register here",
    help: <>The <b>complete</b> exception register (it replaces the current list). Each row needs an Exception ID, a vulnerability (Plugin ID, CVE or name), a scope (All / IP / Subnet / LOB), Justification, Approved By and Valid Till. Matching findings become <b>Accepted</b>: they leave open counts and risk, and reopen automatically when the exception expires.</>,
    commit: "Load exceptions",
  },
  comm: {
    title: "Upload communication matrix",
    drop: "Drop the firewall / NAT communication matrix here",
    help: <>The <b>complete</b> matrix (it replaces the current one). Needed: Rule ID, Source IP / Subnet and Destination IP / Subnet (IP, CIDR, range or list); Direction, zones, ISP link, firewall, destination NAT (public) IP, protocol, ports and action are used when present. Allow rules from Internet / ISP mark their destinations <b>internet-exposed</b> on those ports.</>,
    commit: "Load matrix",
  },
  ndr: {
    title: "Upload Seceon NDR alerts",
    drop: "Drop a Seceon aiXDR / OTM alert export here",
    help: <>An alert export (Excel / CSV). Needed: Time, Alert Name and a Source IP, Destination IP or Host; Severity, Category, Description and Status are used when present. Alerts are <b>added</b> to what is stored (same Alert ID = updated) and appear under Recent detections in Asset 360. Alerts can also arrive live through the webhook (Integrations).</>,
    commit: "Load alerts",
  },
};
const BASE: Record<Kind, string> = { vulns: "/api/vulns", edr: "/api/edr-import", niam: "/api/niam", sod: "/api/sod", comm: "/api/comm", ndr: "/api/ndr" };
const GENERIC = (k: Kind) => k === "sod" || k === "comm" || k === "ndr";

export function MappedUpload({ kind, open, onOpenChange, lobId }: { kind: Kind; open: boolean; onOpenChange: (v: boolean) => void; lobId?: number }) {
  const qc = useQueryClient();
  const { data: meta } = useMeta();
  const t = TEXT[kind];
  const [lob, setLob] = React.useState(lobId ? String(lobId) : "");
  const [parsed, setParsed] = React.useState<any>(null);
  const [mapping, setMapping] = React.useState<Record<string, string>>({});
  const [preview, setPreview] = React.useState<any>(null);
  const [done, setDone] = React.useState<any>(null);
  const [busy, setBusy] = React.useState(false);
  const [drag, setDrag] = React.useState(false);
  const [note, setNote] = React.useState("");
  const fileRef = React.useRef<HTMLInputElement>(null);
  const base = BASE[kind];

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const onFile = (f?: File) => f && run(async () => {
    const fd = new FormData();
    fd.append("file", f);
    const up = await api<any>("/api/uploads", { method: "POST", body: fd });
    const r = await api<any>(`${base}/parse`, { method: "POST", body: { token: up.token } });
    setParsed(r);
    setMapping(r.mapping || {});
    setPreview(null);
  });
  const reparse = (patch: any) => run(async () => {
    const r = await api<any>(`${base}/parse`, { method: "POST", body: { token: parsed.token, sheet: parsed.sheet, header_row: parsed.header_row, ...patch } });
    setParsed(r);
    setMapping(r.mapping || {});
    setPreview(null);
  });
  const body = () => ({ token: parsed.token, sheet: parsed.sheet, header_row: parsed.header_row, mapping, note });
  const doPreview = () => run(async () => {
    setPreview(await api(kind === "vulns" ? `/api/lobs/${lob}/vulns/preview` : `${base}/preview`, { method: "POST", body: body() }));
  });
  const doCommit = () => run(async () => {
    let uploadedBy = "";
    try { uploadedBy = localStorage.getItem("uploader") || ""; } catch {}
    const r = await api<any>(kind === "vulns" ? `/api/lobs/${lob}/vulns/commit` : `${base}/commit`, { method: "POST", body: { ...body(), uploaded_by: uploadedBy } });
    setDone(r);
    qc.invalidateQueries();
    toast.success(kind === "vulns" ? `Scan imported · ${fmtN(r.new)} new, ${fmtN(r.fixed)} fixed` : kind === "niam" ? `NIAM dump imported · ${fmtN(r.rows)} nodes` : GENERIC(kind) ? r.message : `${fmtN(r.added)} old agents imported`);
  });

  const required = (parsed?.fields || []).filter((f: any) => f.required);
  const ok = kind === "vulns" ? required.every((f: any) => mapping[f.key]) && !!lob
    : kind === "niam" || GENERIC(kind) ? required.every((f: any) => mapping[f.key]) : ["aid", "hostname", "local_ip"].some((k) => mapping[k]);
  const sample = (h: string) => {
    if (!parsed || !h) return "";
    const i = parsed.headers.indexOf(h);
    return parsed.sample.map((r: string[]) => r[i]).filter(Boolean).slice(0, 2).join(" · ");
  };

  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={<span className="flex items-center gap-2">{kind === "vulns" || kind === "sod" ? <ShieldAlert className="size-4" /> : kind === "niam" ? <Radio className="size-4" /> : <FileSpreadsheet className="size-4" />}{t.title}</span>}
      footer={done ? <Button variant="primary" onClick={() => onOpenChange(false)}>Close</Button> : <>
        <Button onClick={() => onOpenChange(false)}>Cancel</Button>
        {parsed && !preview && <Button variant="primary" loading={busy} disabled={!ok} onClick={doPreview}>Check</Button>}
        {preview && <Button variant="primary" loading={busy} onClick={doCommit}><Check /> {t.commit}</Button>}
      </>}>
      {done ? (
        <div className="py-8 text-center">
          <div className="mx-auto mb-3 grid size-12 place-items-center rounded-full bg-good-soft"><Check className="size-6 text-good-fg" /></div>
          {kind === "vulns" ? (
            <>
              <div className="text-[17px] font-semibold">Scan imported · {fmtN(done.hosts)} hosts</div>
              <div className="mt-1 text-muted">{fmtN(done.new)} new · {fmtN(done.still_open)} still open · {fmtN(done.reopened)} reopened · <span className="text-good-fg">{fmtN(done.fixed)} fixed</span> · scan date {fmtDt(done.scan_date)}</div>
            </>
          ) : GENERIC(kind) ? (
            <div className="text-[17px] font-semibold">{done.message}</div>
          ) : kind === "niam" ? (
            <>
              <div className="text-[17px] font-semibold">NIAM dump imported · {fmtN(done.rows)} nodes</div>
              <div className="mt-1 text-muted">{fmtN(done.added)} new · {fmtN(done.changed)} changed · {fmtN(done.removed)} dropped from the dump</div>
            </>
          ) : (
            <>
              <div className="text-[17px] font-semibold">{fmtN(done.added)} old agents imported</div>
              <div className="mt-1 text-muted">{fmtN(done.live_now)} are live in the console (skipped) · {fmtN(done.known)} were already known</div>
            </>
          )}
        </div>
      ) : (
        <>
          <Callout className="mb-4">{t.help}</Callout>
          <div className="mb-4 grid gap-3 md:grid-cols-3">
            {kind === "vulns" && (
              <Field label="LOB">
                <Select className="max-w-none" value={lob} onChange={(v) => { setLob(v); setPreview(null); }} placeholder="Choose a LOB…" options={(meta?.lobs || []).map((l) => ({ value: l.id, label: l.name }))} />
              </Field>
            )}
            <Field label="Note (optional)"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder={kind === "vulns" ? "e.g. Monthly Nessus scan – Sep" : kind === "niam" ? "e.g. NIAM export 25 Sep" : kind === "sod" ? "e.g. SOD register Q3" : kind === "comm" ? "e.g. Matrix after CR-2026-1102" : kind === "ndr" ? "e.g. Seceon alerts week 39" : "e.g. Export from 2025 console"} /></Field>
          </div>
          {!parsed ? (
            <div onClick={() => fileRef.current?.click()} onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files[0]); }}
              className={cn("cursor-pointer rounded-2xl border-2 border-dashed px-6 py-12 text-center transition-colors", drag ? "border-accent bg-accent-soft" : "border-border-strong bg-surface-2 hover:border-accent")}>
              {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
              <div className="mt-3 text-[15px] font-semibold">{t.drop}</div>
              <div className="mt-1 text-xs text-muted">.xlsx, .xlsm or .csv · header row detected automatically</div>
              <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
            </div>
          ) : (
            <div className={busy ? "pointer-events-none opacity-60" : ""}>
              <div className="mb-3 flex flex-wrap items-end gap-3">
                <div className="flex items-center gap-2 rounded-lg bg-surface-2 px-3 py-2 text-[13px]"><FileSpreadsheet className="size-4 text-good" /><b>{parsed.filename}</b><span className="text-muted">· {fmtN(parsed.row_count)} rows</span></div>
                {parsed.sheets.length > 1 && <Field label="Sheet"><Select value={parsed.sheet} onChange={(v) => reparse({ sheet: v })} options={parsed.sheets} /></Field>}
                <Field label="Header row"><Input type="number" min={1} className="w-20" value={parsed.header_row} onChange={(e) => e.target.value && reparse({ header_row: +e.target.value })} /></Field>
                <Button size="sm" variant="ghost" onClick={() => { setParsed(null); setPreview(null); }}>Choose another file</Button>
              </div>
              {!preview ? (
                <div className="overflow-hidden rounded-xl border border-border">
                  <table className="w-full text-[12.8px]">
                    <thead><tr className="bg-surface-2 text-left text-xs text-fg-2"><th className="px-3 py-2">Field</th><th className="px-3 py-2">Column in your file</th><th className="px-3 py-2">Sample</th></tr></thead>
                    <tbody>
                      {parsed.fields.map((f: any) => (
                        <tr key={f.key} className="border-t border-border">
                          <td className="px-3 py-1.5 font-medium">{f.label}{f.required && <span className="ml-1 text-crit-fg">*</span>}</td>
                          <td className="px-3 py-1">
                            <select className={cn("h-8 w-full rounded-md border bg-surface px-2", mapping[f.key] ? "border-good" : "border-border-strong")}
                              value={mapping[f.key] || ""} onChange={(e) => setMapping({ ...mapping, [f.key]: e.target.value })}>
                              <option value="">— not mapped —</option>
                              {parsed.headers.map((h: string) => <option key={h} value={h}>{h}</option>)}
                            </select>
                          </td>
                          <td className="max-w-[320px] truncate px-3 py-1.5 text-xs text-muted">{sample(mapping[f.key])}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : kind === "vulns" ? (
                <div>
                  {preview.first_scan && <Callout className="mb-3">First scan for this LOB — every finding will be new.</Callout>}
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
                    {[["Findings", preview.rows, ""], ["Hosts", preview.hosts, ""], ["New", preview.new, "text-accent-fg"], ["Still open", preview.still_open, ""],
                      ["Reopened", preview.reopened, "text-serious-fg"], ["Fixed", preview.fixed, "text-good-fg"]].map(([l, n, cl]) => (
                      <div key={l as string} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                        <div className="text-[11.5px] text-muted">{l}</div>
                        <div className={cn("text-[22px] font-semibold tabular", cl as string)}>{fmtN(n)}</div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 flex flex-wrap gap-3 text-[13px]">
                    {["Critical", "High", "Medium", "Low", "Info"].map((s) => <span key={s} className="flex items-center gap-1.5"><SeverityBadge s={s} /> {fmtN(preview.severity[s] || 0)}</span>)}
                    <span className="ml-auto text-muted">Scan date {fmtDt(preview.scan_date)}</span>
                  </div>
                  {preview.warnings?.length > 0 && <Callout tone="warn" className="mt-3">{preview.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
                  <div className="mt-3 overflow-hidden rounded-xl border border-border">
                    <SimpleTable rows={preview.sample} maxHeight="30vh" columns={[
                      { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip}</Mono> }, { key: "severity", label: "Severity", render: (r: any) => <SeverityBadge s={r.severity} /> },
                      { key: "name", label: "Vulnerability" }, { key: "port", label: "Port" }, { key: "plugin_id", label: "Plugin" }]} />
                  </div>
                </div>
              ) : GENERIC(kind) ? (
                <div>
                  {preview.note && <Callout className="mb-3">{preview.note}</Callout>}
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
                    {preview.stats.map(([l, n, tone]: [string, number, string]) => (
                      <div key={l} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                        <div className="text-[11.5px] text-muted">{l}</div>
                        <div className={cn("text-[22px] font-semibold tabular", { good: "text-good-fg", crit: "text-crit-fg", warn: "text-warn-fg", info: "text-accent-fg" }[tone] || "")}>{fmtN(n)}</div>
                      </div>
                    ))}
                  </div>
                  {preview.warnings?.length > 0 && <Callout tone="warn" className="mt-3">{preview.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
                  <div className="mt-3 overflow-hidden rounded-xl border border-border">
                    <SimpleTable rows={preview.sample} maxHeight="30vh" columns={preview.sample_cols.map(([k, l]: [string, string]) => ({ key: k, label: l }))} />
                  </div>
                </div>
              ) : kind === "niam" ? (
                <div>
                  {preview.first && <Callout className="mb-3">First NIAM dump — every node will be new.</Callout>}
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                    {[["Nodes in file", preview.rows, ""], ["New", preview.added, "text-accent-fg"], ["Changed", preview.changed, "text-warn-fg"], ["Dropped (not in this dump)", preview.removed, "text-crit-fg"],
                      ["Distinct NE IDs", preview.ne_ids, ""], ["In an LOB inventory", preview.in_inventory, "text-good-fg"], ["With a live EDR agent", preview.with_edr, "text-good-fg"], ["IPv6 hosts", preview.ipv6, ""]].map(([l, n, cl]) => (
                      <div key={l as string} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                        <div className="text-[11.5px] text-muted">{l}</div>
                        <div className={cn("text-[22px] font-semibold tabular", cl as string)}>{fmtN(n)}</div>
                      </div>
                    ))}
                  </div>
                  {preview.warnings?.length > 0 && <Callout tone="warn" className="mt-3">{preview.warnings.map((w: string) => <div key={w}>{w}</div>)}</Callout>}
                  <div className="mt-3 overflow-hidden rounded-xl border border-border">
                    <SimpleTable rows={preview.sample} maxHeight="30vh" columns={[
                      { key: "ne_id", label: "NE ID", render: (r: any) => <b>{r.ne_id}</b> }, { key: "host", label: "Host (as in file)", render: (r: any) => <Mono>{r.host}</Mono> },
                      { key: "ip", label: "Normalised IP", render: (r: any) => r.ip ? <Mono>{r.ip}</Mono> : <span className="text-muted">not an IP — matched by name</span> }]} />
                  </div>
                </div>
              ) : (
                <div>
                  <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                    {[["Agents in file", preview.rows, ""], ["Will be imported", preview.new, "text-accent-fg"], ["Live in console (skipped)", preview.live_now, "text-good-fg"], ["Already known", preview.known, ""]].map(([l, n, cl]) => (
                      <div key={l as string} className="rounded-xl border border-border bg-surface-2 px-3 py-2.5">
                        <div className="text-[11.5px] text-muted">{l}</div>
                        <div className={cn("text-[22px] font-semibold tabular", cl as string)}>{fmtN(n)}</div>
                      </div>
                    ))}
                  </div>
                  {preview.reinstalled > 0 && <Callout className="mt-3">{fmtN(preview.reinstalled)} of the imported agents have a live agent today with the same hostname or IP (reinstalled with a new AID).</Callout>}
                  <div className="mt-3 overflow-hidden rounded-xl border border-border">
                    <SimpleTable rows={preview.sample} maxHeight="30vh" empty="Nothing new to import" columns={[
                      { key: "hostname", label: "Hostname" }, { key: "local_ip", label: "IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
                      { key: "aid", label: "Agent ID", render: (r: any) => <Mono>{r.aid.startsWith("import-") ? "— (none in file)" : r.aid}</Mono> },
                      { key: "os_version", label: "OS" }, { key: "last_seen", label: "Last seen", render: (r: any) => fmtDt(r.last_seen) }]} />
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
