"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileSpreadsheet, Radar, Search, Trash2, UploadCloud } from "lucide-react";
import { api, apiUpload } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Field, FilterSelect, Input, Kpi, KpiGrid, Loading, Modal, PageHeader, SearchInput, Select, Spinner, useConfirm } from "@/components/ui";
import { ClassBadge, ClassifyBar, WhoisCell, WhoisFilters } from "@/components/whois";
import { DataTable, type Column } from "@/components/data-table";
import { Mono } from "@/components/badges";

export function PortChips({ ports }: { ports: number[] }) {
  if (!ports?.length) return <span className="text-muted">none</span>;
  const risky = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 161]);
  return (
    <span className="flex max-w-[260px] flex-wrap gap-1">
      {ports.map((p) => <span key={p} className={cn("rounded-md border px-1.5 py-px font-mono text-[11px]", risky.has(p) ? "border-crit/40 bg-crit-soft text-crit-fg" : "border-border bg-surface-2 text-fg-2")}>{p}</span>)}
    </span>
  );
}

export function CveChips({ vulns, max = 4 }: { vulns: string[]; max?: number }) {
  if (!vulns?.length) return <span className="text-muted">none</span>;
  return (
    <span className="flex max-w-[300px] flex-wrap gap-1" title={vulns.join(", ")}>
      {vulns.slice(0, max).map((v) => <Badge key={v} tone="serious">{v}</Badge>)}
      {vulns.length > max && <span className="text-[11px] text-muted">+{vulns.length - max}</span>}
    </span>
  );
}

/** Passive internet scan (Shodan InternetDB): one IP now, an Excel of IPs, or assets selected on All inventory. */
export default function PassiveScan() {
  const qc = useQueryClient();
  const [state, set, replaceAll] = useUrlState();
  const [ip, setIp] = React.useState("");
  const [one, setOne] = React.useState<any[] | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [upload, setUpload] = React.useState(false);
  const [sel, setSel] = React.useState<Set<string>>(new Set());
  const [total, setTotal] = React.useState(0);
  const confirm = useConfirm();
  const st = useQuery({ queryKey: ["passive-status"], queryFn: () => api<any>("/api/passive/status"),
    refetchInterval: (q) => ((q.state.data as any)?.job?.running ? 1200 : false) });
  const wasRunning = React.useRef(false);
  React.useEffect(() => {
    const r = !!st.data?.job?.running;
    if (wasRunning.current && !r) { toast.success(`Passive scan finished · ${st.data?.job?.message}`); qc.invalidateQueries({ queryKey: ["/api/passive/results"] }); }
    wasRunning.current = r;
  }, [st.data, qc]);
  if (!st.data) return <Loading error={st.error} retry={() => st.refetch()} />;
  const s = st.data.summary, job = st.data.job;
  const delJob = async (j: any) => {
    if (!(await confirm({ title: `Delete scan job “${j.note || j.source}”?`, body: `Removes the ${fmtN(j.kept ?? 0)} results this scan found that no later scan replaced. IPs that only this scan knew leave the Attack surface.`, ok: "Delete", danger: true }))) return;
    try { const r = await api<any>(`/api/passive/jobs/${j.id}`, { method: "DELETE" }); toast.success(`Deleted · ${fmtN(r.deleted)} results removed`); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };
  const delSelected = async () => {
    if (!(await confirm({ title: `Delete ${fmtN(sel.size)} results?`, body: "The selected IPs' scan results are removed. IPs that only the scan knew leave the Attack surface.", ok: "Delete", danger: true }))) return;
    try { const r = await api<any>("/api/passive/results/delete", { method: "POST", body: { ips: [...sel] } }); toast.success(`${fmtN(r.deleted)} results deleted`); setSel(new Set()); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };
  const scanOne = async () => {
    if (!ip.trim()) return;
    setBusy(true); setOne(null);
    try {
      const r = await api<any>("/api/passive/scan-one", { method: "POST", body: { ip: ip.trim() } });
      setOne(r.rows);
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const cols: Column[] = [
    { key: "ip", label: "Public IP", render: (r) => <Link className="font-mono text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.asset_ip || r.ip)}`}>{r.ip}</Link> },
    { key: "asset", label: "Asset", render: (r) => <span>{r.asset_name || <span className="text-muted">–</span>}{r.asset_ip && <span className="block font-mono text-[11px] text-muted">behind NAT: {r.asset_ip}</span>}</span> },
    { key: "lobs", label: "LOB", render: (r) => r.lobs || <span className="text-muted">–</span> },
    { key: "status", label: "Result", render: (r) => r.status === "error" ? <Badge tone="crit" title={r.error}>error</Badge> : r.status === "none" ? <Badge>no data</Badge>
      : r.ports.length ? <Badge tone="crit">{r.ports.length} open port{r.ports.length > 1 ? "s" : ""}</Badge> : <Badge tone="good">nothing open</Badge> },
    { key: "ports", label: "Open ports", wrap: true, render: (r) => <PortChips ports={r.ports} /> },
    { key: "vulns", label: "CVEs", wrap: true, render: (r) => <CveChips vulns={r.vulns} /> },
    { key: "cpes", label: "Software", wrap: true, render: (r) => <span className="text-[11.5px] text-fg-2">{r.cpes.map((c: string) => c.replace(/^cpe:\/[aoh]:/, "")).join(", ") || "–"}</span> },
    { key: "whois", label: "WHOIS", wrap: true, render: (r) => <WhoisCell r={r} /> },
    { key: "cls", label: "Class", render: (r) => <ClassBadge c={r.cls} /> },
    { key: "hostnames", label: "Hostnames", wrap: true, hidden: true, render: (r) => <span className="text-[11.5px]">{r.hostnames.join(", ") || "–"}</span> },
    { key: "tags", label: "Tags", hidden: true, render: (r) => r.tags.join(", ") || "–" },
    { key: "scanned_at", label: "Looked up", render: (r) => <span title={fmtDt(r.scanned_at)}>{fmtRel(r.scanned_at)}</span> },
  ];
  return (
    <div>
      <PageHeader title="Internet DB scan (passive)"
        sub="What the internet already sees on your public IPs: open ports, known CVEs, software, hostnames and tags from Shodan InternetDB. Passive: nothing is sent to the assets; only the public IP is sent to Shodan. Private IPs are looked up through their public / NAT IP."
        actions={<>
          <Button onClick={() => setUpload(true)}><FileSpreadsheet /> Scan an Excel file</Button>
          <Link href="/inventory/"><Button><Radar /> Select from All inventory</Button></Link>
        </>} />
      {st.data.demo && <Callout tone="info" className="mb-4">Sample data mode: InternetDB answers are simulated.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Public IPs looked up" value={s.ips} tone="info" foot={s.last ? `last ${fmtRel(s.last)}` : "none yet"} active={!state.show} onClick={() => replaceAll({})} />
        <Kpi label="With open ports" value={s.with_ports} tone="crit" foot="seen from the internet" active={state.show === "ports"} onClick={() => replaceAll({ show: "ports" })} />
        <Kpi label="With known CVEs" value={s.with_vulns} tone="serious" active={state.show === "vulns"} onClick={() => replaceAll({ show: "vulns" })} />
        <Kpi label="Errors" value={s.errors} foot="retry later" active={state.show === "error"} onClick={() => replaceAll({ show: "error" })} />
      </KpiGrid>
      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={<span className="flex items-center gap-2"><Search className="size-4" /> Scan one IP now</span>} hint="public IP, or a private IP with a known public / NAT IP" />
          <div className="flex gap-2 px-4 pb-3">
            <Input className="flex-1" placeholder="e.g. 203.0.113.10 or 10.10.0.16" value={ip} onChange={(e) => setIp(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scanOne()} />
            <Button variant="primary" loading={busy} onClick={scanOne}>Scan</Button>
          </div>
          {one && <div className="space-y-2 px-4 pb-4">{one.map((r) => (
            <div key={r.ip} className="rounded-xl border border-border p-3 text-[12.5px]">
              <div className="flex flex-wrap items-center gap-2"><Mono>{r.ip}</Mono>{r.asset_ip && <span className="text-muted">NAT of {r.asset_ip}{r.asset_name ? ` (${r.asset_name})` : ""}</span>}
                <span className="ml-auto">{r.status === "none" ? <Badge>InternetDB has no data</Badge> : r.status === "error" ? <Badge tone="crit">{r.error}</Badge> : null}</span></div>
              {r.status === "ok" && <div className="mt-2 grid grid-cols-[90px_1fr] gap-y-1.5">
                <span className="text-muted">Open ports</span><PortChips ports={r.ports} />
                <span className="text-muted">CVEs</span><CveChips vulns={r.vulns} max={12} />
                <span className="text-muted">Software</span><span className="text-[11.5px]">{r.cpes.join(", ") || "–"}</span>
                <span className="text-muted">Hostnames</span><span className="text-[11.5px]">{r.hostnames.join(", ") || "–"}</span>
              </div>}
            </div>))}</div>}
        </Card>
        <Card>
          <CardHeader title="Scan jobs" hint="selections from All inventory and Excel uploads run in the background" />
          <div className="space-y-2 px-4 pb-4">
            {job.running && (
              <div className="rounded-xl border border-accent/40 bg-accent-soft/40 p-3 text-[12.5px]">
                <div className="flex items-center gap-2 font-medium"><Spinner className="size-4" /> Scanning · {fmtN(job.done)} of {fmtN(job.total)}</div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-3"><div className="h-full bg-accent transition-all" style={{ width: `${(100 * job.done) / Math.max(1, job.total)}%` }} /></div>
              </div>
            )}
            {!st.data.jobs.length && !job.running && <div className="text-[12.5px] text-muted">No scan jobs yet.</div>}
            <div className="max-h-64 space-y-2 overflow-auto">
            {st.data.jobs.map((j: any) => (
              <div key={j.id} className={cn("flex flex-wrap items-center gap-2 rounded-lg border px-3 py-2 text-[12.5px]", state.job === String(j.id) ? "border-accent bg-accent-soft/40" : "border-border")}>
                <Badge tone="info">{j.source}</Badge><span className="truncate font-mono text-[12px]">{j.note}</span>
                <span className="ml-auto">{fmtN(j.done ?? 0)} / {fmtN(j.total)} · <b className="text-crit-fg">{fmtN(j.found ?? 0)}</b> with ports{j.skipped?.length ? ` · ${j.skipped.length} skipped` : ""}</span>
                <span className="text-[11.5px] text-muted">{fmtRel(j.started_at)}</span>
                <Button size="sm" variant="ghost" title="show this scan's results" onClick={() => replaceAll(state.job === String(j.id) ? {} : { job: String(j.id) })}>{state.job === String(j.id) ? "All results" : `Results (${fmtN(j.kept ?? 0)})`}</Button>
                <Button size="sm" variant="ghost" title="delete this scan and its results" disabled={job.running && job.id === j.id} onClick={() => delJob(j)}><Trash2 className="size-3.5" /></Button>
              </div>
            ))}
            </div>
          </div>
        </Card>
      </div>
      <ClassifyBar path="/api/passive/classify" filter={state} selected={sel} total={total} onDone={() => setSel(new Set())} />
      <DataTable endpoint="/api/passive/results" exportPath="/api/passive/results/export" state={state} setState={set} noun="public IPs" storageKey="passive"
        rowKey={(r: any) => r.ip} onReset={() => replaceAll({})} sortable={false} columns={cols} selected={sel} onSelectedChange={setSel}
        onData={(d: any) => setTotal(d.total)}
        toolbar={sel.size > 0 && <Button size="sm" variant="danger" onClick={delSelected}><Trash2 /> Delete {fmtN(sel.size)}</Button>}
        filters={<>
          <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, asset, CVE, hostname…" />
          <FilterSelect label="Show" value={state.show} onChange={(v) => set({ show: v })} any="All" options={[["ports", "Open ports"], ["vulns", "Known CVEs"], ["none", "No data"], ["error", "Errors"]]} />
          <Input className="w-28" placeholder="Port e.g. 3389" value={state.port || ""} onChange={(e) => set({ port: e.target.value.replace(/\D/g, "") })} />
          <WhoisFilters facetsPath="/api/passive/whois-facets" state={state} set={set} />
          {state.job && <Badge tone="info">scan #{state.job}<button className="ml-1" onClick={() => set({ job: undefined })}>×</button></Badge>}
        </>} />
      {upload && <UploadScan onClose={() => { setUpload(false); st.refetch(); }} />}
    </div>
  );
}

function UploadScan({ onClose }: { onClose: () => void }) {
  const [info, setInfo] = React.useState<any>(null);
  const [token, setToken] = React.useState("");
  const [col, setCol] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);
  const read = async (tok: string, sheet?: string) => {
    const r = await api<any>("/api/passive/upload/columns", { method: "POST", body: { token: tok, sheet } });
    setInfo(r); setCol(r.column || "");
  };
  const onFile = async (f?: File) => {
    if (!f) return;
    setBusy(true);
    try {
      const fd = new FormData(); fd.append("file", f);
      const up = await apiUpload<any>("/api/uploads", fd, () => {});
      setToken(up.token);
      await read(up.token);
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const start = async () => {
    setBusy(true);
    try {
      const r = await api<any>("/api/passive/upload", { method: "POST", body: { token, sheet: info.sheet, column: col || null } });
      toast.success(`Scanning ${fmtN(r.targets)} public IPs from the file${r.skipped?.length ? ` · ${r.skipped.length} skipped (private, no public IP)` : ""}`);
      onClose();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title="Scan the IPs of an Excel file"
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} disabled={!info} onClick={start}><Radar /> Start scan</Button></>}>
      {!info ? (
        <div onClick={() => fileRef.current?.click()} className="cursor-pointer rounded-2xl border-2 border-dashed border-border-strong bg-surface-2 px-6 py-10 text-center hover:border-accent">
          {busy ? <Spinner className="mx-auto size-8" /> : <UploadCloud className="mx-auto size-10 text-muted" />}
          <div className="mt-2 font-semibold">Drop or choose an .xlsx / .csv with IPs</div>
          <div className="text-xs text-muted">any layout: pick the column with the IPs (or search every cell)</div>
          <input ref={fileRef} type="file" accept=".xlsx,.xlsm,.csv,.txt" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
        </div>
      ) : (
        <div className="space-y-3 text-[13px]">
          <div className="flex items-center gap-2 rounded-lg bg-surface-2 px-3 py-2"><FileSpreadsheet className="size-4 text-good" /><b>{info.filename}</b><span className="text-muted">· {fmtN(info.row_count)} rows</span></div>
          {info.sheets.length > 1 && <Field label="Sheet"><Select className="max-w-none" value={info.sheet} onChange={(v) => read(token, v)} options={info.sheets} /></Field>}
          <Field label="Column with the IPs">
            <Select className="max-w-none" value={col} onChange={setCol} placeholder="Search every cell"
              options={info.headers.map((h: string) => ({ value: h, label: `${h}${info.ip_counts[h] ? ` (${fmtN(info.ip_counts[h])} IPs)` : ""}` }))} />
          </Field>
          <div className="text-[12px] text-muted">Public IPs are looked up as they are; private IPs through the public / NAT IP the console knows for them. Lists, ranges and shorthand in a cell are split.</div>
        </div>
      )}
    </Modal>
  );
}
