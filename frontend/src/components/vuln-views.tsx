"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, Upload } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Button, Callout, Card, CardHeader, KV, Kpi, KpiGrid, Loading, SearchInput, Segmented, Select, Sheet, SectionTitle } from "./ui";
import { DataTable, SimpleTable } from "./data-table";
import { EdrBadge, HostLink, Mono, SevCounts, SeverityBadge } from "./badges";
import { MappedUpload } from "./mapped-upload";

const EDR_OPTS: [string, string][] = [["Online", "EDR online"], ["Offline", "EDR offline"], ["Not Installed", "No EDR"]];

/** Summary + hosts / findings / scans for all LOBs (lobId undefined) or one LOB. */
export function VulnPanel({ lobId, state, set, replaceAll, tabKey = "vtab" }: {
  lobId?: number; state: Record<string, string>; set: any; replaceAll: (o: Record<string, string>) => void; tabKey?: string;
}) {
  const { data: meta } = useMeta();
  const lob = lobId ? String(lobId) : state.lob || "";
  const { data: s, error: sErr, refetch: sRetry } = useQuery({ queryKey: ["vuln-summary", lob], queryFn: () => api<any>("/api/vulns/summary", { params: { lob } }) });
  const [upload, setUpload] = React.useState(false);
  const [finding, setFinding] = React.useState<number | null>(null);
  const view = state[tabKey] || "hosts";
  const keep: Record<string, string> = lobId ? { id: String(lobId), tab: state.tab || "vulns" } : state.lob ? { lob: state.lob } : {};
  const go = (patch: Record<string, string>) => replaceAll({ ...keep, [tabKey]: view, ...patch });
  if (!s) return <Loading error={sErr} retry={() => sRetry()} />;
  const sev = s.severity, a = s.assets;
  const fixed = lobId ? { lob: String(lobId) } : undefined;

  return (
    <div>
      {!a.scanned && (
        <Card className="mb-4 flex flex-wrap items-center gap-4 p-6">
          <div className="grid size-11 place-items-center rounded-xl bg-crit-soft text-crit-fg"><ShieldAlert className="size-5" /></div>
          <div className="min-w-0 flex-1">
            <div className="text-[15px] font-semibold">No vulnerability scans yet</div>
            <div className="text-[12.5px] text-muted">Upload a Nessus export for a LOB — findings are matched to its inventory, MSPs and Falcon agents.</div>
          </div>
          <Button variant="primary" onClick={() => setUpload(true)}><Upload /> Upload scan</Button>
        </Card>
      )}
      {a.scanned > 0 && (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
            {fmtN(a.scanned)} scanned hosts · last scan {a.last_scan ? `${fmtDt(a.last_scan)} (${fmtRel(a.last_scan)})` : "–"}
            <Button size="sm" className="ml-auto" onClick={() => setUpload(true)}><Upload /> Upload scan</Button>
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            {([["Critical", sev.crit, "var(--crit)"], ["High", sev.high, "var(--serious)"], ["Medium", sev.med, "var(--warn)"], ["Low", sev.low, "var(--s1)"]] as const).map(([l, n, c]) => (
              <button key={l} onClick={() => go({ [tabKey]: "findings", severity: l })}
                className="rounded-xl border border-border bg-surface p-4 text-left shadow-card transition-colors hover:border-accent">
                <div className="flex items-center gap-1.5 text-[12px] font-medium text-fg-2"><span className="size-2 rounded-full" style={{ background: c }} />{l}</div>
                <div className="mt-1 text-[28px] font-semibold leading-none tabular" style={{ color: n ? c : undefined }}>{fmtN(n)}</div>
                <div className="mt-1 text-[11px] text-muted">open findings</div>
              </button>
            ))}
            <button onClick={() => go({ [tabKey]: "hosts", in_inventory: "0" })}
              className="rounded-xl border border-border bg-surface p-4 text-left shadow-card transition-colors hover:border-accent">
              <div className="text-[12px] font-medium text-fg-2">Scanned, not in inventory</div>
              <div className="mt-1 text-[28px] font-semibold leading-none tabular text-violet-fg">{fmtN(a.not_in_inventory)}</div>
              <div className="mt-1 text-[11px] text-muted">IPs in a scan, in no inventory</div>
            </button>
          </div>

          {!lobId && s.by_lob.length > 0 && (
            <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
              <Card>
                <CardHeader title="By LOB / MSP" hint="open findings on scanned hosts" />
                <SimpleTable rows={s.by_msp} maxHeight="300px" columns={[
                  { key: "lob", label: "LOB", render: (r: any) => <Link className="font-semibold hover:underline" href={`/lob/?id=${r.lob_id}&tab=vulns`}>{r.lob}</Link> },
                  { key: "msp", label: "MSP" },
                  { key: "sev", label: "Crit / High / Med / Low", render: (r: any) => <SevCounts c={r.crit} h={r.high} m={r.med} l={r.low} /> },
                  { key: "vulnerable", label: "Vulnerable hosts", num: true, render: (r: any) => `${fmtN(r.vulnerable)} / ${fmtN(r.scanned)}` },
                  { key: "crit_high_no_edr", label: "Crit/High no EDR", num: true, render: (r: any) => r.crit_high_no_edr ? <b className="text-crit-fg">{fmtN(r.crit_high_no_edr)}</b> : "0" },
                  { key: "last_scan", label: "Last scan", render: (r: any) => fmtDt(r.last_scan) },
                ]} />
              </Card>
              <Card>
                <CardHeader title="Most widespread findings" hint="medium and above" />
                <SimpleTable rows={s.top} maxHeight="300px" onRowClick={(r: any) => go({ [tabKey]: "findings", q: r.plugin_id || r.name })} columns={[
                  { key: "severity", label: "Severity", render: (r: any) => <SeverityBadge s={r.severity} /> },
                  { key: "name", label: "Vulnerability", wrap: true },
                  { key: "hosts", label: "Hosts", num: true },
                ]} />
              </Card>
            </div>
          )}

          <div className="mt-5 mb-3 flex items-center gap-3">
            <Segmented value={view} onChange={(v) => go({ [tabKey]: v })} options={[["hosts", "By host"], ["findings", "Findings"], ["scans", "Scan history"]]} />
          </div>
          {view === "hosts" && <HostsTable state={state} set={set} fixed={fixed} reset={() => go({})} showLob={!lobId} lobId={lobId} meta={meta} />}
          {view === "findings" && <FindingsTable state={state} set={set} fixed={fixed} reset={() => go({})} showLob={!lobId} lobId={lobId} meta={meta} onOpen={setFinding} />}
          {view === "scans" && (
            <Card>
              <SimpleTable rows={s.scans} empty="No scans yet" columns={[
                ...(!lobId ? [{ key: "lob", label: "LOB" }] : []),
                { key: "uploaded_at", label: "Uploaded", render: (r: any) => <span>{fmtDt(r.uploaded_at)} <span className="text-xs text-muted">{r.uploaded_by}</span></span> },
                { key: "scan_date", label: "Scan date", render: (r: any) => fmtDt(r.scan_date) },
                { key: "filename", label: "File" }, { key: "note", label: "Note", wrap: true },
                { key: "hosts", label: "Hosts", num: true }, { key: "rows", label: "Findings", num: true },
                { key: "delta", label: "Changes", render: (r: any) => <span className="tabular"><span className="text-accent-fg">+{fmtN(r.new_findings)} new</span> · <span className="text-good-fg">{fmtN(r.fixed_findings)} fixed</span> · {fmtN(r.reopened)} reopened</span> },
              ]} />
            </Card>
          )}
        </>
      )}
      {upload && <MappedUpload kind="vulns" lobId={lobId} open onOpenChange={setUpload} />}
      {finding !== null && <FindingSheet id={finding} onClose={() => setFinding(null)} />}
    </div>
  );
}

/** One "Show only…" select instead of toggle chips: [url key, value, label]. */
export function ShowOnly({ state, set, flags }: { state: Record<string, string>; set: any; flags: [string, string, string][] }) {
  const cur = flags.find(([k, v]) => state[k] === v);
  return (
    <Select value={cur ? `${cur[0]}=${cur[1]}` : ""} placeholder="Show only…" options={flags.map(([k, v, l]) => [`${k}=${v}`, l] as [string, string])}
      onChange={(x) => {
        const [k, v] = (x || "").split("=");
        set({ ...Object.fromEntries(flags.map(([f]) => [f, undefined])), ...(x ? { [k]: v } : {}) });
      }} />
  );
}

function MspFilter({ lobId, state, set, meta }: { lobId?: number; state: Record<string, string>; set: any; meta: any }) {
  const lid = lobId || (state.lob ? +state.lob : 0);
  const msps = (meta?.msps || []).filter((m: any) => !lid || m.lob_id === lid);
  return <Select value={state.msp} onChange={(v) => set({ msp: v })} placeholder="All MSPs" options={[...msps.map((m: any) => ({ value: m.id, label: m.name })), { value: "none", label: "Unassigned" }]} />;
}

function HostsTable({ state, set, fixed, reset, showLob, lobId, meta }: any) {
  return (
    <DataTable endpoint="/api/vulns/assets" exportPath="/api/vulns/assets/export" state={state} setState={set} fixed={fixed}
      omit={["tab", "id", "vtab", "severity", "status"]} noun="scanned hosts" storageKey="vassets" rowKey={(r: any) => `${r.lob_id}|${r.ip}`} onReset={reset}
      columns={[
        ...(showLob ? [{ key: "lob", label: "LOB", render: (r: any) => <b>{r.lob}</b> }] : []),
        { key: "ip", label: "IP", render: (r: any) => <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${r.ip}`}>{r.ip}</Link> },
        { key: "hostname", label: "Host", sort: false, render: (r: any) => r.aid ? <HostLink aid={r.aid}>{r.hostname || r.node_name}</HostLink> : <span>{r.node_name || <span className="text-muted">–</span>}</span> },
        { key: "msp", label: "MSP", render: (r: any) => r.msp || <span className="text-muted">Unassigned</span> },
        { key: "edr_status", label: "EDR", render: (r: any) => <EdrBadge s={r.edr_status} /> },
        { key: "total", label: "Crit / High / Med / Low", render: (r: any) => <SevCounts c={r.crit} h={r.high} m={r.med} l={r.low} /> },
        { key: "in_inventory", label: "Inventory", sort: false, render: (r: any) => r.in_inventory ? "Yes" : <span className="text-violet-fg">Not in inventory</span> },
        { key: "node_type", label: "Node type", sort: false },
        { key: "last_scanned_at", label: "Last scan", render: (r: any) => <span title={r.last_scanned_at}>{fmtDt(r.last_scanned_at)} <span className="text-xs text-muted">{fmtRel(r.last_scanned_at)}</span></span> },
        { key: "fixed", label: "Fixed", num: true, sort: false, hidden: true },
      ]}
      filters={<>
        <SearchInput className="w-64" value={state.q || ""} onChange={(v: string) => set({ q: v })} placeholder="IP, hostname, node… (paste many)" />
        {showLob && <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />}
        <MspFilter lobId={lobId} state={state} set={set} meta={meta} />
        <Select value={state.edr_status} onChange={(v) => set({ edr_status: v })} placeholder="Any EDR status" options={EDR_OPTS} />
        <Select value={state.min_sev} onChange={(v) => set({ min_sev: v })} placeholder="Any severity" options={[["4", "Has critical"], ["3", "Has critical or high"]]} />
        <Select value={state.stale_scan} onChange={(v) => set({ stale_scan: v })} placeholder="Any scan age" options={[["30", "Not scanned in 30 days"], ["60", "Not scanned in 60 days"], ["90", "Not scanned in 90 days"]]} />
        <ShowOnly state={state} set={set} flags={[["vulnerable", "1", "With open findings"], ["no_edr", "1", "No active EDR"], ["in_inventory", "0", "Not in inventory"]]} />
      </>} />
  );
}

function FindingsTable({ state, set, fixed, reset, showLob, lobId, meta, onOpen }: any) {
  return (
    <DataTable endpoint="/api/vulns/findings" exportPath="/api/vulns/findings/export" state={state} setState={set} fixed={fixed}
      omit={["tab", "id", "vtab", "vulnerable", "stale_scan", "in_inventory"]} noun="findings" storageKey="vfindings" rowKey={(r: any) => String(r.id)} onReset={reset}
      onRowClick={(r: any) => onOpen(r.id)}
      columns={[
        { key: "severity", label: "Severity", render: (r: any) => <SeverityBadge s={r.severity} /> },
        { key: "name", label: "Vulnerability", render: (r: any) => <span className="font-medium">{r.name}</span> },
        { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip}</Mono> },
        { key: "host", label: "Host", sort: false, render: (r: any) => r.aid ? <HostLink aid={r.aid}>{r.hostname || r.node_name}</HostLink> : (r.node_name || <span className="text-muted">–</span>) },
        ...(showLob ? [{ key: "lob", label: "LOB" }] : []),
        { key: "msp", label: "MSP", render: (r: any) => r.msp || <span className="text-muted">–</span> },
        { key: "edr_status", label: "EDR", sort: false, render: (r: any) => <EdrBadge s={r.edr_status} /> },
        { key: "port", label: "Port", render: (r: any) => `${r.port || ""}${r.protocol ? "/" + r.protocol : ""}` },
        { key: "plugin_id", label: "Plugin" },
        { key: "cve", label: "CVE", sort: false, render: (r: any) => <span className="text-xs">{r.cve}</span> },
        { key: "exploit_ease", label: "Exploit", sort: false, hidden: true },
        { key: "first_discovered", label: "First discovered", render: (r: any) => fmtDt(r.first_discovered) },
        { key: "last_observed", label: "Last observed", render: (r: any) => fmtDt(r.last_observed) },
        { key: "status", label: "Status", render: (r: any) => r.status === "fixed" ? <span className="text-good-fg">Fixed {fmtDt(r.fixed_at).slice(0, 10)}</span>
          : r.status === "accepted" ? <span className="text-violet-fg" title="Accepted by an SOD exception">Accepted · {r.exception_ref}</span>
          : (r.reopened ? <span className="text-serious-fg">Reopened</span> : "Open") },
      ]}
      filters={<>
        <SearchInput className="w-64" value={state.q || ""} onChange={(v: string) => set({ q: v })} placeholder="IP, name, CVE, plugin ID…" />
        {showLob && <Select value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} placeholder="All LOBs" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />}
        <MspFilter lobId={lobId} state={state} set={set} meta={meta} />
        <Select value={state.severity} onChange={(v) => set({ severity: v })} placeholder="Any severity" options={["Critical", "High", "Medium", "Low", "Info"]} />
        <Select value={state.status || "open"} onChange={(v) => set({ status: v === "open" ? undefined : v })} options={[["open", "Open"], ["accepted", "Accepted (SOD)"], ["fixed", "Fixed"], ["all", "All"]]} />
        <Select value={state.edr_status} onChange={(v) => set({ edr_status: v })} placeholder="Any EDR status" options={EDR_OPTS} />
        <ShowOnly state={state} set={set} flags={[["no_edr", "1", "Host has no active EDR"], ["exploit", "1", "Exploit available"]]} />
      </>} />
  );
}

function FindingSheet({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: f, error: fErr } = useQuery({ queryKey: ["finding", id], queryFn: () => api<any>(`/api/vulns/findings/${id}`) });
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} width={820}
      title={f ? <span className="flex items-center gap-2"><SeverityBadge s={f.severity} /> {f.name}</span> : "Loading…"}
      sub={f ? <span><Mono>{f.ip}</Mono>{f.port ? ` · ${f.port}/${f.protocol}` : ""} · {f.lob}{f.msp ? ` · ${f.msp}` : ""} · plugin {f.plugin_id}</span> : undefined}>
      {!f ? <Loading error={fErr} /> : (
        <div className="space-y-4">
          {f.exception && (
            <Callout tone="good"><b>Accepted by exception {f.exception.exception_id}</b> ({f.exception.scope}{f.exception.target ? ` ${f.exception.target}` : f.exception.lob ? ` ${f.exception.lob}` : ""}) — valid till {f.exception.valid_till || "no end date"}, approved by {f.exception.approved_by}. {f.exception.justification}</Callout>
          )}
          {f.edr_status !== "Online" && f.edr_status !== "Offline" && <Callout tone="crit">This host has <b>no active EDR agent</b> ({f.edr_status}).</Callout>}
          <Card className="p-4">
            <KV items={[
              ["Status", f.status === "fixed" ? `Fixed (${fmtDt(f.fixed_at)})` : f.status === "accepted" ? `Accepted (${f.exception_ref})` : f.reopened ? "Open (reopened)" : "Open"],
              ["EDR", <EdrBadge key="e" s={f.edr_status} />], ["Host", f.aid ? <HostLink key="h" aid={f.aid}>{f.hostname}</HostLink> : f.node_name || "–"],
              ["In inventory", f.in_inventory ? "Yes" : "No"], ["CVE", f.cve], ["Exploit ease", f.exploit_ease],
              ["First discovered", fmtDt(f.first_discovered)], ["Last observed", fmtDt(f.last_observed)],
              ["Vuln published", fmtDt(f.vuln_pub_date)], ["Patch published", fmtDt(f.patch_pub_date)],
              ["Other hosts with this finding", fmtN(f.other_hosts)], ["Last scan of host", fmtDt(f.last_scanned_at)],
            ]} />
          </Card>
          {[["Synopsis", f.synopsis], ["Description", f.description], ["Steps to remediate", f.solution], ["Plugin output", f.plugin_text], ["See also", f.see_also], ["Remarks", f.remarks]]
            .filter(([, v]) => v).map(([l, v]) => (
              <div key={l as string}>
                <SectionTitle className="mt-0">{l}</SectionTitle>
                <Card className="whitespace-pre-wrap break-words p-4 text-[12.8px]">{v}</Card>
              </div>
            ))}
        </div>
      )}
    </Sheet>
  );
}
