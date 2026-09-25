"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ChevronRight, KeyRound, Loader2, PlugZap, RefreshCw, Save, Trash2, XCircle } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtDt, parseTs } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Checkbox, Field, Input, Loading, PageHeader, Select, useConfirm } from "@/components/ui";
import { SyncProgress, nextSyncLabel, useSyncStatus } from "@/components/sync-progress";

const CLOUD_LABEL: Record<string, string> = { "us-1": "US-1", "us-2": "US-2", "eu-1": "EU-1", "us-gov-1": "US-GOV-1", "us-gov-2": "US-GOV-2" };
const INTERVALS: [string, string][] = [["15", "Every 15 minutes"], ["30", "Every 30 minutes"], ["60", "Every hour"], ["120", "Every 2 hours"], ["360", "Every 6 hours"], ["720", "Every 12 hours"], ["1440", "Once a day"], ["0", "Manual only"]];

export default function SettingsPage() {
  const qc = useQueryClient();
  const { data: st } = useSyncStatus();
  const conn = useQuery({ queryKey: ["connection"], queryFn: () => api<any>("/api/connection") });
  if (!st || !conn.data) return <Loading />;
  const startSync = async () => {
    const r = await api<any>("/api/sync", { method: "POST" });
    r.ok ? toast.message("Sync started") : toast.warning(r.message);
    qc.invalidateQueries({ queryKey: ["sync-status"] });
  };
  return (
    <div>
      <PageHeader title="Sync & settings" sub="Connect the CrowdStrike Falcon API, control automatic syncing and review what every sync fetched." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Connection info={conn.data} running={st.running} />
        <Card>
          <CardHeader title={<span className="flex items-center gap-2"><RefreshCw className="size-4" /> Sync</span>}
            right={<Button variant="primary" size="sm" disabled={!st.configured || st.running} onClick={startSync}>
              <RefreshCw className={st.running ? "animate-spin" : ""} /> {st.running ? "Syncing…" : "Sync now"}</Button>} />
          <div className="space-y-4 px-4 pb-4">
            <div className="grid grid-cols-2 gap-3">
              <Stat label="Last successful sync" value={(() => { const r = st.runs.find((x: any) => x.status === "ok"); return r ? fmtDt(r.finished_at) : "Never"; })()} />
              <Stat label="Schedule" value={nextSyncLabel(st)} />
            </div>
            <IntervalPicker value={String(st.interval_minutes)} />
            {st.steps?.length ? <SyncProgress status={st} /> : (
              <div className="rounded-xl border border-dashed border-border-strong p-6 text-center text-[13px] text-muted">
                {st.configured ? "Live progress of the next sync appears here." : "Connect CrowdStrike to start the first sync."}
              </div>
            )}
          </div>
        </Card>
      </div>
      <History runs={st.runs} />
      <Detection />
      <Danger />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg bg-surface-2 px-3 py-2">
      <div className="text-[11.5px] text-muted">{label}</div>
      <div className="truncate text-[13.5px] font-semibold">{value}</div>
    </div>
  );
}

function Connection({ info, running }: { info: any; running: boolean }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [f, setF] = React.useState({ client_id: info.client_id, client_secret: "", cloud: info.base_url in CLOUD_LABEL ? info.base_url : "custom", custom_url: info.base_url in CLOUD_LABEL ? "" : info.base_url, member_cid: info.member_cid });
  const [test, setTest] = React.useState<any>(null);
  const [busy, setBusy] = React.useState<"" | "test" | "save">("");
  const body = () => ({ client_id: f.client_id, client_secret: f.client_secret, base_url: f.cloud === "custom" ? f.custom_url : f.cloud, member_cid: f.member_cid });
  const doTest = async () => {
    setBusy("test"); setTest(null);
    try { setTest(await api("/api/connection/test", { method: "POST", body: body() })); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  const doSave = async () => {
    setBusy("save");
    try {
      const t = await api<any>("/api/connection/test", { method: "POST", body: body() });
      setTest(t);
      if (!t.ok) { toast.error("Connection test failed — fix the errors below before saving"); return; }
      const r = await api<any>("/api/connection", { method: "PUT", body: { ...body(), sync_now: true } });
      toast.success(r.sync_started ? "Connected — first sync started" : "Connection saved");
      setF((x) => ({ ...x, client_secret: "" }));
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  const disconnect = async () => {
    if (!(await confirm({ title: "Disconnect CrowdStrike?", body: "The saved API credentials are deleted and automatic syncing stops. Synced data stays in the database.", ok: "Disconnect", danger: true }))) return;
    await api("/api/connection", { method: "DELETE" });
    setTest(null);
    setF({ client_id: "", client_secret: "", cloud: "us-1", custom_url: "", member_cid: "" });
    qc.invalidateQueries();
  };
  return (
    <Card>
      <CardHeader title={<span className="flex items-center gap-2"><PlugZap className="size-4" /> CrowdStrike connection</span>}
        right={info.configured ? <Badge tone="good"><CheckCircle2 className="size-3" /> Connected{info.source === "env" ? " (.env)" : ""}</Badge> : <Badge tone="warn">Not connected</Badge>} />
      <div className="space-y-3 px-4 pb-4">
        <Callout>
          In Falcon go to <b>Support and resources → API clients and keys</b>, create a client with the <b>Hosts: Read</b> scope, and paste the client ID and secret here. The secret is kept in the local database only and is never shown again.
        </Callout>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Client ID"><Input value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })} placeholder="32-character client ID" autoComplete="off" spellCheck={false} /></Field>
          <Field label="Client secret" hint={info.secret_set && !f.client_secret ? `Saved (${info.secret_hint}) — leave empty to keep it` : undefined}>
            <Input type="password" value={f.client_secret} onChange={(e) => setF({ ...f, client_secret: e.target.value })} placeholder={info.secret_set ? "••••••••  (unchanged)" : "Client secret"} autoComplete="new-password" />
          </Field>
          <Field label="Cloud region">
            <Select className="max-w-none" value={f.cloud} onChange={(v) => setF({ ...f, cloud: v })} options={[...Object.entries(CLOUD_LABEL).map(([k, l]) => [k, `${l} · ${info.clouds[k].replace("https://", "")}`] as [string, string]), ["custom", "Custom API URL"]]} />
          </Field>
          {f.cloud === "custom" ? (
            <Field label="API base URL"><Input value={f.custom_url} onChange={(e) => setF({ ...f, custom_url: e.target.value })} placeholder="https://api.us-2.crowdstrike.com" /></Field>
          ) : (
            <Field label="Member CID (optional)" hint="Only for MSSP / Flight Control child tenants"><Input value={f.member_cid} onChange={(e) => setF({ ...f, member_cid: e.target.value })} spellCheck={false} /></Field>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={doTest} loading={busy === "test"} disabled={!!busy || !f.client_id || (!f.client_secret && !info.secret_set)}><KeyRound /> Test connection</Button>
          <Button variant="primary" onClick={doSave} loading={busy === "save"} disabled={!!busy || running || !f.client_id || (!f.client_secret && !info.secret_set)}><Save /> Save & sync now</Button>
          {info.configured && info.source !== "env" && <Button variant="ghost" className="ml-auto" onClick={disconnect}>Disconnect</Button>}
        </div>
        {(busy || test) && (
          <div className="rounded-xl border border-border bg-surface-2 p-3">
            {busy && !test && <div className="flex items-center gap-2 text-[13px] text-fg-2"><Loader2 className="size-4 animate-spin" /> Contacting CrowdStrike…</div>}
            {test && (
              <>
                <div className={cn("mb-2 flex items-center gap-2 text-[13px] font-semibold", test.ok ? "text-good-fg" : "text-crit-fg")}>
                  {test.ok ? <CheckCircle2 className="size-4" /> : <XCircle className="size-4" />}
                  {test.ok ? "Connection works" : "Connection failed"}
                </div>
                <ul className="space-y-1.5">
                  {test.checks.map((c: any) => (
                    <li key={c.name} className="grid grid-cols-[16px_minmax(0,1fr)_auto] items-start gap-2 text-[12.5px]">
                      {c.ok ? <CheckCircle2 className="mt-0.5 size-4 text-good" /> : c.required ? <XCircle className="mt-0.5 size-4 text-crit" /> : <XCircle className="mt-0.5 size-4 text-warn" />}
                      <div><b>{c.name}</b>{!c.required && <span className="text-muted"> (optional)</span>}<div className={c.ok ? "text-muted" : c.required ? "text-crit-fg" : "text-warn-fg"}>{c.detail}</div></div>
                      <span className="tabular text-[11px] text-muted">{c.ms} ms</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}

function IntervalPicker({ value }: { value: string }) {
  const qc = useQueryClient();
  const save = async (v: string) => {
    await api("/api/settings", { method: "PUT", body: { sync_interval_minutes: v } });
    toast.success(v === "0" ? "Automatic sync turned off" : `Automatic sync: ${INTERVALS.find((i) => i[0] === v)?.[1].toLowerCase()}`);
    qc.invalidateQueries({ queryKey: ["sync-status"] });
  };
  return (
    <Field label="Automatic sync" hint="Runs in the background while the app is running; a missed sync starts right after restart.">
      <Select className="max-w-none" value={value} onChange={save} options={INTERVALS} />
    </Field>
  );
}

function History({ runs }: { runs: any[] }) {
  const [open, setOpen] = React.useState<number | null>(null);
  const log = useQuery({ queryKey: ["sync-log", open], queryFn: () => api<any>(`/api/sync/runs/${open}/log`), enabled: open !== null });
  const dur = (r: any) => {
    const a = parseTs(r.started_at), b = parseTs(r.finished_at);
    if (!a || !b) return "…";
    const s = Math.round((b.getTime() - a.getTime()) / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
  };
  return (
    <Card className="mt-4">
      <CardHeader title="Sync history & logs" hint="click a run to see everything it fetched" />
      {!runs.length ? <div className="px-4 pb-6 text-center text-muted">No syncs yet</div> : (
        <div className="max-h-[560px] overflow-y-auto scroll-thin">
          {runs.map((r) => (
            <div key={r.id} className="border-t border-border">
              <button onClick={() => setOpen(open === r.id ? null : r.id)} className="grid w-full grid-cols-[18px_150px_90px_70px_minmax(0,1fr)] items-center gap-3 px-4 py-2.5 text-left text-[12.8px] hover:bg-surface-2">
                <ChevronRight className={cn("size-4 text-muted transition-transform", open === r.id && "rotate-90")} />
                <span>{fmtDt(r.started_at)}</span>
                <Badge tone={r.status === "ok" ? "good" : r.status === "running" ? "info" : "crit"} className="justify-center">{r.status === "ok" ? "Success" : r.status === "running" ? "Running" : "Failed"}</Badge>
                <span className="tabular text-muted">{dur(r)}</span>
                <span className={cn("truncate", r.status === "error" ? "text-crit-fg" : "text-fg-2")}>{r.message || `${r.mode} sync`}</span>
              </button>
              {open === r.id && (
                <div className="bg-[#0b0e14] px-4 py-3 font-mono text-[11.5px] leading-relaxed text-[#c9d1d9]">
                  {!log.data ? "Loading…" : !log.data.rows.length ? "No log lines for this run." : log.data.rows.map((l: any, i: number) => (
                    <div key={i} className={l.level === "error" ? "text-[#ff7b72]" : l.level === "warn" ? "text-[#e3b341]" : ""}>
                      <span className="text-[#6e7681]">{fmtDt(l.ts).slice(11)}</span> <span className="text-[#79c0ff]">[{l.step}]</span> {l.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function Detection() {
  const qc = useQueryClient();
  const s = useQuery({ queryKey: ["settings"], queryFn: () => api<Record<string, string>>("/api/settings") });
  const [f, setF] = React.useState<Record<string, string> | null>(null);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => { if (s.data && !f) setF(s.data); }, [s.data, f]);
  if (!f) return null;
  const save = async () => {
    setSaving(true);
    try {
      const { stale_online_hours, auto_remove_days, inventory_stale_days, dup_ip_exclude, fetch_nic_history } = f;
      await api("/api/settings", { method: "PUT", body: { stale_online_hours, auto_remove_days, inventory_stale_days, dup_ip_exclude, fetch_nic_history } });
      toast.success("Settings saved — counts recalculated");
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); } finally { setSaving(false); }
  };
  return (
    <Card className="mt-4">
      <CardHeader title="Detection settings" right={<Button size="sm" variant="primary" loading={saving} onClick={save}><Save /> Save</Button>} />
      <div className="grid gap-4 px-4 pb-4 md:grid-cols-2 xl:grid-cols-4">
        <Field label="“Online · last seen stale” after (hours)" hint="Online agents not seen for longer than this.">
          <Input type="number" step="0.5" min="0.5" value={f.stale_online_hours} onChange={(e) => setF({ ...f, stale_online_hours: e.target.value })} />
        </Field>
        <Field label="Falcon auto-removal window (days)" hint="Match your console setting; separates “Removed > N days” from “Deleted manually”.">
          <Input type="number" min="1" value={f.auto_remove_days} onChange={(e) => setF({ ...f, auto_remove_days: e.target.value })} />
        </Field>
        <Field label="Inventory: agent counts as inactive after (days)" hint="Used for the inventory claim check.">
          <Input type="number" min="1" value={f.inventory_stale_days} onChange={(e) => setF({ ...f, inventory_stale_days: e.target.value })} />
        </Field>
        <div className="flex items-end pb-1">
          <Checkbox checked={f.fetch_nic_history === "1"} onChange={(v) => setF({ ...f, fetch_nic_history: v ? "1" : "0" })} label="Fetch NIC / IP history for new and IP-changed hosts" />
        </div>
        <Field label="Shared IPs — never treated as duplicates" className="md:col-span-2 xl:col-span-4"
          hint="Comma separated, * for prefixes (NAT pools, VPN ranges, loopback). Agents on these IPs are always counted as separate devices.">
          <textarea rows={2} className="rounded-lg border border-border-strong bg-surface p-2.5 font-mono text-[12.5px]" value={f.dup_ip_exclude} onChange={(e) => setF({ ...f, dup_ip_exclude: e.target.value })} />
        </Field>
      </div>
    </Card>
  );
}

function Danger() {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const clear = async () => {
    if (!(await confirm({ title: "Clear all synced Falcon data?", body: "Deletes every synced host, IP history, activity, sync log and agent tag. LOB inventories, templates and the connection are kept. The next sync rebuilds everything from CrowdStrike.", ok: "Clear data", danger: true }))) return;
    try { await api("/api/admin/clear-falcon-data", { method: "POST" }); toast.success("Falcon data cleared"); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };
  return (
    <Card className="mt-4 flex flex-wrap items-center gap-3 border-crit/30 p-4">
      <div className="min-w-0 flex-1">
        <div className="font-semibold">Clear synced data</div>
        <div className="text-[12.5px] text-muted">Use after switching to a different Falcon tenant. LOB inventories are not affected.</div>
      </div>
      <Button variant="danger" onClick={clear}><Trash2 /> Clear Falcon data</Button>
    </Card>
  );
}
