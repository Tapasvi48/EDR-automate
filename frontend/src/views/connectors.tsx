"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Activity, Database, FileText, Network, Radio, Save, ScanSearch, Server, ShieldCheck, Upload } from "lucide-react";
import { api } from "@/lib/api";
import { fmtDt } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, Checkbox, Field, Input, Loading, PageHeader } from "@/components/ui";
import { SatelliteCard } from "@/views/settings";
import { useSyncStatus } from "@/components/sync-progress";

type Tone = "good" | "warn" | "neutral" | "crit" | "info";

function Tile({ icon: Icon, name, status, tone, children, needs, action }: {
  icon: React.ElementType; name: string; status: string; tone: Tone; children?: React.ReactNode; needs?: string[]; action?: React.ReactNode;
}) {
  return (
    <Card className={cn("flex flex-col p-5", tone === "neutral" && "border-dashed")}>
      <div className="flex items-center gap-2">
        <span className="grid size-9 place-items-center rounded-lg bg-surface-2"><Icon className="size-4.5" /></span>
        <div className="text-[15px] font-semibold">{name}</div>
        <Badge tone={tone} className="ml-auto">{status}</Badge>
      </div>
      <div className="mt-3 flex-1 text-[13px] text-fg-2">{children}</div>
      {needs && (
        <div className="mt-3 rounded-lg bg-surface-2 p-3">
          <div className="mb-1 text-[11.5px] font-semibold uppercase tracking-wider text-muted">What it needs</div>
          <ul className="list-disc space-y-0.5 pl-4 text-[12px] text-fg-2">{needs.map((n) => <li key={n}>{n}</li>)}</ul>
        </div>
      )}
      {action && <div className="mt-4">{action}</div>}
    </Card>
  );
}

/** Every data source the console joins, its status and exactly what each integration needs. */
export default function Connectors() {
  const { data: conn } = useQuery({ queryKey: ["connection"], queryFn: () => api<any>("/api/connection") });
  const { data: st } = useSyncStatus() as { data?: any };
  const { data: sat } = useQuery({ queryKey: ["satellite-config"], queryFn: () => api<any>("/api/satellite/config") });
  const { data: src } = useQuery({ queryKey: ["inventory-sources"], queryFn: () => api<any>("/api/inventory-sources") });
  if (!conn || !sat || !src) return <Loading />;
  const manual = src.sources.find((s: any) => s.key === "manual");
  const demo = !!st?.demo;
  const csOk = conn.configured || demo;
  return (
    <div>
      <PageHeader title="Integrations" sub="Every source the console joins on IP and hostname: what is connected, what each one feeds, and what the planned ones need. Credentials are entered here by you and never shown back." />
      <div className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted">Connected</div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Tile icon={ShieldCheck} name="CrowdStrike Falcon" status={demo ? "Sample data" : csOk ? "Connected" : "Not connected"} tone={csOk ? "good" : "warn"}
          needs={["Hosts: Read (required) - agents, online state, NIC history", "Alerts: Read - recent detections on Asset 360",
            "Vulnerabilities: Read - Spotlight", "Prevention policies: Read - policy per agent", "Sensor update policies: Read - N / N-1 / N-2 builds"]}
          action={<Link href="/settings/"><Button size="sm">Connection & sync</Button></Link>}>
          The EDR source of truth: every sync pulls hosts, detections, Spotlight vulnerabilities, prevention policies and sensor builds. Optional permissions are skipped with a warning when missing.
        </Tile>
        <Tile icon={Upload} name="Inventory - manual upload" status={manual?.status === "connected" ? "Connected" : "No uploads"} tone={manual?.status === "connected" ? "good" : "warn"}
          action={<Link href="/inventory-sources/"><Button size="sm">Inventory sources</Button></Link>}>{manual?.detail}</Tile>
        <Tile icon={Radio} name="NIAM dump" status="Upload" tone="info" action={<Link href="/integrations/"><Button size="sm">Open NIAM</Button></Link>}>
          Host IP → NE ID from the NIAM export; drives NIAM integration coverage.
        </Tile>
        <Tile icon={ScanSearch} name="VA scans, communication matrix, SOD" status="Upload" tone="info" action={<Link href="/upload/"><Button size="sm">Upload center</Button></Link>}>
          Nessus exports (findings, open ports, OS), firewall / ISP rules (internet exposure), and the SOD exception register.
        </Tile>
      </div>

      <div className="mb-2 mt-6 text-[12px] font-semibold uppercase tracking-wider text-muted">Connect</div>
      <SatelliteCard />
      <SplunkCard />
      <SeceonCard />

      <div className="mb-2 mt-6 text-[12px] font-semibold uppercase tracking-wider text-muted">Planned</div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Tile icon={Database} name="ServiceNow CMDB" status="Planned" tone="neutral"
          needs={["Instance URL (https://<instance>.service-now.com)", "Read-only integration user with the cmdb_read role (or OAuth client)",
            "CI class to pull, e.g. cmdb_ci_server / cmdb_ci_computer, and the fields: IP, name, class, OS, support group, install status",
            "Mapping of assignment group / business service to LOB and MSP"]}>
          Pull CI records on a schedule into the LOB inventories; each record shows ServiceNow CMDB as its source on Asset 360.
        </Tile>
        <Tile icon={FileText} name="Jaspersoft reports" status="Planned" tone="neutral"
          needs={["JasperReports Server URL and a read-only user", "The report (or ad hoc view) path that lists the inventory",
            "Export format CSV and a schedule, or REST v2 report execution (/rest_v2/reports/...csv)"]}>
          Load a scheduled report export exactly like a manual inventory upload.
        </Tile>

      </div>
    </div>
  );
}

/** Seceon NDR: alerts pushed by webhook (or uploaded); REST pull once Seceon's API docs are available. */
function SeceonCard() {
  const qc = useQueryClient();
  const { data: cfg } = useQuery({ queryKey: ["seceon-config"], queryFn: () => api<any>("/api/seceon/config") });
  const [tok, setTok] = React.useState<string | null>(null);
  if (!cfg) return null;
  const url = typeof window !== "undefined" ? `${window.location.origin}${cfg.path}` : cfg.path;
  const gen = async () => {
    const r = await api<any>("/api/seceon/token", { method: "POST" });
    setTok(r.token);
    qc.invalidateQueries({ queryKey: ["seceon-config"] });
  };
  return (
    <Card className="mt-4">
      <div className="flex items-center gap-2 px-4 pt-4">
        <Activity className="size-4" /><span className="text-[14px] font-semibold">Seceon NDR (aiXDR / OTM)</span>
        <Badge tone={cfg.alerts ? "good" : "warn"}>{cfg.alerts ? `${cfg.alerts.toLocaleString()} alerts received` : "No alerts yet"}</Badge>
        {cfg.last && <span className="text-[12px] text-muted">last {fmtDt(cfg.last)}</span>}
      </div>
      <p className="px-4 pt-1 text-[12.5px] text-fg-2">
        Network detections per IP, shown under Recent detections in Asset 360 next to CrowdStrike and Splunk. Seceon sends alert notifications by syslog, email or
        <b> webhook</b>: point its webhook at this console. Or upload an alert export in the <Link className="text-accent-fg hover:underline" href="/upload/">Upload center</Link>.
      </p>
      <div className="grid gap-3 px-4 py-3 md:grid-cols-2">
        <Field label="Webhook URL (POST, JSON: one alert or a list)"><Input readOnly value={url} onFocus={(e) => e.target.select()} /></Field>
        <Field label="Header X-Webhook-Token" hint={cfg.token_set && !tok ? "a token is set - generate a new one to rotate it (the old one stops working)" : undefined}>
          <div className="flex gap-2">
            <Input readOnly value={tok || (cfg.token_set ? "•••••••• (hidden)" : "")} placeholder="not set" onFocus={(e) => e.target.select()} />
            <Button size="sm" onClick={gen}>{cfg.token_set ? "Rotate" : "Generate"}</Button>
          </div>
        </Field>
      </div>
      {tok && <div className="px-4 pb-2 text-[12px] text-warn-fg">Copy the token now and paste it into Seceon's webhook settings - it is not shown again.</div>}
      <div className="border-t border-border px-4 py-2.5 text-[11.5px] text-muted">
        Needs: Seceon able to reach this server over HTTPS · the token in the webhook's X-Webhook-Token header (or ?token=) · common field names are recognised
        (alert id, time, severity or score, alert name, category, source / destination IP, host). A scheduled REST pull can be added with Seceon's API documentation for your version.
      </div>
    </Card>
  );
}

/** Splunk: log-source presence per host (is this host logging to the SIEM?). */
function SplunkCard() {
  const qc = useQueryClient();
  const { data: cfg } = useQuery({ queryKey: ["splunk-config"], queryFn: () => api<any>("/api/splunk/config") });
  const [f, setF] = React.useState<any>(null);
  const [test, setTest] = React.useState<any>(null);
  React.useEffect(() => { if (cfg && !f) setF({ url: cfg.url, token: "", index: cfg.index, days: cfg.days, verify_ssl: cfg.verify_ssl }); }, [cfg, f]);
  if (!cfg || !f) return null;
  const save = async () => {
    try { await api("/api/splunk/config", { method: "PUT", body: f }); toast.success("Splunk settings saved"); setF({ ...f, token: "" }); qc.invalidateQueries({ queryKey: ["splunk-config"] }); }
    catch (e: any) { toast.error(e.message); }
  };
  return (
    <Card className="mt-4">
      <div className="flex items-center gap-2 px-4 pt-4">
        <Server className="size-4" /><span className="text-[14px] font-semibold">Splunk (SIEM logging)</span>
        <Badge tone={cfg.url || cfg.demo ? "good" : "warn"}>{cfg.demo ? "Simulated (sample data)" : cfg.url ? "Configured" : "Not connected"}</Badge>
      </div>
      <p className="px-4 pt-1 text-[12.5px] text-fg-2">
        Asset 360 asks Splunk, live, whether the host logged in the last N days and to which index / sourcetype - a silent host is a blind spot during an incident.
        It runs one metadata search per view: <code className="text-[11.5px]">| tstats latest(_time) count WHERE (index filter) (host=&lt;name&gt; OR host=&lt;ip&gt;) BY host index sourcetype</code>.
      </p>
      <div className="grid gap-3 px-4 py-3 md:grid-cols-2 xl:grid-cols-5">
        <Field label="Splunk REST URL"><Input value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://splunk-sh.example.com:8089" /></Field>
        <Field label="Authentication token" hint={cfg.token_set ? "saved - leave blank to keep it" : undefined}>
          <Input type="password" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} autoComplete="new-password" placeholder={cfg.token_set ? "••••••••" : ""} /></Field>
        <Field label="Index filter"><Input value={f.index} onChange={(e) => setF({ ...f, index: e.target.value })} placeholder="* or index=wineventlog OR index=linux" /></Field>
        <Field label="Look back (days)"><Input type="number" min={1} max={90} value={f.days} onChange={(e) => setF({ ...f, days: e.target.value })} /></Field>
        <div className="flex flex-col justify-end gap-2">
          <Checkbox checked={f.verify_ssl} onChange={(v) => setF({ ...f, verify_ssl: v })} label="Verify the TLS certificate" />
          <div className="flex gap-2"><Button size="sm" onClick={save}><Save /> Save</Button>
            <Button size="sm" variant="ghost" disabled={!cfg.url} onClick={async () => setTest(await api<any>("/api/splunk/test", { method: "POST" }))}>Test</Button></div>
        </div>
      </div>
      {test && <div className={cn("px-4 pb-2 text-[12.5px]", test.ok ? "text-good-fg" : "text-crit-fg")}>{test.detail}</div>}
      <div className="border-t border-border px-4 py-2.5 text-[11.5px] text-muted">
        Needs: the search head's management port (8089) reachable from this server · a token (Settings → Tokens) for a user whose role has the <b>search</b> capability on the host-log indexes and on <code>index=notable</code> (Enterprise Security notable events, shown as Splunk detections on Asset 360) · read only, nothing is written to Splunk.
      </div>
    </Card>
  );
}
