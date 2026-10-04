"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Crosshair, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { api } from "@/lib/api";
import { fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, Loading } from "../ui";
import { useChat } from "./chat";

export const VERDICT_TONE: Record<string, string> = { Malicious: "crit", Suspicious: "warn", Ours: "good", "Seen internally": "info", "Not known": "neutral", "Not an IOC": "neutral" };
const ICON: Record<string, React.ElementType> = { Malicious: ShieldAlert, Suspicious: ShieldQuestion, Ours: ShieldCheck };

/** Check IPs, domains, URLs and hashes against CrowdStrike threat intel, custom IOCs and our own data. */
export function IocChecker({ initial = "", autoRun = false, compact = false }: { initial?: string; autoRun?: boolean; compact?: boolean }) {
  const qc = useQueryClient();
  const [text, setText] = React.useState(initial);
  const [rows, setRows] = React.useState<any[] | null>(null);
  const [busy, setBusy] = React.useState(false);
  const ran = React.useRef(false);
  const run = async (v = text) => {
    if (!v.trim()) return;
    setBusy(true);
    try { const r = await api<any>("/api/ioc/check", { method: "POST", body: { values: v } }); setRows(r.rows); qc.invalidateQueries({ queryKey: ["ioc-recent"] }); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  React.useEffect(() => { if (autoRun && initial && !ran.current) { ran.current = true; run(initial); } }, [autoRun, initial]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="space-y-3">
      <Card className="p-3">
        <textarea className={cn("w-full rounded-lg border border-border-strong bg-surface p-2.5 font-mono text-[12.5px]", compact ? "h-16" : "h-28")} value={text}
          onChange={(e) => setText(e.target.value)} placeholder={"One per line or separated by spaces: IPs, domains, URLs, MD5 / SHA1 / SHA256\n185.220.101.4\nevil-update.xyz\n44d88612fea8a8f36de82e1278abb02f"} />
        <div className="mt-2 flex items-center gap-2">
          <Button variant="primary" loading={busy} onClick={() => run()}><Crosshair /> Check</Button>
          <span className="text-[11.5px] text-muted">CrowdStrike threat intel and custom IOCs (direct API with the sync's credentials — Falcon MCP not needed) · sightings in detections, NDR and assets · WHOIS / InternetDB / GreyNoise / VirusTotal for public IPs · up to 50 values</span>
        </div>
      </Card>
      {busy && <Card className="p-6"><Loading /></Card>}
      {rows && !busy && rows.map((r) => <IocResult key={r.value} r={r} />)}
    </div>
  );
}

export function IocResult({ r }: { r: any }) {
  const chat = useChat();
  const Icon = ICON[r.verdict] || ShieldQuestion;
  const seen = r.seen || {};
  return (
    <Card className={cn("p-3", r.verdict === "Malicious" && "border-crit/50")}>
      <div className="flex flex-wrap items-center gap-2">
        <Icon className={cn("size-5", r.verdict === "Malicious" ? "text-crit-fg" : r.verdict === "Suspicious" ? "text-warn-fg" : r.verdict === "Ours" ? "text-good-fg" : "text-muted")} />
        <span className="break-all font-mono text-[13px] font-semibold">{r.value}</span>
        {r.kind && <Badge tone="neutral">{r.kind}</Badge>}
        {r.source && <span className="text-[10.5px] text-muted">via {r.source}</span>}
        <Badge tone={VERDICT_TONE[r.verdict] as any}>{r.verdict}</Badge>
        {r.previous?.length > 0 && <span className="text-[11px] text-muted">checked before: {r.previous.map((p: any) => `${p.verdict} ${fmtRel(p.at)}`).join(", ")}</span>}
        {r.hunt && <Button size="sm" className="ml-auto" onClick={() => chat.ask(r.kind === "ipv4" ? `which endpoints connected to ${r.value}` : r.kind?.startsWith("sha") || r.kind === "md5" ? `did ${r.value} execute anywhere` : `who resolved ${r.hunt_slot.domain}`)}>
          Hunt it across endpoints</Button>}
      </div>
      {(r.why?.length > 0 || r.error) && <div className="mt-1.5 text-[12.5px] text-fg-2">{r.error || r.why.join(" · ")}</div>}
      {r.kind && (
        <div className="mt-2 grid gap-2 text-[12px] md:grid-cols-3">
          <Block title="CrowdStrike intel">{r.intel?.length ? r.intel.map((i: any, k: number) => <div key={k}><b>{i.confidence || "?"}</b> confidence · {i.type}
            {i.labels?.length > 0 && <div className="text-muted">{i.labels.join(", ")}</div>}{i.actors?.length > 0 && <div>actors: {i.actors.join(", ")}</div>}</div>)
            : <span className="text-muted">not in CrowdStrike intel</span>}
            {r.custom?.length > 0 && <div className="mt-1 text-crit-fg">custom IOC: {r.custom.map((c: any) => `${c.action} (${c.severity || "–"})`).join(", ")}</div>}</Block>
          <Block title="In our data">
            {seen.asset && <div>asset <Link className="text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(seen.asset.ip)}`}>{seen.asset.name || seen.asset.ip}</Link> · {seen.asset.lobs || "no LOB"} · EDR {seen.asset.edr_status}</div>}
            {seen.mark && <div>marked {seen.mark}</div>}
            {seen.agents > 0 && <div>{seen.agents} CrowdStrike agents use it</div>}
            {seen.ndr > 0 && <div>{seen.ndr} NDR alerts</div>}
            {seen.detections?.length > 0 && <div>{seen.detections.length} detections, e.g. {seen.detections[0].name} on {seen.detections[0].hostname}</div>}
            {!seen.asset && !seen.mark && !seen.agents && !seen.ndr && !seen.detections?.length && <span className="text-muted">not seen</span>}
          </Block>
          <Block title="Internet">
            {r.internet?.whois?.whois_name && <div>{r.internet.whois.whois_name} · {r.internet.whois.whois_org || r.internet.whois.whois_descr} {r.internet.whois.whois_country}</div>}
            {r.internet?.ports?.length > 0 && <div>open ports {r.internet.ports.join(", ")}</div>}
            {r.internet?.greynoise?.gn_noise ? <div className="text-warn-fg">GreyNoise: scanning the internet</div> : null}
            {r.internet?.virustotal && <div>VirusTotal: {r.internet.virustotal.malicious || 0} malicious / {r.internet.virustotal.suspicious || 0} suspicious</div>}
            {!r.internet || !Object.values(r.internet).some(Boolean) ? <span className="text-muted">{r.kind === "ipv4" ? "private IP or not looked up" : "n/a"}</span> : null}
          </Block>
        </div>
      )}
      {r.errors?.length > 0 && <div className="mt-1.5 text-[11px] text-muted">{r.errors.join(" · ")}</div>}
    </Card>
  );
}

const Block = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <div className="rounded-lg bg-surface-2 p-2"><div className="mb-0.5 text-[10.5px] font-semibold uppercase tracking-wider text-muted">{title}</div>{children}</div>
);

export function IocRecent() {
  const { data } = useQuery({ queryKey: ["ioc-recent"], queryFn: () => api<any>("/api/ioc/recent") });
  if (!data?.rows?.length) return null;
  return (
    <Card>
      <CardHeader title="Recent checks" hint="team memory: the last verdict shows next time someone checks the same value" />
      <div className="px-4 pb-3 text-[12.5px]">
        {data.rows.slice(0, 15).map((r: any) => (
          <div key={r.id} className="flex items-center gap-2 border-t border-border py-1.5 first:border-0">
            <span className="truncate font-mono">{r.value}</span><Badge tone={VERDICT_TONE[r.verdict] as any}>{r.verdict}</Badge>
            <span className="ml-auto shrink-0 text-[11px] text-muted">{fmtRel(r.at)}</span>
          </div>
        ))}
      </div>
    </Card>
  );
}
