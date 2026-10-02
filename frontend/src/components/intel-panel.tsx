"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowUpRight, Bug, Globe2, KeyRound, RefreshCw, Radar, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, Loading } from "./ui";
import { EdrBadge, Mono } from "./badges";

export const LOOKUPS: [string, (ip: string) => string][] = [
  ["Shodan", (ip) => `https://www.shodan.io/search?query=${encodeURIComponent(ip)}`],
  ["VirusTotal", (ip) => `https://www.virustotal.com/gui/ip-address/${ip}`],
  ["Censys", (ip) => `https://search.censys.io/hosts/${ip}`],
  ["GreyNoise", (ip) => `https://viz.greynoise.io/ip/${ip}`],
];
const RISKY = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017, 161]);

function Tile({ icon: Icon, label, value, sub, tone, href, sample }: { icon: React.ElementType; label: string; value: React.ReactNode; sub?: React.ReactNode; tone: string; href?: string; sample?: boolean }) {
  const t: Record<string, string> = { crit: "bg-crit-soft text-crit-fg", warn: "bg-warn-soft text-warn-fg", good: "bg-good-soft text-good-fg", neutral: "bg-surface-3 text-fg-2", info: "bg-accent-soft text-accent-fg" };
  return (
    <div className="rounded-xl border border-border p-3">
      <div className="flex items-center gap-2 text-[11.5px] font-medium text-muted"><span className={cn("grid size-6 place-items-center rounded-md", t[tone])}><Icon className="size-3.5" /></span>{label}
        <span className="ml-auto flex items-center gap-1.5">
          {sample && <span className="rounded bg-violet-soft px-1 text-[10px] text-violet-fg" title="Sample data mode: simulated, not fetched from the internet">sample</span>}
          {href && <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-0.5 text-[10.5px] text-accent-fg hover:underline" title="Check this value at its source">source<ArrowUpRight className="size-3" /></a>}
        </span></div>
      <div className={cn("mt-1.5 text-[15px] font-semibold", tone === "crit" && "text-crit-fg")}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-muted">{sub}</div>}
    </div>
  );
}

/** Everything the free internet sources say about one public IP: InternetDB, VirusTotal, GreyNoise and RIPEstat, in one card. */
export function IntelPanel({ ip, showAsset }: { ip: string; showAsset?: boolean }) {
  const qc = useQueryClient();
  const { data: d, error, refetch, isFetching } = useQuery({ queryKey: ["intel", ip], queryFn: () => api<any>("/api/intel/ip", { params: { ip } }) });
  const [busy, setBusy] = React.useState(false);
  const refresh = async () => {
    setBusy(true);
    try { qc.setQueryData(["intel", ip], await api("/api/intel/ip/refresh", { method: "POST", body: { ip } })); toast.success(`${ip} looked up again`); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  if (!d) return <Card className="p-4"><div className="mb-2 text-[13px] text-muted">Looking up <Mono>{ip}</Mono> on InternetDB, VirusTotal, GreyNoise and RIPEstat…</div><Loading error={error} retry={() => refetch()} /></Card>;
  const pv = d.internetdb || {}, vt = d.virustotal, gn = d.greynoise || {}, rp = d.ripe || {};
  const ports: number[] = pv.ports || [], cves: string[] = pv.vulns || [];
  const vtBad = vt ? (vt.malicious || 0) + (vt.suspicious || 0) : 0;
  const vtTotal = vt ? (vt.malicious || 0) + (vt.suspicious || 0) + (vt.harmless || 0) + (vt.undetected || 0) : 0;
  return (
    <Card className={cn(isFetching && "opacity-80")}>
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <Globe2 className="size-5 text-accent-fg" />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[15px] font-semibold">{ip}</span>
            {rp.asn && <span className="text-[12px] text-muted">AS{rp.asn} · {rp.holder}</span>}
            {vt?.country && <Badge tone="neutral">{vt.country}</Badge>}</div>
          <div className="text-[11.5px] text-muted">{rp.prefix ? <>advertised in <Mono>{rp.prefix}</Mono> <a className="text-accent-fg hover:underline" href={`https://stat.ripe.net/${ip}`} target="_blank" rel="noopener noreferrer">RIPEstat↗</a></> : "prefix not looked up"}
            {showAsset && d.asset && <> · {d.asset.name ? <Link className="text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(d.asset.ip)}`}>{d.asset.name}</Link> : "known IP"} {d.asset.lobs ? `· ${d.asset.lobs}` : ""}</>}
            {showAsset && !d.asset && <> · <span className="text-violet-fg">not a known asset</span></>}</div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          {LOOKUPS.map(([n, url]) => <a key={n} href={url(ip)} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-0.5 rounded-md border border-border px-2 py-1 text-[12px] hover:border-accent hover:text-accent-fg">{n}<ArrowUpRight className="size-3" /></a>)}
          <Button size="sm" loading={busy} onClick={refresh}><RefreshCw /> Look up again</Button>
        </div>
      </div>
      <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">
        <Tile icon={Radar} label="Open ports (Shodan InternetDB)" href={`https://internetdb.shodan.io/${ip}`} sample={d.demo} tone={!pv.status ? "neutral" : ports.some((p) => RISKY.has(p)) ? "crit" : ports.length ? "warn" : "good"}
          value={!pv.status ? "–" : pv.status === "none" ? "No data" : pv.status === "error" ? "Error" : ports.length ? `${ports.length} open` : "Nothing open"}
          sub={pv.status === "error" ? pv.error : pv.scanned_at ? `looked up ${fmtRel(pv.scanned_at)}` : undefined} />
        <Tile icon={Bug} label="Known CVEs (InternetDB)" href={`https://internetdb.shodan.io/${ip}`} sample={d.demo} tone={cves.length ? "crit" : pv.status === "ok" ? "good" : "neutral"}
          value={pv.status === "ok" ? (cves.length ? `${cves.length} CVE${cves.length > 1 ? "s" : ""}` : "None") : "–"} sub={cves.slice(0, 2).join(", ")} />
        <Tile icon={ShieldAlert} label="VirusTotal" href={`https://www.virustotal.com/gui/ip-address/${ip}`} sample={d.demo} tone={!vt ? "neutral" : vt.malicious ? "crit" : vt.suspicious ? "warn" : "good"}
          value={!d.virustotal_key ? "No API key" : !vt ? (d.virustotal_error ? "Not available" : "–") : vt.not_found ? "Not in VirusTotal" : vtBad ? `${vtBad} / ${vtTotal} vendors flag it` : `Clean · 0 / ${vtTotal}`}
          sub={!d.virustotal_key ? <Link className="text-accent-fg hover:underline" href="/connectors/">add a free key under Integrations</Link>
            : d.virustotal_error || (vt ? `reputation ${vt.reputation ?? 0}${vt.as_owner ? ` · ${vt.as_owner}` : ""}` : undefined)} />
        <Tile icon={Globe2} label="GreyNoise" href={`https://viz.greynoise.io/ip/${ip}`} sample={d.demo} tone={gn.gn_noise ? "crit" : gn.gn_riot ? "info" : gn.gn_at ? "good" : "neutral"}
          value={!gn.gn_at ? "–" : gn.gn_noise ? "Seen scanning the internet" : gn.gn_riot ? "Known benign service" : "Not seen scanning"}
          sub={gn.gn_noise ? `${gn.gn_class || ""}${gn.gn_last_seen ? ` · last seen ${gn.gn_last_seen}` : ""}` : gn.gn_riot ? gn.gn_name : undefined} />
      </div>
      {(ports.length > 0 || cves.length > 0 || (pv.cpes || []).length > 0 || (pv.hostnames || []).length > 0) && (
        <div className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-2 border-t border-border px-4 py-3 text-[12.5px]">
          {ports.length > 0 && <><span className="text-muted">Open ports</span><span className="flex flex-wrap gap-1">{ports.map((p) =>
            <span key={p} className={cn("rounded-md border px-1.5 py-px font-mono text-[11px]", RISKY.has(p) ? "border-crit/40 bg-crit-soft text-crit-fg" : "border-border bg-surface-2")}>{p}</span>)}</span></>}
          {cves.length > 0 && <><span className="text-muted">CVEs</span><span className="flex flex-wrap gap-1">{cves.map((c) =>
            <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer"><Badge tone="serious">{c}</Badge></a>)}</span></>}
          {(pv.cpes || []).length > 0 && <><span className="text-muted">Software</span><span className="text-fg-2">{pv.cpes.map((c: string) => c.replace(/^cpe:\/[aoh]:/, "")).join(", ")}</span></>}
          {(pv.hostnames || []).length > 0 && <><span className="text-muted">Hostnames</span><span className="text-fg-2">{pv.hostnames.join(", ")}</span></>}
          {vt && vtTotal > 0 && <><span className="text-muted">VirusTotal</span><span className="flex items-center gap-2">
            <span className="flex h-2 w-48 overflow-hidden rounded-full bg-surface-3">
              <span className="bg-crit" style={{ width: `${(100 * (vt.malicious || 0)) / vtTotal}%` }} />
              <span className="bg-warn" style={{ width: `${(100 * (vt.suspicious || 0)) / vtTotal}%` }} />
              <span className="bg-good" style={{ width: `${(100 * (vt.harmless || 0)) / vtTotal}%` }} /></span>
            <span className="text-[11.5px] text-muted">{vt.malicious} malicious · {vt.suspicious} suspicious · {vt.harmless} harmless · {vt.undetected} undetected</span></span></>}
        </div>
      )}
      {showAsset && d.asset && <div className="border-t border-border px-4 py-2 text-[12px] text-muted">Known to the console: {d.asset.exposed ? <Badge tone="crit">internet exposed</Badge> : "not marked exposed"} · EDR <EdrBadge s={d.asset.edr_status} /></div>}
      <div className="border-t border-border px-4 py-2 text-[11px] text-muted">Only the IP address is sent to Shodan InternetDB, GreyNoise, RIPEstat and VirusTotal. Nothing is sent to the asset.{d.demo ? " Sample data mode: answers are simulated." : ""}</div>
    </Card>
  );
}

/** VirusTotal API key (Integrations page). */
export function VirusTotalCard() {
  const { data, refetch } = useQuery({ queryKey: ["intel-config"], queryFn: () => api<any>("/api/intel/config") });
  const [key, setKey] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const save = async (k: string) => {
    setBusy(true);
    try { await api("/api/intel/config", { method: "PUT", body: { virustotal_key: k } }); setKey(""); refetch(); toast.success(k ? "VirusTotal key saved" : "VirusTotal key removed"); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const test = async () => { const r = await api<any>("/api/intel/test", { method: "POST" }); toast[r.ok ? "success" : "error"](r.detail); };
  return (
    <Card className="p-4">
      <div className="mb-1 flex items-center gap-2 text-[14px] font-semibold"><KeyRound className="size-4" /> VirusTotal
        {data?.virustotal_key_set ? <Badge tone="good">key set</Badge> : <Badge>no key</Badge>}</div>
      <div className="mb-3 text-[12.5px] text-muted">Asset 360 shows how many security vendors flag a public IP. Needs a free VirusTotal account → API key
        (free tier: 4 lookups a minute, 500 a day; answers are cached). Only the IP address is sent.</div>
      <div className="flex flex-wrap gap-2">
        <input type="password" autoComplete="off" className="h-8.5 min-w-[260px] flex-1 rounded-lg border border-border-strong bg-surface px-2.5 text-[13px]"
          placeholder={data?.virustotal_key_set ? "•••••••• (enter a new key to replace)" : "Paste your VirusTotal API key"} value={key} onChange={(e) => setKey(e.target.value)} />
        <Button variant="primary" loading={busy} disabled={!key} onClick={() => save(key)}>Save</Button>
        {data?.virustotal_key_set && <><Button onClick={test}>Test</Button><Button variant="ghost" onClick={() => save("")}>Remove</Button></>}
      </div>
    </Card>
  );
}
