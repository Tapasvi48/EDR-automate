"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { fmtDt, fmtRel } from "@/lib/format";
import { Badge, Card, CardHeader, Loading, Sheet } from "./ui";
import { Mono } from "./badges";
import { ExplainButton } from "./ai/brief";

const SEV_TONE: Record<string, any> = { critical: "crit", high: "serious", medium: "warn", low: "info", informational: "neutral" };
const sevTone = (s?: string) => SEV_TONE[(s || "").toLowerCase()] || "neutral";
const isUrl = (v: any) => typeof v === "string" && /^https?:\/\//.test(v.split(" ")[0]);

/** Label / value grid; long values wrap, links open in a new tab. */
export function KV({ data, cols = 1 }: { data: Record<string, any>; cols?: 1 | 2 }) {
  const items = Object.entries(data || {}).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (!items.length) return <div className="px-4 pb-4 text-[12.5px] text-muted">Nothing recorded.</div>;
  return (
    <dl className={`grid gap-x-4 gap-y-2 px-4 pb-4 text-[12.5px] ${cols === 2 ? "md:grid-cols-[130px_1fr_130px_1fr]" : ""} grid-cols-[140px_1fr]`}>
      {items.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">
            {isUrl(v) ? <a className="inline-flex items-center gap-1 text-accent-fg hover:underline" href={String(v).split(" ")[0]} target="_blank" rel="noopener noreferrer">{String(v)} <ExternalLink className="size-3" /></a>
              : /command line|sha256|md5|path|vector/i.test(k) ? <code className="break-all font-mono text-[11.5px]">{String(v)}</code> : String(v)}
          </dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

function Raw({ raw }: { raw: any }) {
  const [open, setOpen] = React.useState(false);
  if (!raw || !Object.keys(raw).length) return null;
  return (
    <Card>
      <button className="flex w-full items-center px-4 py-2.5 text-left text-[12.5px] font-medium" onClick={() => setOpen(!open)}>
        Full record from CrowdStrike (JSON) <span className="ml-auto text-muted">{open ? "hide" : "show"}</span></button>
      {open && <pre className="max-h-[50vh] overflow-auto border-t border-border px-4 py-3 font-mono text-[11px] leading-relaxed scroll-thin">{JSON.stringify(raw, null, 2)}</pre>}
    </Card>
  );
}

function HostCard({ h }: { h: any }) {
  if (!h) return null;
  return (
    <Card>
      <CardHeader title="Host" right={<Link className="text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(h.connection_ip || h.hostname)}`}>Open in Asset 360 →</Link>} />
      <KV cols={2} data={{ Hostname: h.hostname, "Connection IP": h.connection_ip, "Local IP": h.local_ip, Platform: [h.platform_name, h.os_version].filter(Boolean).join(" · "),
        Sensor: h.agent_version, Agent: h.online_state ? `${h.online_state} · last seen ${fmtRel(h.last_seen)}` : undefined, Domain: h.machine_domain,
        Site: h.site_name, "Last user": h.last_login_user, Containment: h.containment_status }} />
    </Card>
  );
}

/** One CrowdStrike detection in full. */
export function DetectionSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, error } = useQuery({ queryKey: ["detection", id], queryFn: () => api<any>("/api/detections/item", { params: { id: id! } }), enabled: !!id });
  const d = data?.detection;
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()} width={880}
      title={d ? <span className="flex flex-wrap items-center gap-2"><Badge tone={sevTone(d.severity)}>{d.severity}</Badge>{d.name}</span> : "Detection"}
      sub={d ? `${d.hostname || d.aid} · ${fmtDt(d.created_at)} · ${d.status || "new"}${d.assigned_to ? ` · ${d.assigned_to}` : ""}` : undefined}
      actions={id ? <ExplainButton kind="detection" id={id} label="Triage with AI" /> : undefined}>
      {!data ? <Loading error={error} /> : (
        <div className="space-y-4">
          <Card><CardHeader title="What fired" /><KV data={data.what} /></Card>
          {data.tree.length > 0 && (
            <Card>
              <CardHeader title="Process tree" />
              <div className="space-y-2 px-4 pb-4">
                {data.tree.map(([label, p]: [string, any], i: number) => (
                  <div key={label} className="rounded-lg border border-border p-2.5" style={{ marginLeft: i * 18 }}>
                    <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">{label}</div>
                    <KV data={p} />
                  </div>
                ))}
              </div>
            </Card>
          )}
          <Card><CardHeader title="Status & handling" /><KV data={data.state} /></Card>
          <HostCard h={data.host} />
          {data.same_host.length > 0 && (
            <Card>
              <CardHeader title="Other detections on this host" />
              <div className="px-4 pb-3 text-[12.5px]">
                {data.same_host.map((x: any) => (
                  <div key={x.id} className="flex items-center gap-2 border-t border-border py-1.5 first:border-0">
                    <Badge tone={sevTone(x.severity)}>{x.severity}</Badge><span className="truncate">{x.name}</span>
                    <span className="ml-auto shrink-0 text-muted">{x.status} · {fmtRel(x.created_at)}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
          <Raw raw={data.raw} />
        </div>
      )}
    </Sheet>
  );
}

/** One CrowdStrike Spotlight finding in full. */
export function SpotlightSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, error } = useQuery({ queryKey: ["spotlight-item", id], queryFn: () => api<any>("/api/spotlight/item", { params: { id: id! } }), enabled: !!id });
  const r = data?.row;
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()} width={880}
      title={r ? <span className="flex flex-wrap items-center gap-2"><Badge tone={sevTone(r.severity)}>{r.severity}</Badge><Mono>{r.cve}</Mono>{r.title && <span>{r.title}</span>}</span> : "Spotlight finding"}
      sub={r ? `${r.hostname || r.aid} · ${r.ip || ""} · ${r.status}` : undefined}
      actions={r ? <ExplainButton kind="cve" id={r.cve} label="Explain CVE" /> : undefined}>
      {!data ? <Loading error={error} /> : (
        <div className="space-y-4">
          <Card>
            <CardHeader title="Vulnerability" right={<span className="flex gap-3 text-[12px]">
              <a className="text-accent-fg hover:underline" href={`https://nvd.nist.gov/vuln/detail/${r.cve}`} target="_blank" rel="noopener noreferrer">NVD ↗</a>
              <a className="text-accent-fg hover:underline" href={`https://www.cve.org/CVERecord?id=${r.cve}`} target="_blank" rel="noopener noreferrer">CVE.org ↗</a></span>} />
            <KV data={data.vuln} />
          </Card>
          {data.software.length > 0 && <Card><CardHeader title="Affected software" />{data.software.map((s: any, i: number) => <KV key={i} data={s} />)}</Card>}
          <Card><CardHeader title="How to fix" /><KV data={data.fix} /></Card>
          <Card><CardHeader title="This finding" /><KV data={data.finding} /></Card>
          <Card>
            <CardHeader title="VA scan on the same IP" hint="what the vulnerability scanner reports for this CVE on this host" />
            {data.va.length ? (
              <div className="px-4 pb-3 text-[12.5px]">
                {data.va.map((v: any, i: number) => (
                  <div key={i} className="border-t border-border py-1.5 first:border-0">
                    <div className="flex items-center gap-2"><Badge tone={sevTone(v.severity)}>{v.severity}</Badge><b>{v.name}</b>
                      <span className="ml-auto text-muted">{v.port ? `${v.protocol || ""}/${v.port} · ` : ""}{v.status}</span></div>
                    {v.solution && <div className="mt-0.5 text-[12px] text-fg-2">{v.solution}</div>}
                  </div>
                ))}
              </div>
            ) : <div className="px-4 pb-4 text-[12.5px] text-muted">The VA scan does not report this CVE on this IP (Spotlight only).</div>}
          </Card>
          <HostCard h={data.host} />
          <Raw raw={data.raw} />
        </div>
      )}
    </Sheet>
  );
}
