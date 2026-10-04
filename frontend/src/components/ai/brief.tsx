"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { BookOpen, Crosshair, MessageSquarePlus, Play, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Loading, Sheet } from "../ui";
import { useChat, useOpenStudio } from "./chat";
import { CqlCode, CqlResult } from "./cql";

const LEVEL_TONE = (l: string) => (/act now|now|high risk|patch now/i.test(l) ? "crit" : /investigate|review|medium|suspicious/i.test(l) ? "warn" : /benign|low/i.test(l) ? "good" : "info");
const FACT_TONE: Record<string, string> = { crit: "text-crit-fg", warn: "text-warn-fg", good: "text-good-fg" };
const VERDICT: Record<string, string> = { Malicious: "crit", Suspicious: "warn", Ours: "good", "Seen internally": "info", "Not known": "neutral" };

/** The model's narrative, written after the brief is shown (does not block it). */
function Narrative({ b }: { b: any }) {
  const { data, isFetching, error } = useQuery({
    queryKey: ["brief-narrate", b.kind, b.id, b.level], queryFn: () => api<any>("/api/brief/narrate", { method: "POST", body: { kind: b.kind, id: b.id } }),
    enabled: !!b.can_narrate && !b.narrative, staleTime: 30 * 60_000, retry: false,
  });
  const n = b.narrative || data?.narrative;
  if (!b.can_narrate) return null;
  if (isFetching && !n) return (
    <div className="rounded-xl border border-violet/25 bg-violet-soft/30 p-3">
      <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-violet-fg"><Sparkles className="size-3.5 animate-pulse" /> On-prem model is writing the summary…</div>
      <div className="space-y-1.5"><div className="h-2.5 w-11/12 animate-pulse rounded bg-violet/15" /><div className="h-2.5 w-4/5 animate-pulse rounded bg-violet/15" /><div className="h-2.5 w-2/3 animate-pulse rounded bg-violet/15" /></div>
    </div>
  );
  if (n) return (
    <div className="rounded-xl border border-violet/30 bg-violet-soft/30 p-3 leading-relaxed">
      <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-violet-fg"><Sparkles className="size-3.5" /> {b.model || data?.model} · every sentence cites the facts below{data?.model_seconds ? ` · ${data.model_seconds}s` : ""}</div>
      {n}
    </div>
  );
  const err = data?.model_error || (error as any)?.message;
  return err ? <div className="text-[11.5px] text-muted">{/404|not found/i.test(err) ? "The AI model is not installed yet" : /refused|connect/i.test(err) ? "The AI model server is not running" : "The AI model did not answer"} — the assessment comes from rules over the facts (Settings → AI model).</div> : null;
}

function HuntCard({ h }: { h: any }) {
  const openStudio = useOpenStudio();
  const [res, setRes] = React.useState<any>(null);
  const [busy, setBusy] = React.useState(false);
  const run = async () => { setBusy(true); try { setRes(await api("/api/cql/run", { method: "POST", body: { cql: h.cql, days: 7, question: h.title } })); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); } };
  return (
    <div className="overflow-hidden rounded-xl border border-border">
      <div className="flex flex-wrap items-center gap-2 bg-surface-2/60 px-3 py-1.5 text-[12px]">
        <Crosshair className="size-3.5 text-violet-fg" /><b>{h.title}</b>{h.mitre && <Badge tone="violet">{h.mitre}</Badge>}<span className="text-muted">{h.why}</span>
        <div className="flex-1" />
        <button className="text-accent-fg hover:underline" onClick={() => openStudio(h.cql, h.title)}>Edit</button>
        <Button size="sm" loading={busy} onClick={run}><Play /> Run</Button>
      </div>
      <CqlCode code={h.cql} className="max-h-28 overflow-auto px-3 py-2 text-[11px]" />
      {res && <div className="border-t border-border p-2"><CqlResult r={res} max={6} /></div>}
    </div>
  );
}

/** A brief: verdict, why, response steps, evidence (behaviours, indicators, the host's kill chain), facts with sources, hunts to run,
 *  knowledge-base guidance and the model's narrative. */
export function BriefView({ b, compact }: { b: any; compact?: boolean }) {
  return (
    <div className="space-y-3 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={LEVEL_TONE(b.level) as any}>{b.level}</Badge>
        {b.likelihood != null && (
          <span className="flex items-center gap-1.5 text-[11.5px] text-fg-2" title="How likely this is a real attack, from the evidence below (rules)">
            true-positive likelihood
            <span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-3"><span className={cn("block h-full rounded-full", b.likelihood >= 75 ? "bg-crit" : b.likelihood >= 45 ? "bg-warn" : "bg-good")} style={{ width: `${b.likelihood}%` }} /></span>
            <b>{b.likelihood}%</b>
          </span>
        )}
      </div>
      {b.why?.length > 0 && <ul className="space-y-0.5 text-[12.5px] text-fg-2">{b.why.map((w: string) => <li key={w} className="flex gap-1.5"><span className="mt-1.5 size-1 shrink-0 rounded-full bg-fg-2" />{w}</li>)}</ul>}
      <Narrative b={b} />
      {b.steps?.length > 0 && (
        <div className="rounded-xl border border-border p-3">
          <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted"><ShieldAlert className="size-3.5" /> Respond</div>
          <ol className="list-decimal space-y-0.5 pl-5">{b.steps.map((s: string) => <li key={s}>{s}</li>)}</ol>
        </div>
      )}
      {(b.behaviours?.length > 0 || b.indicators?.length > 0) && (
        <div className="grid gap-2 sm:grid-cols-2">
          {b.behaviours?.length > 0 && <div className="rounded-xl border border-border p-2.5">
            <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">What the command line does</div>
            <div className="flex flex-wrap gap-1">{b.behaviours.map((x: any) => <Badge key={x.label} tone="crit">{x.label} · {x.mitre}</Badge>)}</div>
          </div>}
          {b.indicators?.length > 0 && <div className="rounded-xl border border-border p-2.5">
            <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">Indicators (checked)</div>
            {b.indicators.map((i: any) => <div key={i.value} className="flex items-center gap-1.5 text-[12px]"><span className="truncate font-mono text-[11px]" title={i.value}>{i.value.length > 28 ? i.value.slice(0, 26) + "…" : i.value}</span>
              <Badge tone={VERDICT[i.verdict] as any}>{i.verdict}</Badge></div>)}
          </div>}
        </div>
      )}
      {b.chain?.length > 1 && (
        <div className="rounded-xl border border-border p-2.5">
          <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-wider text-muted">This host, ±48h</div>
          <div className="space-y-1">{b.chain.map((x: any) => (
            <div key={x.id} className={cn("flex items-center gap-2 border-l-2 pl-2 text-[12px]", x.this ? "border-violet font-medium" : "border-border")}>
              <span className="w-20 shrink-0 text-[11px] text-muted">{fmtRel(x.at)}</span><Badge tone={/crit|high/i.test(x.severity) ? "crit" : "neutral"}>{x.tactic || "–"}</Badge>
              <span className="truncate">{x.name}</span>{x.this && <span className="text-[10.5px] text-violet-fg">this one</span>}
            </div>))}</div>
        </div>
      )}
      {b.hunts?.length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted">Hunt next</div>
          {(compact ? b.hunts.slice(0, 2) : b.hunts).map((h: any) => <HuntCard key={h.title} h={h} />)}
        </div>
      )}
      <div>
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted">Facts ({b.facts.length})</div>
        <div className={cn("overflow-hidden rounded-xl border border-border", compact && "max-h-64 overflow-y-auto")}>
          {b.facts.map((f: any, i: number) => (
            <div key={i} className={cn("grid gap-x-2 border-t border-border px-2.5 py-1.5 first:border-0", compact ? "grid-cols-[18px_1fr]" : "grid-cols-[22px_150px_1fr]")}>
              <span className="text-[11px] text-muted">{i + 1}</span>
              <span className={cn("text-fg-2", compact && "text-[11.5px]")}>{f.label}</span>
              <span className={cn("min-w-0", compact && "col-start-2")}><span className={cn("break-words", FACT_TONE[f.tone] || "")}>{String(f.value)}</span>
                <span className="ml-1.5 text-[10.5px] text-muted">{f.source}{f.at ? ` · ${fmtRel(f.at)}` : ""}</span></span>
            </div>
          ))}
        </div>
      </div>
      {b.kb?.length > 0 && (
        <div>
          <div className="mb-1 flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-muted"><BookOpen className="size-3.5" /> From the knowledge base</div>
          {b.kb.map((k: any, i: number) => (
            <div key={i} className="mb-1 rounded-lg bg-surface-2 px-2.5 py-1.5 text-[12px]"><b>{k.title}</b> <span className="text-fg-2">{k.snippet}</span></div>
          ))}
        </div>
      )}
    </div>
  );
}

/** "Explain with AI" for a detection / asset / CVE / IP / the estate: opens the brief in a side panel, can continue in chat. */
export function ExplainButton({ kind, id, label = "Explain with AI", size = "sm", variant = "soft" }: { kind: string; id: string; label?: string; size?: any; variant?: any }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <Button size={size} variant={variant} onClick={(e) => { e.stopPropagation(); setOpen(true); }}><Sparkles /> {label}</Button>
      {open && <BriefSheet kind={kind} id={id} onClose={() => setOpen(false)} />}
    </>
  );
}

function BriefSheet({ kind, id, onClose }: { kind: string; id: string; onClose: () => void }) {
  const chat = useChat();
  const { data, error } = useQuery({ queryKey: ["brief", kind, id], queryFn: () => api<any>("/api/brief", { method: "POST", body: { kind, id } }), staleTime: 60_000 });
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()} width={820} title={<span className="flex items-center gap-2"><Sparkles className="size-4 text-violet-fg" />{data?.title || "Brief"}</span>}
      sub={`AI SOC brief · ${kind}`}
      actions={data && <Button size="sm" onClick={() => { chat.attach({ kind: "explain", payload: data, text: `${data.title}: ${data.level}`, context: { [kind === "detection" ? "detection" : kind === "cve" ? "cve" : kind === "ip" ? "ip" : "host"]: id } }); onClose(); }}>
        <MessageSquarePlus /> Continue in chat</Button>}>
      {!data ? <Loading error={error} /> : <BriefView b={data} />}
      {data && kind === "asset" && <div className="mt-4 text-[12px]"><Link className="text-accent-fg hover:underline" href={`/falcon-mcp/?tab=fabric&q=${encodeURIComponent(id)}`}>See its relationships in the data fabric →</Link></div>}
    </Sheet>
  );
}
