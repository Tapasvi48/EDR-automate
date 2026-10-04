"use client";
import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowUp, BookOpen, ExternalLink, Brain, ChevronDown, Crosshair, FileSearch, GitBranch, Maximize2, MessageSquarePlus, PanelLeft, Pin, Search, ShieldQuestion, Sparkles, Trash2, X, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge } from "../ui";
import { BriefView } from "./brief";
import { IocResult } from "./ioc";
import { CqlMsg, SummarizeButton } from "./cql";

/* ---------------- app-wide chat state: any page can open the chat, ask, or attach a brief ---------------- */
type Ctx = {
  open: boolean; setOpen: (v: boolean) => void; sid: number | null; setSid: (v: number | null) => void; pending: string | null;
  ask: (text: string, opts?: { fresh?: boolean }) => Promise<void>; attach: (m: { kind: string; payload: any; text: string; context?: any }) => Promise<void>; newChat: () => Promise<number>;
};
const ChatCtx = React.createContext<Ctx | null>(null);
export const useChat = () => {
  const c = React.useContext(ChatCtx);
  if (!c) throw new Error("ChatProvider missing");
  return c;
};

export function ChatProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const [open, setOpen] = React.useState(false);
  const [sid, setSidState] = React.useState<number | null>(null);
  const [pending, setPending] = React.useState<string | null>(null);
  React.useEffect(() => { try { const v = localStorage.getItem("ai-chat-sid"); if (v) setSidState(+v); } catch {} }, []);
  const setSid = (v: number | null) => { setSidState(v); try { v ? localStorage.setItem("ai-chat-sid", String(v)) : localStorage.removeItem("ai-chat-sid"); } catch {} };
  const newChat = async () => {
    const cur: any = sid ? qc.getQueryData(["chat-session", sid]) : null;
    if (cur && !cur.messages?.length) return sid as number; // reuse an empty conversation
    const r = await api<any>("/api/chat/sessions", { method: "POST", body: {} });
    setSid(r.id); qc.invalidateQueries({ queryKey: ["chat-sessions"] });
    return r.id as number;
  };
  const ensure = async (fresh?: boolean) => (fresh || !sid ? await newChat() : sid);
  const ask = async (text: string, opts?: { fresh?: boolean }) => {
    if (!text.trim()) return;
    const id = await ensure(opts?.fresh);
    setOpen(true); setPending(text);
    try { await api(`/api/chat/sessions/${id}/message`, { method: "POST", body: { text } }); }
    catch (e: any) { toast.error(e.message); } finally {
      setPending(null); qc.invalidateQueries({ queryKey: ["chat-session", id] }); qc.invalidateQueries({ queryKey: ["chat-sessions"] });
    }
  };
  const attach = async (m: { kind: string; payload: any; text: string; context?: any }) => {
    const id = await ensure(false);
    await api(`/api/chat/sessions/${id}/attach`, { method: "POST", body: m });
    setOpen(true); qc.invalidateQueries({ queryKey: ["chat-session", id] }); qc.invalidateQueries({ queryKey: ["chat-sessions"] });
  };
  return <ChatCtx.Provider value={{ open, setOpen, sid, setSid, pending, ask, attach, newChat }}>{children}</ChatCtx.Provider>;
}

/** Open a CQL query in the Hunt studio (from anywhere). */
export function useOpenStudio() {
  const router = useRouter();
  const c = React.useContext(ChatCtx);
  return (cql: string, q: string) => {
    try { sessionStorage.setItem("studio-open", JSON.stringify({ cql, q })); } catch {}
    c?.setOpen(false);
    router.push(`/falcon-mcp/?tab=studio&t=${Date.now()}`);
  };
}

export const Orb = ({ size = 28, pulse }: { size?: number; pulse?: boolean }) => (
  <span className={cn("relative flex shrink-0 items-center justify-center rounded-full bg-[conic-gradient(from_200deg,var(--violet),var(--accent),#22d3ee,var(--violet))] text-white shadow-[0_4px_14px_-4px_var(--violet)]", pulse && "animate-pulse")}
    style={{ width: size, height: size }}>
    <span className="absolute inset-[2px] rounded-full bg-[radial-gradient(circle_at_35%_30%,rgba(255,255,255,.45),transparent_55%)]" />
    <Sparkles style={{ width: size * 0.5, height: size * 0.5 }} className="relative" />
  </span>
);

/* ---------------- floating launcher + docked window (every page) ---------------- */
export function ChatDock() {
  const c = useChat();
  const path = usePathname();
  if (path?.startsWith("/falcon-mcp") || path?.startsWith("/ai")) return null; // the AI SOC page shows the chat full size
  return (
    <>
      {!c.open && (
        <button onClick={() => c.setOpen(true)} title="AI SOC assistant"
          className="group fixed bottom-5 right-5 z-40 flex items-center gap-2 rounded-full border border-white/20 bg-[linear-gradient(135deg,var(--violet),var(--accent))] py-2 pl-2 pr-4 text-[13px] font-semibold text-white shadow-[0_10px_30px_-8px_var(--violet)] transition hover:-translate-y-0.5 hover:shadow-[0_14px_36px_-8px_var(--violet)] print:hidden">
          <Orb size={30} /> Ask AI SOC
        </button>
      )}
      {c.open && (
        <div className="anim-fade fixed bottom-4 right-4 top-16 z-40 flex w-[min(560px,calc(100vw-2rem))] flex-col overflow-hidden rounded-3xl border border-border bg-bg shadow-[0_30px_80px_-20px_rgba(0,0,0,.45)] print:hidden">
          <ChatPanel docked onClose={() => c.setOpen(false)} />
        </div>
      )}
    </>
  );
}

/* ---------------- the chat (docked or full page with the conversation list) ---------------- */
const MODES: [string, string, React.ElementType, string][] = [
  ["auto", "Auto", Sparkles, "Ask anything — hunt, explain, check an IOC, or ask how two things are connected…"],
  ["hunt", "Hunt", Crosshair, "Describe what to hunt for, e.g. office apps spawning powershell this week"],
  ["explain", "Explain", FileSearch, "A host, IP, CVE or detection to explain, or “today's SOC brief”"],
  ["ioc", "IOC", ShieldQuestion, "IPs, domains or hashes to check against CrowdStrike intel"],
  ["kb", "Knowledge", BookOpen, "Ask your playbooks and SOPs, e.g. how do we escalate ransomware?"],
];
const PREFIX: Record<string, (t: string) => string> = {
  hunt: (t) => (/^(hunt|find|which|who|where|show|list)\b/i.test(t) ? t : `hunt for ${t}`),
  explain: (t) => (/^(explain|summari[sz]e|brief|triage)\b/i.test(t) ? t : `explain ${t}`),
  ioc: (t) => (/\bcheck\b/i.test(t) ? t : `check ${t}`),
  kb: (t) => (/\b(playbook|sop|how (do|should) we)\b/i.test(t) ? t : `playbook: ${t}`),
};

export function ChatPanel({ docked, onClose, fill }: { docked?: boolean; onClose?: () => void; fill?: boolean }) {
  const c = useChat();
  const openStudio = useOpenStudio();
  const [text, setText] = React.useState("");
  const [mode, setMode] = React.useState("auto");
  const [side, setSide] = React.useState(!docked);
  const [showList, setShowList] = React.useState(false);
  const listRef = React.useRef<HTMLDivElement>(null);
  const taRef = React.useRef<HTMLTextAreaElement>(null);
  const { data: s } = useQuery({ queryKey: ["chat-session", c.sid], queryFn: () => api<any>(`/api/chat/sessions/${c.sid}`), enabled: !!c.sid, retry: false });
  const msgs: any[] = s?.messages || [];
  React.useEffect(() => { const el = listRef.current; if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" }); }, [msgs.length, c.pending]);
  React.useEffect(() => { const t = taRef.current; if (t) { t.style.height = "0px"; t.style.height = Math.min(180, t.scrollHeight) + "px"; } }, [text]);
  const send = (t0?: string) => {
    const t = (t0 ?? text).trim();
    if (!t || c.pending) return;
    setText("");
    c.ask(mode !== "auto" && !t0 ? PREFIX[mode](t) : t);
  };
  const memory = s?.context ? Object.entries(s.context).filter(([, v]) => v) : [];
  const empty = !msgs.length && !c.pending;
  const curMode = MODES.find((m) => m[0] === mode)!;
  return (
    <div className={cn("flex min-h-0 flex-1", docked ? "flex-col" : cn(fill ? "h-full" : "h-[calc(100vh-290px)] min-h-[520px]", "gap-0 overflow-hidden rounded-3xl border border-border bg-surface shadow-card"))}>
      {!docked && side && <div className="hidden w-72 shrink-0 flex-col border-r border-border bg-surface-2/40 md:flex"><SessionList /></div>}
      <div className="relative flex min-h-0 flex-1 flex-col bg-[radial-gradient(ellipse_at_top,var(--violet-soft),transparent_55%)]">
        <div className="flex items-center gap-1.5 px-3 py-2.5">
          {!docked && <IconBtn title="Conversations" onClick={() => setSide(!side)}><PanelLeft /></IconBtn>}
          {docked && <Orb size={26} />}
          <button className="flex min-w-0 items-center gap-1 rounded-lg px-1.5 py-1 text-left hover:bg-surface-2" onClick={() => setShowList(!showList)} title="Conversations">
            <span className="truncate text-[13.5px] font-semibold">{s?.title || "New conversation"}</span><ChevronDown className="size-3.5 shrink-0 text-muted" />
          </button>
          <div className="flex-1" />
          <IconBtn title="New conversation" onClick={() => c.newChat()}><MessageSquarePlus /></IconBtn>
          {!fill && <IconBtn title="Full-screen chat in a new tab" onClick={() => window.open("/ai/?focus=chat", "_blank", "noopener")}><ExternalLink /></IconBtn>}
          {docked && <Link href="/falcon-mcp/" onClick={onClose}><IconBtn title="Open full page"><Maximize2 /></IconBtn></Link>}
          {onClose && <IconBtn title="Close" onClick={onClose}><X /></IconBtn>}
        </div>
        {showList && <div className="absolute left-3 right-3 top-12 z-30 h-96 overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl"><SessionList onPick={() => setShowList(false)} /></div>}
        {memory.length > 0 && (
          <div className="mx-auto flex w-full max-w-3xl flex-wrap items-center gap-1 px-4 pb-1 text-[11px]">
            <Brain className="size-3.5 text-violet-fg" /><span className="text-muted">Context:</span>
            {memory.map(([k, v]) => <span key={k} className="rounded-full border border-violet/25 bg-violet-soft/60 px-2 py-0.5"><span className="text-violet-fg">{k}</span> <span className="font-mono">{String(v).slice(0, 26)}</span></span>)}
          </div>
        )}
        <div ref={listRef} className="min-h-0 flex-1 overflow-y-auto scroll-thin">
          <div className={cn("mx-auto w-full max-w-3xl space-y-6 px-4 py-4", empty && "flex min-h-full flex-col")}>
            {empty && <Welcome docked={docked} onAsk={(q) => send(q)} />}
            {msgs.map((m) => <Message key={m.id} m={m} onOpenStudio={openStudio} onAsk={(q) => send(q)} />)}
            {c.pending && <><UserBubble text={c.pending} /><Thinking text={c.pending} /></>}
          </div>
        </div>
        <div className="mx-auto w-full max-w-3xl px-3 pb-3 pt-1">
          <div className="rounded-[22px] bg-[linear-gradient(135deg,var(--violet),var(--accent),#22d3ee)] p-[1.5px] shadow-[0_12px_40px_-18px_var(--violet)]">
            <div className="rounded-[20.5px] bg-surface">
              <textarea ref={taRef} value={text} onChange={(e) => setText(e.target.value)} rows={1}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
                placeholder={curMode[3]}
                className="block max-h-44 min-h-[52px] w-full resize-none bg-transparent px-4 pb-1 pt-3.5 text-[14px] outline-none placeholder:text-muted" />
              <div className="flex items-center gap-1 px-2 pb-2">
                {MODES.map(([id, label, Icon]) => (
                  <button key={id} onClick={() => setMode(id)} title={label} className={cn("flex items-center gap-1 rounded-full px-2.5 py-1 text-[11.5px] transition",
                    mode === id ? "bg-violet-soft font-medium text-violet-fg" : "text-muted hover:bg-surface-2 hover:text-fg")}><Icon className="size-3.5" />{!docked || mode === id ? label : null}</button>
                ))}
                <div className="flex-1" />
                <button onClick={() => send()} disabled={!!c.pending || !text.trim()}
                  className="flex size-8 items-center justify-center rounded-full bg-[linear-gradient(135deg,var(--violet),var(--accent))] text-white shadow transition enabled:hover:scale-105 disabled:opacity-35"><ArrowUp className="size-4" /></button>
              </div>
            </div>
          </div>
          <PageChips onAsk={(q) => send(q)} />
          {!docked && <div className="mt-1.5 text-center text-[10.5px] text-muted">Runs on your CrowdStrike data and an on-prem model. Every hunt shows its query; nothing changes in the tenant.</div>}
        </div>
      </div>
    </div>
  );
}

const IconBtn = ({ children, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button {...p} className="flex size-8 items-center justify-center rounded-lg text-fg-2 hover:bg-surface-2 hover:text-fg [&_svg]:size-4">{children}</button>
);

function groupOf(at: string) {
  const d = new Date(at), now = new Date();
  const days = Math.floor((new Date(now.toDateString()).getTime() - new Date(d.toDateString()).getTime()) / 86400000);
  return days <= 0 ? "Today" : days === 1 ? "Yesterday" : days < 7 ? "This week" : "Earlier";
}

function SessionList({ onPick }: { onPick?: () => void }) {
  const c = useChat();
  const qc = useQueryClient();
  const [q, setQ] = React.useState("");
  const { data } = useQuery({ queryKey: ["chat-sessions", q], queryFn: () => api<any>("/api/chat/sessions", { params: { q } }) });
  const del = async (id: number) => { await api(`/api/chat/sessions/${id}`, { method: "DELETE" }); if (c.sid === id) c.setSid(null); qc.invalidateQueries({ queryKey: ["chat-sessions"] }); };
  const pin = async (id: number, v: boolean) => { await api(`/api/chat/sessions/${id}`, { method: "PATCH", body: { pinned: v } }); qc.invalidateQueries({ queryKey: ["chat-sessions"] }); };
  const rows: any[] = data?.rows || [];
  const groups: [string, any[]][] = [];
  rows.forEach((r) => {
    const g = r.pinned ? "Pinned" : groupOf(r.updated_at);
    const hit = groups.find((x) => x[0] === g);
    if (hit) hit[1].push(r); else groups.push([g, [r]]);
  });
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 p-3">
        <button onClick={async () => { await c.newChat(); onPick?.(); }}
          className="flex w-full items-center gap-2 rounded-xl border border-border bg-surface px-3 py-2 text-[13px] font-medium shadow-card hover:border-violet"><MessageSquarePlus className="size-4 text-violet-fg" /> New conversation</button>
        <div className="relative"><Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted" />
          <input className="h-8 w-full rounded-lg border border-border bg-surface pl-8 pr-2 text-[12.5px] outline-none focus:border-violet" placeholder="Search conversations" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2 scroll-thin">
        {groups.map(([g, rs]) => (
          <div key={g} className="mb-2">
            <div className="px-2 py-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">{g}</div>
            {rs.map((r: any) => (
              <div key={r.id} onClick={() => { c.setSid(r.id); onPick?.(); }}
                className={cn("group flex cursor-pointer items-center gap-1.5 rounded-lg px-2.5 py-1.5 hover:bg-surface-2", c.sid === r.id && "bg-violet-soft/70")}>
                <div className="min-w-0 flex-1"><div className="truncate text-[12.5px]">{r.title}</div>
                  <div className="text-[10.5px] text-muted">{r.messages} messages · {fmtRel(r.updated_at)}</div></div>
                <button className={cn("rounded p-1 hover:bg-surface-3", r.pinned ? "text-violet-fg" : "invisible text-muted group-hover:visible")} onClick={(e) => { e.stopPropagation(); pin(r.id, !r.pinned); }}><Pin className="size-3.5" /></button>
                <button className="invisible rounded p-1 text-muted hover:bg-surface-3 hover:text-crit-fg group-hover:visible" onClick={(e) => { e.stopPropagation(); del(r.id); }}><Trash2 className="size-3.5" /></button>
              </div>
            ))}
          </div>
        ))}
        {!rows.length && <div className="p-3 text-[12px] text-muted">No conversations yet.</div>}
      </div>
    </div>
  );
}

const CAPS: [React.ElementType, string, string, string][] = [
  [Crosshair, "Threat hunt in CQL", "Writes and runs NG-SIEM queries from plain English", "hunt for lsass credential dumping"],
  [FileSearch, "Triage & explain", "Detections, hosts, CVEs — with every fact sourced", "give me today's SOC brief"],
  [ShieldQuestion, "Check IOCs", "CrowdStrike intel, custom IOCs and our own sightings", "check sample-c2.example"],
  [GitBranch, "Connect the dots", "Walks the data-fabric graph between any two entities", "how is svc_batch connected to Payments?"],
  [Zap, "Posture questions", "Coverage gaps, exposure, riskiest assets per LOB", "exposed assets without EDR in Payments"],
  [BookOpen, "Ask the playbooks", "Your SOPs, the CQL guides, MITRE — quoted with sources", "how do we escalate credential dumping?"],
];

function Welcome({ onAsk, docked }: { onAsk: (q: string) => void; docked?: boolean }) {
  const h = new Date().getHours();
  return (
    <div className="my-auto py-4 text-center">
      <div className="mx-auto mb-4 w-fit"><Orb size={docked ? 44 : 56} /></div>
      <div className={cn("bg-[linear-gradient(90deg,var(--violet),var(--accent),#0891b2)] bg-clip-text font-semibold tracking-tight text-transparent", docked ? "text-[22px]" : "text-[30px]")}>
        Good {h < 12 ? "morning" : h < 17 ? "afternoon" : "evening"}, analyst
      </div>
      <p className="mx-auto mt-1 max-w-lg text-[13px] text-fg-2">What should we look into? I hunt across CrowdStrike, reason over the data fabric and quote your knowledge base — and I remember the thread.</p>
      <div className={cn("mx-auto mt-6 grid gap-2.5 text-left", docked ? "grid-cols-1 sm:grid-cols-2" : "sm:grid-cols-2 lg:grid-cols-3")}>
        {CAPS.map(([Icon, t, d, q]) => (
          <button key={t} onClick={() => onAsk(q)} className="group rounded-2xl border border-border bg-surface p-3 text-left shadow-card transition hover:-translate-y-0.5 hover:border-violet/50 hover:shadow-lg">
            <div className="flex items-center gap-2"><span className="flex size-7 items-center justify-center rounded-lg bg-violet-soft text-violet-fg"><Icon className="size-4" /></span><b className="text-[12.5px]">{t}</b></div>
            <div className="mt-1.5 text-[11.5px] text-fg-2">{d}</div>
            <div className="mt-2 truncate text-[11.5px] text-accent-fg opacity-80 group-hover:opacity-100">“{q}” →</div>
          </button>
        ))}
      </div>
    </div>
  );
}

/** Questions about what is on screen (Asset 360 search, a CVE filter…). */
function PageChips({ onAsk }: { onAsk: (q: string) => void }) {
  const path = usePathname() || "";
  const sp = useSearchParams();
  const q = sp?.get("q") || "";
  const chips: string[] = [];
  if (path.startsWith("/ip-search") && q) chips.push(`summarize ${q}`, `any detections on ${q} this week`, `what vulnerabilities does ${q} have`);
  if (path.startsWith("/spotlight") && sp?.get("cve")) chips.push(`explain ${sp.get("cve")}`, `who has ${sp.get("cve")}`);
  if (path.startsWith("/detections")) chips.push("critical detections from today", "which hosts have the most detections");
  if (path === "/" || path.startsWith("/alerts")) chips.push("give me today's SOC brief");
  if (!chips.length) return null;
  return <div className="mt-2 flex flex-wrap gap-1">{chips.map((x) => <button key={x} onClick={() => onAsk(x)} className="rounded-full border border-border bg-surface px-2.5 py-0.5 text-[11.5px] text-fg-2 hover:border-violet hover:text-violet-fg">{x}</button>)}</div>;
}

const UserBubble = ({ text }: { text: string }) => (
  <div className="flex justify-end"><div className="max-w-[80%] whitespace-pre-wrap rounded-3xl rounded-br-lg bg-surface-3/80 px-4 py-2.5 text-[13.5px] shadow-card">{text}</div></div>
);

/** Agent trace while the answer is being built. */
function Thinking({ text }: { text: string }) {
  const steps = /\b(check|ioc|malicious)\b/i.test(text) ? ["Reading the indicators", "Querying CrowdStrike threat intel", "Looking for sightings in our data", "Deciding a verdict"]
    : /\b(explain|summari|brief|triage)\b/i.test(text) ? ["Resolving the entity", "Gathering facts from the data fabric", "Matching playbook guidance", "Writing the brief"]
    : /\b(connected|related|linked)\b/i.test(text) ? ["Finding both entities", "Walking the fabric graph", "Building the path"]
    : ["Understanding the question", "Choosing a tested hunt / planning the query", "Running it against CrowdStrike", "Summarising what came back"];
  const [i, setI] = React.useState(0);
  React.useEffect(() => { const t = setInterval(() => setI((x) => Math.min(steps.length - 1, x + 1)), 1600); return () => clearInterval(t); }, [steps.length]);
  return (
    <div className="flex gap-3">
      <Orb size={28} pulse />
      <div className="space-y-1 pt-1">
        {steps.map((s, k) => (
          <div key={s} className={cn("flex items-center gap-2 text-[12.5px] transition", k < i ? "text-fg-2" : k === i ? "font-medium text-violet-fg" : "text-muted opacity-50")}>
            {k < i ? <span className="size-1.5 rounded-full bg-good" /> : k === i ? <span className="size-1.5 animate-ping rounded-full bg-violet" /> : <span className="size-1.5 rounded-full bg-border-strong" />}
            {s}{k === i && "…"}
          </div>
        ))}
      </div>
    </div>
  );
}

const KIND: Record<string, [string, string]> = { learned: ["Preference saved", "good"], hunt: ["Hunt", "info"], cql: ["CQL hunt", "violet"], explain: ["Brief", "info"], ioc: ["IOC check", "warn"], knowledge: ["Knowledge base", "neutral"], path: ["Fabric graph", "violet"] };

function Trace({ m }: { m: any }) {
  const p = m.payload || {};
  const bits: string[] = [];
  if (m.kind === "cql") bits.push(p.source?.startsWith("library:") ? "matched a tested hunt" : p.source?.startsWith("model") ? "query planned by the local model" : "built from the question", `ran on ${p.result?.via === "sample" ? "sample telemetry" : p.result?.via === "direct" ? "CrowdStrike NG-SIEM" : p.result?.via || "CrowdStrike"} in ${p.result?.seconds ?? "?"}s`);
  if (m.kind === "hunt") bits.push(p.router === "model" ? "planned by the local model" : "matched by rules", p.tool?.startsWith("fabric:") ? "answered from the data fabric" : `queried ${p.via === "direct" ? "CrowdStrike API" : p.via === "sample" ? "sample data" : "CrowdStrike"}`);
  if (m.kind === "explain") bits.push(`${p.facts?.length || 0} facts from the fabric`, p.kb?.length ? `${p.kb.length} playbook passages` : "", p.narrative ? `narrative by ${p.model}` : "rule-based assessment");
  if (m.kind === "ioc") bits.push(`checked via ${p.source || "CrowdStrike"}`);
  if (m.kind === "path") bits.push(p.found ? `${p.hops?.length} hops · ${p.expanded} entities searched` : "no path");
  if (m.kind === "knowledge") bits.push(`${p.passages?.length || 0} passages`, p.answer && !/Nothing in/.test(p.answer) ? "answer grounded in them" : "");
  const k = KIND[m.kind] || [m.kind, "neutral"];
  return (
    <div className="mb-2 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
      <Badge tone={k[1] as any}>{k[0]}</Badge>{bits.filter(Boolean).map((b) => <span key={b} className="flex items-center gap-1.5"><span className="size-1 rounded-full bg-border-strong" />{b}</span>)}
      <span className="ml-auto">{fmtRel(m.at)}</span>
    </div>
  );
}

function Message({ m, onOpenStudio, onAsk }: { m: any; onOpenStudio: (cql: string, q: string) => void; onAsk: (q: string) => void }) {
  if (m.role === "user") return <UserBubble text={m.text} />;
  const p = m.payload || {};
  return (
    <div className="flex gap-3">
      <Orb size={28} />
      <div className="min-w-0 flex-1 pt-0.5">
        <Trace m={m} />
        {m.kind === "hunt" && <HuntMsg p={p} />}
        {m.kind === "cql" && <CqlMsg p={p} onOpenStudio={onOpenStudio} />}
        {m.kind === "explain" && <BriefView b={p} compact />}
        {m.kind === "ioc" && <IocResult r={p} />}
        {m.kind === "knowledge" && <KnowledgeMsg p={p} />}
        {m.kind === "path" && <PathMsg p={p} text={m.text} />}
        {m.kind === "learned" && <div className="text-[13px]">{m.text}<div className="mt-1 text-[11.5px] text-muted">Change or remove it under AI SOC → Settings → What the AI learned.</div></div>}
        <LessonNote p={p} />
        {!Object.keys(KIND).includes(m.kind) && <div className="text-[13px]">{m.text}</div>}
        <FollowUps m={m} onAsk={onAsk} />
      </div>
    </div>
  );
}

/** The AI learned from a correction, or answered the way it was taught before (undo-able). */
function LessonNote({ p }: { p: any }) {
  const [gone, setGone] = React.useState(false);
  const l = p?.learned || p?.applied_lesson;
  if (!l || gone) return null;
  const forget = async () => { try { await api(`/api/ai/learned/lesson/${l.id}`, { method: "DELETE" }); setGone(true); toast.success("Forgotten"); } catch (e: any) { toast.error(e.message); } };
  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-1.5 rounded-xl border border-good/30 bg-good-soft/50 px-3 py-1.5 text-[12px]">
      <Brain className="size-3.5 text-good-fg" />
      {p.learned ? <>Learned: next time someone asks <b>“{l.question}”</b>, I'll answer <b>“{l.right_question}”</b>.</>
        : <>Answered as you taught me: <b>“{l.right_question}”</b> instead of <span className="text-fg-2">“{l.question}”</span>.</>}
      <button onClick={forget} className="ml-auto text-[11.5px] text-muted underline-offset-2 hover:text-crit-fg hover:underline">{p.learned ? "undo" : "forget this"}</button>
    </div>
  );
}

/** Suggested next questions (the conversation remembers the entities). */
function FollowUps({ m, onAsk }: { m: any; onAsk: (q: string) => void }) {
  const p = m.payload || {};
  const s: string[] = [];
  if (m.kind === "cql" && p.result?.rows?.length) {
    const h = p.result.rows.find((r: any) => r.ComputerName)?.ComputerName;
    if (h) s.push(`summarize ${h}`, `timeline of ${h}`);
  }
  if (m.kind === "ioc" && p.hunt) s.push(p.kind === "ipv4" ? `which endpoints connected to ${p.value}` : p.kind?.startsWith("sha") || p.kind === "md5" ? `did ${p.value} execute anywhere` : `which machines looked up ${p.hunt_slot?.domain}`);
  if (m.kind === "explain" && p.kind === "asset") s.push("show its timeline", "what vulnerabilities does it have");
  if (m.kind === "explain" && p.kind === "detection") s.push("explain the host it fired on");
  if (!s.length) return null;
  return <div className="mt-2.5 flex flex-wrap gap-1.5">{s.slice(0, 3).map((x) => <button key={x} onClick={() => onAsk(x)} className="rounded-full border border-border bg-surface px-2.5 py-0.5 text-[11.5px] text-fg-2 transition hover:border-violet hover:text-violet-fg">↳ {x}</button>)}</div>;
}

function PathMsg({ p, text }: { p: any; text: string }) {
  if (!p.found) return <div className="text-[13px]">{text}</div>;
  const lb = p.labels || {};
  return (
    <div className="space-y-2 text-[13px]">
      <div><b>{lb[p.path[0]]}</b> connects to <b>{lb[p.path[p.path.length - 1]]}</b> in {p.hops.length} hop{p.hops.length === 1 ? "" : "s"}:</div>
      <div className="flex flex-wrap items-center gap-1.5 rounded-xl border border-border bg-surface-2/50 p-2.5">
        {p.path.map((id: string, i: number) => (
          <React.Fragment key={id}>
            <span className="rounded-lg border border-border bg-surface px-2 py-1 text-[12px] shadow-card"><span className="mr-1 text-[10px] uppercase text-muted">{id.split(":")[0]}</span>{lb[id] || id}</span>
            {i < p.path.length - 1 && <span className="text-[11px] text-violet-fg">— {p.hops[i]?.rel} →</span>}
          </React.Fragment>
        ))}
      </div>
      <Link href={`/falcon-mcp/?tab=fabric&view=explore&node=${encodeURIComponent(p.path[0])}`} className="text-[12px] text-accent-fg hover:underline">Explore it in the data-fabric graph →</Link>
    </div>
  );
}

function KnowledgeMsg({ p }: { p: any }) {
  return (
    <div className="space-y-2 text-[13px]">
      {p.answer && <div className="whitespace-pre-wrap leading-relaxed">{p.answer}</div>}
      {!p.answer && p.passages?.length > 0 && <div className="text-fg-2">From the knowledge base:</div>}
      {p.passages?.map((x: any, i: number) => (
        <div key={i} className="rounded-xl border border-border bg-surface px-3 py-2 text-[12px]"><span className="mr-1 text-violet-fg">[{i + 1}]</span><b>{x.title}</b> <span className="text-fg-2">{x.snippet}</span></div>
      ))}
    </div>
  );
}

function HuntMsg({ p }: { p: any }) {
  const [all, setAll] = React.useState(false);
  const [q, setQ] = React.useState(false);
  if (p.need?.length) return <div className="text-[13px]">For <b>{p.title}</b> I need <b>{p.need.join(", ")}</b> — e.g. add a host name, IP or value to the question.</div>;
  const rows: any[] = p.rows || [];
  const cols: string[] = p.columns || [];
  return (
    <div className="space-y-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <b>{p.title}</b><span className="text-[11.5px] text-muted">{p.tool?.startsWith("fabric:") ? "data fabric" : `last ${p.days}d`}{p.run_seconds != null ? ` · ${p.run_seconds}s` : ""}</span>
        {p.id && <span className="ml-auto"><Feedback id={p.id} /></span>}
      </div>
      {!p.ok && <div className="rounded-lg bg-crit-soft px-3 py-2 text-crit-fg">{p.error}</div>}
      {p.ok && p.facts?.length > 0 && <div className="flex flex-wrap gap-1.5">{p.facts.map((f: string) => <span key={f} className="rounded-full bg-surface-2 px-2.5 py-0.5 text-[12px]">{f}</span>)}</div>}
      {p.summary && <div className="whitespace-pre-wrap rounded-xl border border-violet/25 bg-violet-soft/40 p-3 text-[12.5px] leading-relaxed"><Sparkles className="mr-1 inline size-3.5 text-violet-fg" />{p.summary}</div>}
      {rows.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-border">
          <div className="max-h-72 overflow-auto scroll-thin">
            <table className="w-full text-[11.5px]">
              <thead className="sticky top-0 bg-surface-2 text-left text-muted"><tr>{cols.map((c) => <th key={c} className="whitespace-nowrap px-2.5 py-1.5 font-medium">{c.split(".").pop()!.replace(/_/g, " ")}</th>)}</tr></thead>
              <tbody>{(all ? rows : rows.slice(0, 8)).map((r, i) => <tr key={i} className="border-t border-border">{cols.map((c) => <td key={c} className="max-w-[220px] truncate px-2.5 py-1" title={String(r[c] ?? "")}>{String(r[c] ?? "")}</td>)}</tr>)}</tbody>
            </table>
          </div>
          {rows.length > 8 && <button className="w-full border-t border-border py-1 text-[11.5px] text-accent-fg hover:bg-surface-2" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${fmtN(p.total ?? rows.length)} rows`}</button>}
        </div>
      )}
      {p.ok && !p.summary && <SummarizeButton question={p.question} template={p.template} rows={rows} />}
      {p.tool && <button className="block text-[11.5px] text-muted hover:text-fg" onClick={() => setQ(!q)}>{q ? "▾" : "▸"} {p.tool.startsWith("fabric:") ? "Answered from the data fabric (no CrowdStrike call)" : `Query sent to CrowdStrike (${p.tool})`}</button>}
      {q && <pre className="overflow-auto rounded-lg bg-surface-2 p-2 font-mono text-[11px]">{JSON.stringify(p.args, null, 2)}</pre>}
    </div>
  );
}

function Feedback({ id }: { id: number }) {
  const [v, setV] = React.useState(0);
  const send = async (good: boolean) => { setV(good ? 1 : -1); try { await api("/api/ai/feedback", { method: "POST", body: { id, good } }); } catch {} };
  return (
    <span className="flex items-center gap-1 text-[11px] text-muted">right hunt?
      <button onClick={() => send(true)} className={cn("rounded-full border px-1.5", v === 1 ? "border-good bg-good-soft text-good-fg" : "border-border")}>yes</button>
      <button onClick={() => send(false)} className={cn("rounded-full border px-1.5", v === -1 ? "border-crit bg-crit-soft text-crit-fg" : "border-border")}>no</button>
    </span>
  );
}
