"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import Link from "next/link";
import { BookOpen, Crosshair, Download, ExternalLink, Maximize2, History as History_, Network, Power, Settings2, Sparkles, Terminal, Trash2, Upload, Zap } from "lucide-react";
import { api, apiUpload } from "@/lib/api";
import { ChatPanel, Orb } from "@/components/ai/chat";
import { HuntStudio, CqlEval } from "@/components/ai/cql";
import { GraphExplorer, OntologyView } from "@/components/ai/graph";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, Field, FilterSelect, Input, Loading, Modal, PageHeader, SearchInput, Segmented, Sheet, Tabs, useConfirm } from "@/components/ui";

const TABS = [["chat", "Assistant", Sparkles], ["studio", "Hunt studio", Crosshair], ["fabric", "Data fabric", Network], ["kb", "Knowledge", BookOpen], ["history", "Activity", History_]] as const;

/** AI SOC: the assistant, CQL hunt studio, the data-fabric ontology and graph, the knowledge base, and every call it made. */
export default function FalconMcp({ full }: { full?: boolean } = {}) {
  const qc = useQueryClient();
  const [state, , replaceAll] = useUrlState();
  const tab = TABS.some(([id]) => id === state.tab) ? state.tab : "chat";
  const { data: st, refetch } = useQuery({ queryKey: ["mcp-status"], queryFn: () => api<any>("/api/mcp/status"), refetchInterval: 15_000 });
  const { data: ai, refetch: aiRefetch } = useQuery({ queryKey: ["ai-config"], queryFn: () => api<any>("/api/ai/config"), refetchInterval: 30_000 });
  const { data: soc } = useQuery({ queryKey: ["aisoc-status"], queryFn: () => api<any>("/api/cql/status"), refetchInterval: 30_000 });
  const [busy, setBusy] = React.useState(false);
  const [cfg, setCfg] = React.useState(false);
  if (!st) return <Loading />;
  const connect = async (stop?: boolean) => {
    setBusy(true);
    try { await api(stop ? "/api/mcp/stop" : "/api/mcp/start", { method: "POST" }); toast.success(stop ? "Falcon MCP stopped" : "Falcon MCP connected"); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); refetch(); qc.invalidateQueries({ queryKey: ["mcp-tools"] }); }
  };
  const modelReady = ai && ai.provider !== "off" && (ai.provider !== "ollama" || (ai.reachable && ai.model_installed));
  return (
    <div>
      <div className="relative mb-4 overflow-hidden rounded-3xl border border-border bg-[linear-gradient(120deg,#1e1b4b,#1e3a8a_55%,#0e7490)] px-5 py-4 text-white shadow-[0_20px_50px_-25px_#312e81]">
        <div className="pointer-events-none absolute -right-16 -top-24 size-72 rounded-full bg-[radial-gradient(circle,rgba(168,85,247,.55),transparent_65%)] blur-2xl" />
        <div className="pointer-events-none absolute -bottom-28 left-1/3 size-72 rounded-full bg-[radial-gradient(circle,rgba(34,211,238,.35),transparent_65%)] blur-2xl" />
        <div className="relative flex flex-wrap items-center gap-3">
          <Orb size={44} />
          <div className="min-w-0">
            <h1 className="text-[21px] font-semibold tracking-tight">AI SOC</h1>
            <div className="text-[12.5px] text-white/75">Agentic analyst over CrowdStrike, the data fabric and your playbooks · Splunk and NDR next</div>
          </div>
          <div className="flex-1" />
          {!full && <Link href={`/ai/${tab === "chat" ? "" : `?tab=${tab}`}`}><Button className="border-white/25 bg-white/10 text-white hover:bg-white/20" title="AI SOC without the console navigation"><Maximize2 /> Full window</Button></Link>}
          <Button className="border-white/25 bg-white/10 text-white hover:bg-white/20" title="Open the AI SOC in a new browser tab" onClick={() => window.open(`/ai/${tab === "chat" ? "" : `?tab=${tab}`}`, "_blank", "noopener")}><ExternalLink /> New tab</Button>
          <Button className="border-white/25 bg-white/10 text-white hover:bg-white/20" onClick={() => setCfg(true)}><Settings2 /> Settings</Button>
        </div>
        <div className="relative mt-3.5 flex flex-wrap gap-2">
          <Pill ok={!!soc?.live} label="CrowdStrike" value={soc?.live_label || "…"} title={soc?.live === "direct" ? "IOC checks and CQL hunts call the CrowdStrike API directly with the sync's credentials — Falcon MCP is optional" : undefined} />
          <Pill ok={!!modelReady} warn={!modelReady} label="Model" value={ai?.provider === "off" ? "off · rules only" : modelReady ? `${ai.model} · on-prem` : "not ready · rules"} />
          <Pill ok={st.running} label="Falcon MCP" value={st.running ? `${st.counts?.tools ?? "?"} tools${st.read_only ? " · read-only" : ""}` : "optional · idle"}
            action={st.running ? <button className="ml-1 opacity-70 hover:opacity-100" title="Stop" onClick={() => connect(true)} disabled={busy}><Power className="size-3" /></button>
              : <button className="ml-1 underline-offset-2 opacity-80 hover:underline" onClick={() => connect()} disabled={busy}>connect</button>} />
          <Pill ok label="Hunts" value={`${soc?.library ?? "…"} tested${soc?.saved ? ` + ${soc.saved} saved` : ""}`} />
          <Pill ok label="Knowledge" value={`${soc?.kb_docs ?? "…"} documents`} />
          {st.demo && <Pill ok label="Data" value="sample" />}
        </div>
      </div>
      <div className="mb-4 flex gap-1 overflow-x-auto rounded-2xl border border-border bg-surface p-1 shadow-card">
        {TABS.map(([id, label, Icon]) => (
          <button key={id} onClick={() => replaceAll(id === "chat" ? {} : { tab: id })}
            className={cn("flex items-center gap-1.5 whitespace-nowrap rounded-xl px-3.5 py-2 text-[13px] font-medium transition",
              tab === id ? "bg-[linear-gradient(135deg,var(--violet),var(--accent))] text-white shadow" : "text-fg-2 hover:bg-surface-2 hover:text-fg")}><Icon className="size-4" />{label}</button>
        ))}
      </div>
      {tab === "chat" && <ChatPanel />}
      {tab === "studio" && <Studio t={state.t} />}
      {tab === "fabric" && <Fabric q0={state.q || ""} view0={state.view} node0={state.node} />}
      {tab === "kb" && <KnowledgeBase />}
      {tab === "history" && <><History />{st.log?.length > 0 && <ServerLog lines={st.log} />}</>}
      {cfg && <SettingsDialog st={st} ai={ai} onClose={() => { setCfg(false); refetch(); aiRefetch(); }} />}
    </div>
  );
}

const Pill = ({ ok, warn, label, value, title, action }: { ok: boolean; warn?: boolean; label: string; value: React.ReactNode; title?: string; action?: React.ReactNode }) => (
  <span title={title} className="flex items-center gap-1.5 rounded-full border border-white/15 bg-white/10 px-2.5 py-1 text-[11.5px] backdrop-blur">
    <span className={cn("size-1.5 rounded-full", ok ? "bg-emerald-400 shadow-[0_0_6px_#34d399]" : warn ? "bg-amber-400" : "bg-white/40")} />
    <span className="text-white/60">{label}</span><span className="font-medium">{value}</span>{action}</span>
);

function Studio({ t }: { t?: string }) {
  const [init, setInit] = React.useState<{ cql?: string; q?: string } | undefined>();
  React.useEffect(() => {
    try { const v = sessionStorage.getItem("studio-open"); if (v) { setInit(JSON.parse(v)); sessionStorage.removeItem("studio-open"); } } catch {}
  }, [t]);
  return <HuntStudio initial={init} />;
}

/* ---------------- data fabric ---------------- */
function Fabric({ q0, view0, node0 }: { q0: string; view0?: string; node0?: string }) {
  const [, set] = useUrlState();
  const view = view0 || (q0 || node0 ? "explore" : "ontology");
  const [typeHint, setTypeHint] = React.useState<string | undefined>();
  const start = node0 || (q0 ? `asset:${q0}` : undefined);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={view} onChange={(v) => set({ view: v, q: undefined, node: undefined })}
          options={[["ontology", "Ontology"], ["explore", "Graph explorer"], ["sources", "Sources"], ["alerts", "Unified alerts"]] as any} />
        <span className="text-[12px] text-fg-2">{view === "ontology" ? "What kinds of things the console knows and how they relate" : view === "explore" ? "Walk the connections between real entities"
          : view === "sources" ? "Every source the AI SOC reads, with freshness" : "Detections and NDR alerts in one OCSF-style shape"}</span>
      </div>
      {view === "ontology" && <OntologyView onPick={(t) => { setTypeHint(t); set({ view: "explore" }); }} />}
      {view === "explore" && <GraphExplorer start={start} typeHint={typeHint} />}
      {view === "sources" && <Sources />}
      {view === "alerts" && <UnifiedAlerts />}
    </div>
  );
}

function Sources() {
  const { data: cat } = useQuery({ queryKey: ["fabric-catalog"], queryFn: () => api<any>("/api/fabric/catalog") });
  if (!cat) return <Loading />;
  return (
    <div className="space-y-3">
      {cat.links && <div className="flex flex-wrap gap-2">
        {[["assets in the registry", cat.links.assets], ["agents matched to inventory", cat.links.agents_in_inventory], ["detections on known assets", cat.links.detections_on_known_assets]].map(([l, v]) => (
          <div key={l as string} className="rounded-2xl border border-border bg-surface px-4 py-2.5 shadow-card"><div className="text-[18px] font-semibold tabular">{fmtN(v as number)}</div><div className="text-[11.5px] text-muted">{l}</div></div>))}
      </div>}
      <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
        {cat.rows.map((d: any) => (
          <Link key={d.id} href={d.page} className="group rounded-2xl border border-border bg-surface p-3.5 shadow-card transition hover:-translate-y-0.5 hover:border-violet/50">
            <div className="flex items-center gap-1.5"><span className={cn("size-2 rounded-full", d.status === "connected" ? "bg-good" : d.status === "empty" ? "bg-warn" : "bg-muted")} />
              <b className="truncate text-[12.5px]">{d.label}</b><span className="ml-auto text-[13px] font-semibold tabular">{fmtN(d.rows)}</span></div>
            <div className="mt-0.5 truncate text-[11px] text-muted">{d.source} · {d.entity}{d.fresh ? ` · ${fmtRel(d.fresh)}` : ""}</div>
            <div className="mt-1.5 line-clamp-2 text-[11.5px] text-fg-2">{d.description}</div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function UnifiedAlerts() {
  const { data: al } = useQuery({ queryKey: ["fabric-alerts"], queryFn: () => api<any>("/api/fabric/alerts", { params: { size: 50 } }) });
  if (!al) return <Loading />;
  return (
    <Card>
      <div className="max-h-[65vh] overflow-auto scroll-thin">
        <table className="w-full text-[12px]"><thead className="sticky top-0 bg-surface-2 text-left text-[11px] text-muted"><tr>
          <th className="px-3 py-2">Time</th><th>Source</th><th>Class</th><th>Severity</th><th>Title</th><th>Device</th><th>MITRE</th></tr></thead>
          <tbody>{al.rows.map((r: any, i: number) => <tr key={i} className="border-t border-border">
            <td className="px-3 py-1.5">{fmtRel(r.time)}</td><td className="pr-2">{r.source}</td><td className="pr-2 text-fg-2">{r.class}</td>
            <td className="pr-2"><Badge tone={/crit/i.test(r.severity) ? "crit" : /high/i.test(r.severity) ? "serious" : /med/i.test(r.severity) ? "warn" : "neutral"}>{r.severity}</Badge></td>
            <td className="max-w-[320px] truncate pr-2">{r.title}</td><td className="pr-2">{r.device?.hostname || r.device?.ip || "–"}</td>
            <td className="text-fg-2">{r.mitre?.tactic || "–"}</td></tr>)}</tbody></table>
      </div>
      <div className="border-t border-border px-3 py-2 text-[11px] text-muted">{fmtN(al.total)} alerts across sources</div>
    </Card>
  );
}

/* ---------------- knowledge base ---------------- */
function KnowledgeBase() {
  const qc = useQueryClient();
  const [q, setQ] = React.useState("");
  const [open, setOpen] = React.useState<number | null>(null);
  const [adding, setAdding] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement>(null);
  const { data: docs } = useQuery({ queryKey: ["kb-docs"], queryFn: () => api<any>("/api/kb/docs") });
  const { data: hits } = useQuery({ queryKey: ["kb-search", q], queryFn: () => api<any>("/api/kb/search", { params: { q } }), enabled: q.length > 2 });
  const { data: doc } = useQuery({ queryKey: ["kb-doc", open], queryFn: () => api<any>(`/api/kb/docs/${open}`), enabled: open != null });
  const upload = async (f: File) => {
    const fd = new FormData(); fd.append("file", f);
    try { await apiUpload("/api/kb/upload", fd, () => {}); toast.success(`${f.name} added`); qc.invalidateQueries({ queryKey: ["kb-docs"] }); } catch (e: any) { toast.error(e.message); }
  };
  const importGuides = async () => {
    setBusy(true);
    try { const r = await api<any>("/api/kb/import-guides", { method: "POST" }); toast.success(`${r.imported} Falcon guides imported`); qc.invalidateQueries({ queryKey: ["kb-docs"] }); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const del = async (id: number) => { await api(`/api/kb/docs/${id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["kb-docs"] }); };
  const [hubBusy, setHubBusy] = React.useState(false);
  const importHub = async () => {
    setHubBusy(true);
    try { const r = await api<any>("/api/cql/hub/import", { method: "POST" }); toast.success(`${r.imported} CQL Hub queries imported`); qc.invalidateQueries({ queryKey: ["kb-docs"] }); qc.invalidateQueries({ queryKey: ["cql-hub"] }); }
    catch (e: any) { toast.error(e.message); } finally { setHubBusy(false); }
  };
  const rows: any[] = docs?.rows || [];
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Card>
        <CardHeader title="Documents" hint="SOPs, playbooks, escalation matrix, case notes — the assistant quotes them with the source named"
          right={<span className="flex gap-1.5"><Button size="sm" onClick={() => setAdding(true)}>Paste text</Button>
            <Button size="sm" onClick={() => fileRef.current?.click()}><Upload /> Upload</Button>
            <Button size="sm" loading={busy} onClick={importGuides} title="FQL / CQL guides from the Falcon MCP server">Import Falcon guides</Button>
            <Button size="sm" loading={hubBusy} onClick={importHub} title="ByteRay CQL Hub: open (MIT) community library of Next-Gen SIEM queries">Import CQL Hub</Button></span>} />
        <input ref={fileRef} type="file" accept=".txt,.md,.csv,.html,.htm,.json,.log" className="hidden" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
        <div className="max-h-[60vh] overflow-y-auto px-2 pb-3 scroll-thin">
          {rows.map((d) => (
            <div key={d.id} onClick={() => setOpen(d.id)} className={cn("group flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 hover:bg-surface-2", open === d.id && "bg-accent-soft")}>
              <BookOpen className="size-4 shrink-0 text-muted" />
              <div className="min-w-0 flex-1"><div className="truncate text-[12.5px] font-medium">{d.title}</div>
                <div className="text-[10.5px] text-muted">{d.kind} · {d.source} · {fmtN(d.chars)} chars · {d.chunks} passages</div></div>
              {d.builtin ? <Badge tone="neutral">built-in</Badge> : <button className="invisible rounded p-1 text-muted hover:text-crit-fg group-hover:visible" onClick={(e) => { e.stopPropagation(); del(d.id); }}><Trash2 className="size-3.5" /></button>}
            </div>
          ))}
        </div>
      </Card>
      <div className="space-y-4">
        <Card className="p-3">
          <SearchInput className="w-full" value={q} onChange={setQ} placeholder="Search the knowledge base (what the assistant would find)…" />
          {hits?.rows?.map((h: any, i: number) => (
            <button key={i} onClick={() => setOpen(h.doc_id)} className="mt-2 block w-full rounded-lg bg-surface-2 px-2.5 py-1.5 text-left text-[12px] hover:bg-surface-3">
              <b>{h.title}</b> <span className="text-fg-2">{h.snippet}</span></button>
          ))}
          {q.length > 2 && hits && !hits.rows.length && <div className="mt-2 text-[12px] text-muted">No passage matches.</div>}
        </Card>
        <Card className="max-h-[60vh] overflow-auto p-4 scroll-thin">
          {!open ? <div className="text-[12.5px] text-muted">Pick a document to read it.</div> : !doc ? <Loading /> :
            <><div className="mb-2 text-[14px] font-semibold">{doc.title}</div><pre className="whitespace-pre-wrap font-sans text-[12.5px] leading-relaxed">{doc.text}</pre></>}
        </Card>
      </div>
      {adding && <AddDoc onClose={() => { setAdding(false); qc.invalidateQueries({ queryKey: ["kb-docs"] }); }} />}
    </div>
  );
}

function AddDoc({ onClose }: { onClose: () => void }) {
  const [title, setTitle] = React.useState("");
  const [kind, setKind] = React.useState("sop");
  const [text, setText] = React.useState("");
  const save = async () => { try { await api("/api/kb/docs", { method: "POST", body: { title, kind, text } }); toast.success("Added"); onClose(); } catch (e: any) { toast.error(e.message); } };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title="Add to the knowledge base" wide
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" onClick={save} disabled={!title || !text}>Add</Button></>}>
      <div className="space-y-3">
        <div className="flex gap-2"><Input className="flex-1" placeholder="Title, e.g. Escalation matrix — Payments LOB" value={title} onChange={(e) => setTitle(e.target.value)} />
          <select className="h-9 rounded-lg border border-border-strong bg-surface px-2 text-[13px]" value={kind} onChange={(e) => setKind(e.target.value)}>
            {["sop", "playbook", "policy", "contacts", "case", "note"].map((k) => <option key={k} value={k}>{k}</option>)}</select></div>
        <textarea className="h-72 w-full rounded-lg border border-border-strong bg-surface p-3 text-[13px]" value={text} onChange={(e) => setText(e.target.value)}
          placeholder="Paste the document text. Blank lines separate passages; the assistant finds and quotes the matching passages." />
      </div>
    </Modal>
  );
}

function History() {
  const [open, setOpen] = React.useState<number | null>(null);
  const { data, error } = useQuery({ queryKey: ["mcp-runs"], queryFn: () => api<any>("/api/mcp/runs") });
  const { data: one } = useQuery({ queryKey: ["mcp-run", open], queryFn: () => api<any>(`/api/mcp/runs/${open}`), enabled: open != null });
  if (!data) return <Loading error={error} />;
  return (
    <Card>
      <div className="max-h-[calc(100vh-260px)] overflow-auto scroll-thin">
        <table className="w-full text-[12.5px]">
          <thead className="sticky top-0 bg-surface-2 text-left text-[11.5px] text-muted"><tr>
            <th className="px-3 py-2">When</th><th className="px-3 py-2">Tool</th><th className="px-3 py-2">Arguments</th><th className="px-3 py-2">Result</th><th className="px-3 py-2 text-right">Time</th></tr></thead>
          <tbody>
            {data.rows.map((r: any) => (
              <tr key={r.id} className="cursor-pointer border-t border-border hover:bg-surface-2" onClick={() => setOpen(r.id)}>
                <td className="whitespace-nowrap px-3 py-1.5" title={fmtDt(r.at)}>{fmtRel(r.at)}</td>
                <td className="px-3 py-1.5 font-mono">{r.tool}{!r.read_only && <Badge tone="warn" className="ml-1">write</Badge>}</td>
                <td className="max-w-[420px] truncate px-3 py-1.5 font-mono text-[11.5px] text-fg-2">{JSON.stringify(r.args)}</td>
                <td className="px-3 py-1.5">{r.ok ? <Badge tone="good">ok · {fmtN(r.size)} chars</Badge> : <Badge tone="crit" title={r.error}>error</Badge>}</td>
                <td className="px-3 py-1.5 text-right tabular">{r.seconds}s</td>
              </tr>
            ))}
            {!data.rows.length && <tr><td colSpan={5} className="px-3 py-6 text-center text-muted">No calls yet</td></tr>}
          </tbody>
        </table>
      </div>
      <Sheet open={open != null} onOpenChange={(o) => !o && setOpen(null)} width={980} title={one ? one.tool : "Run"} sub={one ? `${fmtDt(one.at)} · ${one.seconds}s` : undefined}>
        {one ? <><pre className="mb-3 rounded-lg bg-surface-2 p-3 font-mono text-[11.5px]">{JSON.stringify(one.args, null, 2)}</pre>
          <Result res={{ ...one, ok: !!one.ok }} busy={false} /></> : <Loading />}
      </Sheet>
    </Card>
  );
}


/* ---------------- results ---------------- */
function Result({ res, busy }: { res: any; busy: boolean }) {
  const [raw, setRaw] = React.useState(false);
  const [open, setOpen] = React.useState<any>(null);
  const [q, setQ] = React.useState("");
  if (busy) return <Card className="p-6"><Loading /></Card>;
  if (!res) return null;
  if (!res.ok) return <Callout tone="crit" className="whitespace-pre-wrap">{res.error || "The tool reported an error"}</Callout>;
  const data = res.data;
  const rows: any[] | null = Array.isArray(data) ? data : Array.isArray(data?.results) ? data.results : null;
  const objRows = rows && rows.length && typeof rows[0] === "object" ? rows : null;
  const cols = objRows ? pickCols(objRows) : [];
  const shown = objRows ? objRows.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase())) : [];
  const meta = data && !Array.isArray(data) ? Object.fromEntries(Object.entries(data).filter(([k]) => k !== "results")) : null;
  const download = () => {
    const blob = new Blob([res.text ?? JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `${res.tool || "falcon"}-${Date.now()}.json`; a.click();
  };
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5 text-[12.5px]">
        <b>{objRows ? `${fmtN(objRows.length)} results` : "Result"}</b>
        <span className="text-muted">{res.tool} · {res.seconds}s · {fmtN(res.size)} chars</span>
        {objRows && <SearchInput className="ml-2 w-56" value={q} onChange={setQ} placeholder="Search in results…" />}
        <div className="flex-1" />
        <Button size="sm" variant="ghost" onClick={() => setRaw(!raw)}>{raw ? "Table" : "Raw JSON"}</Button>
        <Button size="sm" onClick={download}><Download /> JSON</Button>
      </div>
      {meta && Object.keys(meta).length > 0 && !raw && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-border px-4 py-2 text-[11.5px] text-fg-2">
          {Object.entries(meta).map(([k, v]) => <span key={k}><span className="text-muted">{k}: </span>{typeof v === "object" ? JSON.stringify(v).slice(0, 220) : String(v)}</span>)}
        </div>
      )}
      {raw || !objRows ? <pre className="max-h-[60vh] overflow-auto px-4 py-3 font-mono text-[11.5px] leading-relaxed scroll-thin">{res.text ?? JSON.stringify(data, null, 2)}</pre> : (
        <div className="max-h-[60vh] overflow-auto scroll-thin">
          <table className="w-full text-[12px]">
            <thead className="sticky top-0 bg-surface-2 text-left text-[11px] text-muted"><tr>{cols.map((c) => <th key={c} className="whitespace-nowrap px-3 py-2">{c}</th>)}</tr></thead>
            <tbody>{shown.slice(0, 500).map((r, i) => (
              <tr key={i} className="cursor-pointer border-t border-border align-top hover:bg-surface-2" onClick={() => setOpen(r)}>
                {cols.map((c) => <td key={c} className="max-w-[320px] truncate px-3 py-1.5" title={cell(r[c])}>{cell(r[c])}</td>)}
              </tr>))}</tbody>
          </table>
        </div>
      )}
      <Modal open={!!open} onOpenChange={(o) => !o && setOpen(null)} wide title="Record">
        <pre className="max-h-[65vh] overflow-auto font-mono text-[11.5px] scroll-thin">{JSON.stringify(open, null, 2)}</pre>
      </Modal>
    </Card>
  );
}

const PREFER = ["hostname", "name", "display_name", "severity_name", "severity", "status", "local_ip", "external_ip", "platform_name", "os_version", "agent_version",
  "created_timestamp", "@timestamp", "ComputerName", "FileName", "CommandLine", "tactic", "technique", "indicator", "type", "malicious_confidence", "last_seen", "device_id", "id"];
function pickCols(rows: any[]) {
  const keys = new Set<string>();
  rows.slice(0, 50).forEach((r) => Object.keys(r).forEach((k) => keys.add(k)));
  const scalar = [...keys].filter((k) => rows.slice(0, 20).some((r) => r[k] !== null && r[k] !== undefined && typeof r[k] !== "object"));
  const nested = [...keys].filter((k) => !scalar.includes(k) && rows.slice(0, 20).some((r) => r[k] && typeof r[k] === "object" && !Array.isArray(r[k])));
  const ordered = [...PREFER.filter((k) => scalar.includes(k)), ...scalar.filter((k) => !PREFER.includes(k))];
  return [...ordered.slice(0, 10), ...nested.slice(0, 2)];
}
function cell(v: any): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return Array.isArray(v) ? v.map((x) => (typeof x === "object" ? x.name || x.value || x.id || JSON.stringify(x) : x)).join(", ") : (v.hostname || v.id || v.name || JSON.stringify(v)).toString();
  return String(v);
}


function ServerLog({ lines }: { lines: string[] }) {
  const [open, setOpen] = React.useState(false);
  return (
    <Card className="mt-4">
      <button className="flex w-full items-center px-4 py-2.5 text-left text-[12.5px] font-medium" onClick={() => setOpen(!open)}>
        <Terminal className="mr-2 size-4 text-muted" /> falcon-mcp log <span className="ml-auto text-muted">{open ? "hide" : "show"}</span></button>
      {open && <pre className="max-h-64 overflow-auto border-t border-border px-4 py-3 font-mono text-[11px] text-fg-2 scroll-thin">{lines.join("\n")}</pre>}
    </Card>
  );
}

/** Settings: the AI model (Ask Falcon) and the Falcon MCP connection. */
function SettingsDialog({ st, ai, onClose }: { st: any; ai: any; onClose: () => void }) {
  const [tab, setTab] = React.useState("ai");
  return tab === "ai" ? <AiDialog ai={ai} onClose={onClose} onSwitch={() => setTab("mcp")} /> : <ConnectionDialog st={st} onClose={onClose} onSwitch={() => setTab("ai")} />;
}

function AiDialog({ ai, onClose, onSwitch }: { ai: any; onClose: () => void; onSwitch: () => void }) {
  const qc = useQueryClient();
  const [provider, setProvider] = React.useState(ai?.provider || "ollama");
  const [url, setUrl] = React.useState(ai?.url || "http://127.0.0.1:11434");
  const [model, setModel] = React.useState(ai?.model || "qwen3:8b");
  const [key, setKey] = React.useState("");
  const [summ, setSumm] = React.useState(ai?.summarize ?? true);
  const [busy, setBusy] = React.useState("");
  const { data: ev, refetch } = useQuery({ queryKey: ["ai-eval"], queryFn: () => api<any>("/api/ai/eval"), refetchInterval: (q) => ((q.state.data as any)?.running ? 2000 : false) });
  const save = async () => { await api("/api/ai/config", { method: "PUT", body: { provider, url, model, api_key: key || undefined, summarize: summ } }); qc.invalidateQueries({ queryKey: ["ai-config"] }); };
  const test = async () => {
    setBusy("test");
    try { await save(); const r = await api<any>("/api/ai/test", { method: "POST" }); r.ok ? toast.success(`Model answered in ${r.seconds}s: ${r.plan.template}`) : toast.error(r.error); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  const evaluate = async () => { try { await save(); await api("/api/ai/eval", { method: "POST" }); refetch(); } catch (e: any) { toast.error(e.message); } };
  const r = ev?.result;
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title="Settings · AI model" wide
      footer={<><Button variant="ghost" onClick={onSwitch}>Falcon MCP connection →</Button><div className="flex-1" /><Button onClick={onClose}>Close</Button>
        <Button variant="primary" onClick={async () => { await save(); toast.success("Saved"); onClose(); }}>Save</Button></>}>
      <div className="space-y-4 text-[13px]">
        <Segmented value={provider} onChange={setProvider} options={[["ollama", "Ollama (local)"], ["openai", "OpenAI-compatible (vLLM, LM Studio…)"], ["off", "Off — keywords only"]] as any} />
        {provider !== "off" && <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Server URL"><Input className="w-full" value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
          <Field label="Model" hint={provider === "ollama" ? (ai?.models?.length ? `installed: ${ai.models.join(", ")}` : "none installed — ollama pull qwen3:8b") : "model name on that server"}>
            {provider === "ollama" && ai?.models?.length ? <select className="h-9 w-full rounded-lg border border-border-strong bg-surface px-2" value={model} onChange={(e) => setModel(e.target.value)}>
              {[...new Set([model, ...ai.models])].map((m: string) => <option key={m} value={m}>{m}</option>)}</select>
              : <Input className="w-full" value={model} onChange={(e) => setModel(e.target.value)} />}
          </Field>
          {provider === "openai" && <Field label="API key" hint={ai?.key_set ? "saved — leave empty to keep" : "if the server needs one"}><Input className="w-full" type="password" value={key} onChange={(e) => setKey(e.target.value)} /></Field>}
          <label className="flex items-center gap-2"><input type="checkbox" className="accent-[var(--accent)]" checked={summ} onChange={(e) => setSumm(e.target.checked)} /> Write a short summary of each result</label>
        </div>}
        <p className="text-[12px] text-fg-2">Built for 4–8B on-prem models: the model fills a small JSON plan (forced schema, temperature 0, thinking off) — a hunt template, or a CQL query plan with enum-checked events and fields — and the console compiles, lints and runs the query. Tested library hunts answer common questions instantly without a model call. Questions and results stay on this machine.</p>
        {provider !== "off" && <div className="flex flex-wrap items-center gap-2">
          <Button loading={busy === "test"} onClick={test}><Zap /> Test the model</Button>
          <Button onClick={evaluate} disabled={ev?.running}>{ev?.running ? `Evaluating… ${ev.done}/${ev.total}` : `Evaluate routing (${ev?.total ?? 30} questions)`}</Button>
        </div>}
        {provider !== "off" && <CqlEval />}
        {r && (
          <Card className="p-3">
            <div className="mb-2 flex flex-wrap gap-x-4 text-[12.5px]"><b>{r.model}</b><span>routing accuracy <b>{r.model_accuracy}%</b></span><span>keywords {r.keyword_accuracy}%</span>
              <span>{r.avg_seconds}s per question</span><span className="text-muted">{fmtRel(r.at)}</span></div>
            {r.rows && <div className="max-h-52 overflow-auto text-[11.5px] scroll-thin">
              {r.rows.filter((x: any) => x.model !== x.expected).map((x: any) => <div key={x.question} className="border-t border-border py-1"><span className="text-crit-fg">✗</span> {x.question} → <span className="font-mono">{x.model || x.error}</span> (expected <span className="font-mono">{x.expected}</span>)</div>)}
              {r.rows.every((x: any) => x.model === x.expected) && <div className="text-good-fg">Every question routed correctly.</div>}
            </div>}
          </Card>
        )}
      </div>
    </Modal>
  );
}

function ConnectionDialog({ st, onClose, onSwitch }: { st: any; onClose: () => void; onSwitch?: () => void }) {
  const [mode, setMode] = React.useState(st.mode);
  const [url, setUrl] = React.useState(st.external_url || "");
  const [key, setKey] = React.useState("");
  const [mods, setMods] = React.useState<string>((st.modules || []).join("|"));
  const [ro, setRo] = React.useState(st.read_only);
  const [busy, setBusy] = React.useState(false);
  const save = async () => {
    setBusy(true);
    try {
      await api("/api/mcp/config", { method: "PUT", body: { mode, url, api_key: key || undefined, modules: mods.split("|").filter(Boolean), read_only: ro } });
      if (mode !== "off") await api("/api/mcp/start", { method: "POST" });
      toast.success(mode === "off" ? "Falcon MCP switched off" : "Saved and connected"); onClose();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title="Falcon MCP connection" wide
      footer={<>{onSwitch && <Button variant="ghost" onClick={onSwitch}>← AI model</Button>}<div className="flex-1" /><Button onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={save}>Save & connect</Button></>}>
      <div className="space-y-4 text-[13px]">
        <Segmented value={mode} onChange={setMode} options={[["managed", "Run by the console"], ["external", "My own falcon-mcp server"], ["off", "Off"]] as any} />
        {mode === "managed" && <p className="text-fg-2">The console starts the official <code>falcon-mcp</code> on 127.0.0.1 (random API key, never exposed) with the CrowdStrike API client saved under Sync & settings. The tools you can use depend on that client's API scopes.</p>}
        {mode === "external" && <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Server URL" hint="streamable HTTP endpoint, e.g. http://mcp-host:8000/mcp"><Input className="w-full" value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
          <Field label="API key (x-api-key)" hint={st.external_key_set ? "saved — leave empty to keep it" : "the --api-key the server runs with"}><Input className="w-full" type="password" value={key} onChange={(e) => setKey(e.target.value)} /></Field>
        </div>}
        {mode !== "off" && <>
          <Field label="Modules" hint="empty = all modules; fewer modules = fewer tools for an AI assistant to choose from">
            <FilterSelect label="Modules" value={mods} onChange={setMods} any="All modules" options={(st.available_modules || []).map((m: string) => [m, m])} />
          </Field>
          <label className="flex items-start gap-2 rounded-lg border border-border p-3">
            <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={!ro} onChange={(e) => setRo(!e.target.checked)} />
            <span><b>Allow write tools</b> (contain / release hosts, update detections, create IOCs, policies, exclusions…). Off by default. Even when on, each write call asks for confirmation and is recorded.
              {!ro && <span className="mt-1 block text-warn-fg">With write tools on, the read-only RTR command tool is not loaded (falcon-mcp offers it only in read-only mode).</span>}</span>
          </label>
        </>}
      </div>
    </Modal>
  );
}
