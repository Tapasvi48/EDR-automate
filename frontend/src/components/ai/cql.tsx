"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, BookMarked, Check, CheckCircle2, Copy, Cpu, Library, Play, Save, Search, Sparkles, Trash2, Wand2, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Loading, Segmented } from "../ui";

/* ---------------- CQL syntax highlighting (tags, fields, regexes, strings, functions, pipes) ---------------- */
const TOKEN = /(\/\/[^\n]*)|("(?:\\.|[^"\\])*")|((?<=[=(,\s]|^)\/(?:\\.|[^/\\\n])+\/[gimsx]*)|(#[\w.]+)|(\|)|(\b[a-zA-Z_:]+(?=\())|([@\w.]+(?=\s*(?:!=|<=|>=|=|<|>)))|(\b\d+\b)/gm;

export function CqlCode({ code, className }: { code: string; className?: string }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  let i = 0;
  while ((m = TOKEN.exec(code))) {
    if (m.index > last) parts.push(code.slice(last, m.index));
    const [t] = m;
    const cls = m[1] ? "text-muted italic" : m[2] ? "text-good-fg" : m[3] ? "text-serious-fg" : m[4] ? "text-violet-fg font-semibold" : m[5] ? "text-accent-fg font-bold"
      : m[6] ? "text-accent-fg" : m[7] ? "text-warn-fg" : "text-crit-fg";
    parts.push(<span key={i++} className={cls}>{t}</span>);
    last = m.index + t.length;
    if (t.length === 0) TOKEN.lastIndex++;
  }
  if (last < code.length) parts.push(code.slice(last));
  return <pre className={cn("whitespace-pre-wrap break-words font-mono text-[12px] leading-relaxed", className)}>{parts}</pre>;
}

const copy = (t: string) => { navigator.clipboard?.writeText(t); toast.success("Copied"); };

/* ---------------- result table ---------------- */
export function CqlResult({ r, max = 12 }: { r: any; max?: number }) {
  const [all, setAll] = React.useState(false);
  const [q, setQ] = React.useState("");
  if (!r) return null;
  if (!r.ok) return <div className="rounded-lg bg-crit-soft px-3 py-2 text-[12.5px] text-crit-fg">{r.error}</div>;
  const cols: string[] = r.columns || [];
  const rows: any[] = (r.rows || []).filter((x: any) => !q || JSON.stringify(x).toLowerCase().includes(q.toLowerCase()));
  const shown = all ? rows : rows.slice(0, max);
  const csv = () => {
    const esc = (v: any) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const blob = new Blob([[cols.join(","), ...rows.map((x) => cols.map((c) => esc(x[c])).join(","))].join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `hunt-${Date.now()}.csv`; a.click();
  };
  return (
    <div className="overflow-hidden rounded-xl border border-border">
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface-2/60 px-3 py-1.5 text-[11.5px]">
        <b className="text-[12px]">{fmtN(r.total)} result{r.total === 1 ? "" : "s"}</b>
        <span className="text-muted">{r.seconds}s · {r.via === "sample" ? "sample telemetry" : r.via === "direct" ? "CrowdStrike NG-SIEM (direct API)" : r.via === "mcp" ? "via Falcon MCP" : r.via}
          {r.meta?.processedEvents ? ` · ${fmtN(r.meta.processedEvents)} events scanned` : ""}</span>
        <div className="flex-1" />
        {r.rows?.length > 6 && <input className="h-6 w-40 rounded-md border border-border bg-bg px-2 text-[11.5px] outline-none" placeholder="Filter rows…" value={q} onChange={(e) => setQ(e.target.value)} />}
        {r.rows?.length > 0 && <button className="text-accent-fg hover:underline" onClick={csv}>CSV</button>}
      </div>
      {rows.length ? (
        <div className="max-h-80 overflow-auto scroll-thin">
          <table className="w-full text-[11.5px]">
            <thead className="sticky top-0 bg-surface text-left text-muted"><tr>{cols.map((c) => <th key={c} className="whitespace-nowrap px-2.5 py-1.5 font-medium">{c}</th>)}</tr></thead>
            <tbody>{shown.map((x, i) => <tr key={i} className="border-t border-border hover:bg-surface-2/60">{cols.map((c) => (
              <td key={c} className={cn("max-w-[340px] truncate px-2.5 py-1", /CommandLine|HashData|Reg/.test(c) && "font-mono text-[11px]", c === "_count" && "text-right font-semibold tabular")} title={String(x[c] ?? "")}>{String(x[c] ?? "")}</td>))}</tr>)}</tbody>
          </table>
        </div>
      ) : <div className="px-3 py-4 text-center text-[12px] text-muted">Nothing matched in this time range — a clean result is a result.</div>}
      {rows.length > max && <button className="w-full border-t border-border py-1 text-[11.5px] text-accent-fg hover:bg-surface-2" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${fmtN(rows.length)} rows`}</button>}
    </div>
  );
}

/* ---------------- lint badge row ---------------- */
function LintRow({ lt }: { lt: any }) {
  if (!lt) return null;
  return (
    <div className="space-y-1 text-[11.5px]">
      {lt.errors?.map((e: string) => <div key={e} className="flex items-start gap-1.5 text-crit-fg"><XCircle className="mt-0.5 size-3.5 shrink-0" />{e}</div>)}
      {lt.warnings?.map((e: string) => <div key={e} className="flex items-start gap-1.5 text-warn-fg"><AlertTriangle className="mt-0.5 size-3.5 shrink-0" />{e}</div>)}
      {lt.changes?.length > 0 && <div className="flex items-start gap-1.5 text-accent-fg"><Wand2 className="mt-0.5 size-3.5 shrink-0" />Auto-fixed: {lt.changes.join(" · ")}</div>}
      {lt.ok && !lt.errors?.length && !lt.warnings?.length && <div className="flex items-center gap-1.5 text-good-fg"><CheckCircle2 className="size-3.5" />Valid CQL</div>}
    </div>
  );
}

const SOURCE_LABEL = (s?: string) => !s ? "" : s.startsWith("library:") ? "tested library hunt" : s === "entities" ? "built from the question's values" : s.startsWith("model") ? `written by the local model${s.includes("free") ? " (free-form)" : ""}` : s;

/* ---------------- a CQL hunt inside a chat message ---------------- */
/** "Summarize with AI": the on-prem model reads the result rows (on demand, so answers are instant). */
export function SummarizeButton({ question, template, rows }: { question: string; template?: string; rows: any[] }) {
  const [busy, setBusy] = React.useState(false);
  const [out, setOut] = React.useState<any>(null);
  if (!rows?.length) return null;
  if (out) return <div className="whitespace-pre-wrap rounded-xl border border-violet/25 bg-violet-soft/40 p-3 text-[12.5px] leading-relaxed"><Sparkles className="mr-1 inline size-3.5 text-violet-fg" />{out.summary}<div className="mt-1 text-[10.5px] text-muted">{out.model} · {out.seconds}s · from the rows above only</div></div>;
  return <button disabled={busy} onClick={async () => { setBusy(true); try { setOut(await api("/api/ai/summarize", { method: "POST", body: { question, template, rows: rows.slice(0, 25) } })); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); } }}
    className="flex items-center gap-1.5 rounded-full border border-violet/30 bg-violet-soft/40 px-2.5 py-1 text-[11.5px] text-violet-fg hover:bg-violet-soft disabled:opacity-60"><Sparkles className={cn("size-3.5", busy && "animate-spin")} />{busy ? "Summarizing…" : "Summarize with AI"}</button>;
}

export function CqlMsg({ p, onOpenStudio }: { p: any; onOpenStudio?: (cql: string, q: string) => void }) {
  const [res, setRes] = React.useState<any>(p.result);
  const [busy, setBusy] = React.useState(false);
  const [why, setWhy] = React.useState(false);
  const rerun = async () => { setBusy(true); try { setRes(await api("/api/cql/run", { method: "POST", body: { cql: p.cql, days: p.days, question: p.question } })); } catch (e: any) { toast.error(e.message); } finally { setBusy(false); } };
  const save = async () => { try { await api("/api/cql/saved", { method: "POST", body: { title: p.title || p.question, question: p.question, cql: p.cql, plan: p.plan, mitre: p.mitre } }); toast.success("Saved to your hunt library — the assistant will reuse it"); } catch (e: any) { toast.error(e.message); } };
  return (
    <div className="space-y-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <b>{p.title || "CQL hunt"}</b>{p.mitre && <Badge tone="violet">{p.mitre}</Badge>}
        <span className="text-[11.5px] text-muted">{SOURCE_LABEL(p.source)} · last {p.days}d{p.seconds ? ` · ${p.seconds}s to write` : ""}</span>
      </div>
      {p.facts?.length > 0 && <div className="flex flex-wrap gap-1.5">{p.facts.map((f: string) => <span key={f} className="rounded-full bg-surface-2 px-2.5 py-0.5 text-[12px]">{f}</span>)}</div>}
      <div className="group relative overflow-hidden rounded-xl border border-border bg-surface-2/50">
        <div className="flex items-center gap-1 border-b border-border px-3 py-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">CQL
          <div className="flex-1" />
          <button className="rounded p-1 hover:bg-surface-3" title="Copy" onClick={() => copy(p.cql)}><Copy className="size-3.5" /></button>
          <button className="rounded p-1 hover:bg-surface-3" title="Save to library" onClick={save}><Save className="size-3.5" /></button>
          {onOpenStudio && <button className="rounded px-1.5 py-0.5 normal-case tracking-normal hover:bg-surface-3" onClick={() => onOpenStudio(p.cql, p.question)}>Edit in studio</button>}
          <button className="rounded px-1.5 py-0.5 normal-case tracking-normal hover:bg-surface-3" onClick={rerun} disabled={busy}><Play className="mr-0.5 inline size-3" />{busy ? "Running…" : "Run again"}</button>
        </div>
        <CqlCode code={p.cql} className="px-3 py-2" />
      </div>
      <CqlResult r={res} max={8} />
      <SummarizeButton question={p.question} template="hunt_process" rows={res?.rows || []} />
      <button className="block text-[11.5px] text-muted hover:text-fg" onClick={() => setWhy(!why)}>{why ? "▾" : "▸"} How this query works</button>
      {why && <div className="space-y-1.5 rounded-lg bg-surface-2/60 p-2.5 text-[12px]">
        <ol className="list-decimal space-y-0.5 pl-4 text-fg-2">{p.explain?.map((x: string) => <li key={x}>{x}</li>)}</ol>
        {p.notes?.length > 0 && <div className="text-[11.5px] text-accent-fg">{p.notes.join(" · ")}</div>}
        <LintRow lt={p.lint} />
        {p.model_error && <div className="text-[11.5px] text-muted">Model unavailable ({p.model_error.slice(0, 90)}) — built from the library / the question instead.</div>}
      </div>}
    </div>
  );
}

/* ---------------- Hunt studio: English -> CQL -> check -> run -> save ---------------- */
export function HuntStudio({ initial }: { initial?: { cql?: string; q?: string } }) {
  const qc = useQueryClient();
  const [q, setQ] = React.useState(initial?.q || "");
  const [cql, setCql] = React.useState(initial?.cql || "");
  const [mode, setMode] = React.useState<"auto" | "rules" | "model">("auto");
  const [style, setStyle] = React.useState<"plan" | "cql">("plan");
  const [days, setDays] = React.useState(7);
  const [gen, setGen] = React.useState<any>(null);
  const [lt, setLt] = React.useState<any>(null);
  const [res, setRes] = React.useState<any>(null);
  const [busy, setBusy] = React.useState("");
  const [libQ, setLibQ] = React.useState("");
  const [libTab, setLibTab] = React.useState<"tested" | "hub" | "saved">("tested");
  const [importing, setImporting] = React.useState(false);
  const { data: lib } = useQuery({ queryKey: ["cql-library"], queryFn: () => api<any>("/api/cql/library") });
  const { data: hub } = useQuery({ queryKey: ["cql-hub"], queryFn: () => api<any>("/api/cql/hub") });
  const importHub = async () => {
    setImporting(true);
    try { const r = await api<any>("/api/cql/hub/import", { method: "POST" }); toast.success(`${r.imported} CQL Hub queries imported — the AI now uses them as references`); qc.invalidateQueries({ queryKey: ["cql-hub"] }); qc.invalidateQueries({ queryKey: ["kb-docs"] }); }
    catch (e: any) { toast.error(e.message); } finally { setImporting(false); }
  };
  const hubRows = (hub?.rows || []).filter((x: any) => !libQ || `${x.name} ${x.mitre} ${x.tags} ${x.log_sources} ${x.description}`.toLowerCase().includes(libQ.toLowerCase()));
  React.useEffect(() => { if (initial?.cql) { setCql(initial.cql); setQ(initial.q || ""); } }, [initial?.cql, initial?.q]);
  React.useEffect(() => {
    if (!cql.trim()) { setLt(null); return; }
    const t = setTimeout(() => api<any>("/api/cql/lint", { method: "POST", body: { cql, fix: false } }).then(setLt).catch(() => {}), 350);
    return () => clearTimeout(t);
  }, [cql]);
  const generate = async () => {
    if (!q.trim()) return;
    setBusy("gen"); setRes(null);
    try { const g = await api<any>("/api/cql/generate", { method: "POST", body: { question: q, mode, style } }); setGen(g); setCql(g.cql); setDays(g.days || 7); }
    catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  const fix = async () => { const r = await api<any>("/api/cql/lint", { method: "POST", body: { cql, fix: true } }); setCql(r.cql); setLt(r); if (r.changes?.length) toast.success(`Fixed: ${r.changes.join(", ")}`); else toast.message("Nothing to auto-fix"); };
  const run = async () => { setBusy("run"); try { setRes(await api("/api/cql/run", { method: "POST", body: { cql, days, question: q } })); } catch (e: any) { toast.error(e.message); } finally { setBusy(""); } };
  const save = async () => { try { await api("/api/cql/saved", { method: "POST", body: { title: gen?.title || q || "Saved hunt", question: q, cql, plan: gen?.plan, mitre: gen?.mitre } }); toast.success("Saved"); qc.invalidateQueries({ queryKey: ["cql-library"] }); } catch (e: any) { toast.error(e.message); } };
  const unsave = async (id: number) => { await api(`/api/cql/saved/${id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: ["cql-library"] }); };
  const libRows = (lib?.rows || []).filter((x: any) => !libQ || `${x.title} ${x.mitre} ${x.tags}`.toLowerCase().includes(libQ.toLowerCase()));
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
      <div className="space-y-4">
        <div className="rounded-2xl border border-border bg-surface p-4 shadow-card">
          <div className="mb-2 flex items-center gap-2 text-[12px] font-semibold uppercase tracking-wider text-muted"><Sparkles className="size-3.5 text-violet-fg" /> Describe the hunt</div>
          <div className="flex gap-2">
            <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && generate()}
              className="h-11 flex-1 rounded-xl border border-border-strong bg-bg px-3.5 text-[14px] outline-none transition focus:border-violet focus:ring-4 focus:ring-violet/15"
              placeholder="e.g. office apps spawning powershell on PAY-SER-085 in the last 3 days" />
            <Button variant="primary" className="h-11 px-4" loading={busy === "gen"} onClick={generate}><Wand2 /> Write CQL</Button>
          </div>
          <div className="mt-2.5 flex flex-wrap items-center gap-2 text-[12px]">
            <Segmented value={mode} onChange={setMode} options={[["auto", "Auto"], ["rules", "Library + rules"], ["model", "Local model"]]} />
            {mode !== "rules" && <Segmented value={style} onChange={setStyle} options={[["plan", "Query plan (best for 4–8B)"], ["cql", "Free-form CQL"]]} />}
            {gen && <span className="text-muted">{SOURCE_LABEL(gen.source)} · {gen.seconds}s{gen.model_error ? " · model unavailable, used rules" : ""}</span>}
          </div>
          {gen?.references?.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11.5px]"><span className="text-muted">From the CQL Hub (community):</span>
              {gen.references.map((a: any) => <button key={a.id} onClick={() => setCql(a.cql)} title={`by ${a.author || "community"} · byteray.com/cql-hub`} className="rounded-full border border-border px-2 py-0.5 hover:border-accent hover:text-accent-fg">{a.title}{a.mitre ? ` · ${a.mitre.split(",")[0]}` : ""}</button>)}</div>
          )}
          {gen?.cached && <div className="mt-1 text-[11px] text-muted">Answered from the cache (asked before) · instant</div>}
          {gen?.alternatives?.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[11.5px]"><span className="text-muted">Similar tested hunts:</span>
              {gen.alternatives.map((a: any) => <button key={a.id} onClick={() => setCql(a.cql)} className="rounded-full border border-border px-2 py-0.5 hover:border-violet hover:text-violet-fg">{a.title}{a.mitre ? ` · ${a.mitre}` : ""}</button>)}</div>
          )}
        </div>

        <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
          <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2">
            <span className="text-[12px] font-semibold uppercase tracking-wider text-muted">CQL editor</span>
            {lt && (lt.ok ? <Badge tone="good"><Check className="mr-0.5 inline size-3" />valid</Badge> : <Badge tone="crit">{lt.errors.length} error{lt.errors.length === 1 ? "" : "s"}</Badge>)}
            {lt?.warnings?.length > 0 && <Badge tone="warn">{lt.warnings.length} warning{lt.warnings.length === 1 ? "" : "s"}</Badge>}
            <div className="flex-1" />
            <select className="h-8 rounded-lg border border-border-strong bg-surface px-2 text-[12px]" value={days} onChange={(e) => setDays(+e.target.value)}>
              {[1, 3, 7, 14, 30, 90].map((d) => <option key={d} value={d}>last {d} day{d === 1 ? "" : "s"}</option>)}</select>
            <Button size="sm" onClick={fix} disabled={!cql.trim()}><Wand2 /> Auto-fix</Button>
            <Button size="sm" onClick={() => copy(cql)} disabled={!cql.trim()}><Copy /></Button>
            <Button size="sm" onClick={save} disabled={!lt?.ok}><Save /> Save</Button>
            <Button size="sm" variant="primary" loading={busy === "run"} disabled={!lt?.ok} onClick={run}><Play /> Run</Button>
          </div>
          <div className="grid lg:grid-cols-2">
            <textarea value={cql} onChange={(e) => setCql(e.target.value)} spellCheck={false}
              className="min-h-[220px] w-full resize-y border-border bg-bg p-3.5 font-mono text-[12.5px] leading-relaxed outline-none lg:border-r"
              placeholder={"#event_simpleName=ProcessRollup2 FileName=/powershell/i CommandLine=/-enc/i\n| groupBy([ComputerName, UserName])\n| sort(_count, order=desc)"} />
            <div className="space-y-2.5 p-3.5">
              {cql.trim() ? <CqlCode code={cql} className="rounded-lg bg-surface-2/60 p-2.5" /> : <div className="text-[12px] text-muted">Write a query or describe the hunt above. Pick a tested hunt from the library on the right.</div>}
              <LintRow lt={lt} />
              {lt?.ok && <Explain cql={cql} />}
            </div>
          </div>
        </div>
        {busy === "run" && <div className="rounded-xl border border-border p-6"><Loading /></div>}
        {res && busy !== "run" && <CqlResult r={res} max={25} />}
      </div>

      <div className="space-y-4">
        <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
          <div className="flex items-center gap-2 border-b border-border px-3 py-2"><Library className="size-4 text-violet-fg" /><b className="text-[13px]">Hunt library</b></div>
          <div className="flex gap-1 px-2 pt-2 text-[11.5px]">
            {([["tested", `Tested · ${lib?.rows?.length || 0}`], ["hub", `CQL Hub · ${hub?.rows?.length || 0}`], ["saved", `Saved · ${lib?.saved?.length || 0}`]] as const).map(([id, l]) => (
              <button key={id} onClick={() => setLibTab(id)} className={cn("rounded-full px-2.5 py-1", libTab === id ? "bg-violet-soft font-medium text-violet-fg" : "text-muted hover:bg-surface-2")}>{l}</button>))}
          </div>
          <div className="p-2"><div className="relative"><Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted" />
            <input className="h-8 w-full rounded-lg border border-border bg-bg pl-7 pr-2 text-[12px] outline-none" placeholder="lateral movement, T1003, identity, M365…" value={libQ} onChange={(e) => setLibQ(e.target.value)} /></div></div>
          <div className="max-h-[52vh] overflow-y-auto px-1.5 pb-2 scroll-thin">
            {libTab === "saved" && (lib?.saved?.length ? lib.saved.map((s: any) => (
              <div key={`s${s.id}`} onClick={() => { setCql(s.cql); setQ(s.question || ""); }} className="group flex cursor-pointer items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-2">
                <BookMarked className="mt-0.5 size-3.5 shrink-0 text-good-fg" /><div className="min-w-0 flex-1"><div className="truncate text-[12.5px]">{s.title}</div><div className="text-[10.5px] text-muted">{fmtRel(s.created_at)}</div></div>
                <button className="invisible text-muted hover:text-crit-fg group-hover:visible" onClick={(e) => { e.stopPropagation(); unsave(s.id); }}><Trash2 className="size-3.5" /></button>
              </div>)) : <div className="p-2 text-[12px] text-muted">Save a query from the editor — the assistant reuses saved hunts as examples.</div>)}
            {libTab === "tested" && libRows.map((x: any) => (
              <div key={x.id} onClick={() => { setCql(x.cql); setQ(x.examples?.[0] || x.title); setGen(null); }} className="cursor-pointer rounded-lg px-2 py-1.5 hover:bg-surface-2">
                <div className="flex items-center gap-1.5"><span className="min-w-0 flex-1 truncate text-[12.5px]">{x.title}</span>{x.mitre && <span className="shrink-0 font-mono text-[10px] text-violet-fg">{x.mitre}</span>}</div>
                <div className="truncate text-[10.5px] text-muted">{x.event}{x.platform !== "any" ? ` · ${x.platform}` : ""}</div>
              </div>
            ))}
            {libTab === "hub" && (hub?.rows?.length ? <>
              <div className="px-2 pb-1 text-[10.5px] text-muted">Community queries from <a className="text-accent-fg hover:underline" href={hub.site} target="_blank" rel="noopener noreferrer">ByteRay CQL Hub</a> (MIT) · imported {fmtRel(hub.imported_at)} · <button className="text-accent-fg hover:underline" onClick={importHub} disabled={importing}>{importing ? "updating…" : "update"}</button></div>
              {hubRows.map((x: any) => (
                <div key={x.id} onClick={() => { setCql(x.cql); setQ(x.name); setGen(null); }} title={x.description} className="cursor-pointer rounded-lg px-2 py-1.5 hover:bg-surface-2">
                  <div className="flex items-center gap-1.5"><span className="min-w-0 flex-1 truncate text-[12.5px]">{x.name}</span>{x.mitre && <span className="shrink-0 font-mono text-[10px] text-violet-fg">{x.mitre.split(",")[0]}</span>}</div>
                  <div className="truncate text-[10.5px] text-muted">{[x.log_sources, x.tags, x.author && `by ${x.author}`].filter(Boolean).join(" · ")}</div>
                </div>))}</>
              : <div className="space-y-2 p-2 text-[12px] text-fg-2">
                  <p>The <a className="text-accent-fg hover:underline" href="https://www.byteray.com/cql-hub" target="_blank" rel="noopener noreferrer">CQL Hub</a> by ByteRay is an open (MIT) library of ~185 community hunting and detection queries for Next-Gen SIEM. Import it once: the queries become browsable here, searchable in the knowledge base, and reference examples for the AI.</p>
                  <Button size="sm" variant="primary" loading={importing} onClick={importHub}>Import CQL Hub from GitHub</Button>
                </div>)}
          </div>
        </div>
        <CqlEval />
      </div>
    </div>
  );
}

function Explain({ cql }: { cql: string }) {
  const { data } = useQuery({ queryKey: ["cql-explain", cql], queryFn: () => api<any>("/api/cql/lint", { method: "POST", body: { cql, fix: false } }), staleTime: 60_000 });
  if (!data?.explain?.length) return null;
  return <div className="rounded-lg border border-border p-2.5"><div className="mb-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">In plain English</div>
    <ol className="list-decimal space-y-0.5 pl-4 text-[12px] text-fg-2">{data.explain.map((x: string) => <li key={x}>{x}</li>)}</ol></div>;
}

/** Does the on-prem model write correct hunts? 24 questions, scored on event + values + valid CQL; rules alongside. */
export function CqlEval() {
  const { data, refetch } = useQuery({ queryKey: ["cql-eval"], queryFn: () => api<any>("/api/cql/eval"), refetchInterval: (q) => ((q.state.data as any)?.running ? 2500 : false) });
  const [open, setOpen] = React.useState(false);
  const start = async () => { try { await api("/api/cql/eval", { method: "POST", body: { style: "plan" } }); refetch(); } catch (e: any) { toast.error(e.message); } };
  const r = data?.result;
  return (
    <div className="rounded-2xl border border-border bg-surface p-3 shadow-card">
      <div className="flex items-center gap-2"><Cpu className="size-4 text-accent-fg" /><b className="text-[13px]">Model check</b>
        <div className="flex-1" /><Button size="sm" onClick={start} disabled={data?.running}>{data?.running ? `${data.done}/${data.total}…` : "Run"}</Button></div>
      <p className="mt-1 text-[11.5px] text-fg-2">Scores the local model on {data?.total ?? 24} hunting questions: right event, the question's values kept, valid CQL.</p>
      {r && <div className="mt-2 space-y-1.5">
        <Bar label={`${r.model} (model)`} v={r.model_accuracy} />
        <Bar label="Library + rules (no model)" v={r.rules_accuracy} />
        <div className="text-[11px] text-muted">{r.avg_seconds}s per question · {fmtRel(r.at)} <button className="ml-1 text-accent-fg" onClick={() => setOpen(!open)}>{open ? "hide" : "details"}</button></div>
        {open && <div className="max-h-56 overflow-y-auto text-[11px] scroll-thin">{r.rows.map((x: any) => (
          <div key={x.question} className="border-t border-border py-1"><span className={x.model_ok ? "text-good-fg" : "text-crit-fg"}>{x.model_ok ? "✓" : "✗"}</span> {x.question}
            {!x.model_ok && <div className="truncate font-mono text-muted" title={x.model_cql || x.error}>{x.model_cql || x.error}</div>}</div>))}</div>}
      </div>}
    </div>
  );
}

const Bar = ({ label, v }: { label: string; v: number }) => (
  <div><div className="flex justify-between text-[11.5px]"><span>{label}</span><b>{v}%</b></div>
    <div className="mt-0.5 h-1.5 overflow-hidden rounded-full bg-surface-3"><div className={cn("h-full rounded-full", v >= 85 ? "bg-good" : v >= 60 ? "bg-warn" : "bg-crit")} style={{ width: `${v}%` }} /></div></div>
);
