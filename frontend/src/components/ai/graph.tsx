"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowRight, ExternalLink, GitBranch, Locate, Maximize, Minus, Plus, Route, Search, Trash2, X } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button } from "../ui";
import { ExplainButton } from "./brief";

/* Entity types: colour + short tag */
export const TYPE: Record<string, { c: string; tag: string; label: string }> = {
  asset: { c: "#2a78d6", tag: "AS", label: "Asset" }, agent: { c: "#0ca30c", tag: "AG", label: "CrowdStrike agent" }, ip: { c: "#0891b2", tag: "IP", label: "IP address" },
  subnet: { c: "#64748b", tag: "SN", label: "Subnet" }, lob: { c: "#7c3aed", tag: "LB", label: "Line of business" }, msp: { c: "#a855f7", tag: "MS", label: "MSP" },
  user: { c: "#db2777", tag: "US", label: "User" }, detection: { c: "#dc2626", tag: "DT", label: "Detection" }, tactic: { c: "#ea580c", tag: "TA", label: "MITRE tactic" },
  file: { c: "#b45309", tag: "FL", label: "Process / file" }, cve: { c: "#e11d48", tag: "CV", label: "Vulnerability" }, policy: { c: "#16a34a", tag: "PL", label: "Policy" },
  ndr: { c: "#f97316", tag: "ND", label: "NDR alert" }, rule: { c: "#475569", tag: "RL", label: "Matrix rule" }, netblock: { c: "#0f766e", tag: "NB", label: "Network block" },
  ioc: { c: "#be123c", tag: "IO", label: "Checked IOC" },
};
const color = (t: string) => TYPE[t]?.c || "#94a3b8";

/* ---------------- ontology: the schema of the fabric ---------------- */
const POS: Record<string, [number, number]> = {
  lob: [110, 80], msp: [110, 230], asset: [350, 160], agent: [610, 160], policy: [860, 70], user: [860, 220],
  ip: [350, 360], subnet: [120, 380], rule: [140, 520], netblock: [350, 540], ndr: [560, 560], cve: [560, 380],
  detection: [790, 380], tactic: [960, 300], file: [960, 470], ioc: [790, 540],
};

const SHORT: Record<string, string> = { lob: "LOB", agent: "CS agent", policy: "Policy", user: "User", detection: "Detection", tactic: "MITRE tactic", file: "Process / file",
  cve: "CVE", netblock: "Net block", ioc: "IOC", ndr: "NDR alert", rule: "Matrix rule", ip: "IP address", asset: "Asset", subnet: "Subnet", msp: "MSP" };

export function OntologyView({ onPick }: { onPick: (type: string) => void }) {
  const { data } = useQuery({ queryKey: ["fabric-ontology"], queryFn: () => api<any>("/api/fabric/ontology") });
  const [hover, setHover] = React.useState<string | null>(null);
  if (!data) return <div className="h-[560px] animate-pulse rounded-2xl bg-surface-2" />;
  const types: Record<string, any> = Object.fromEntries(data.types.map((t: any) => [t.id, t]));
  const lit = (r: any) => !hover || r.from === hover || r.to === hover;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
      <div className="relative overflow-hidden rounded-2xl border border-border bg-[radial-gradient(circle_at_30%_20%,var(--violet-soft),transparent_45%),radial-gradient(circle_at_80%_80%,var(--accent-soft),transparent_45%)]">
        <svg viewBox="0 0 1060 620" className="h-auto w-full">
          <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" className="fill-muted" /></marker></defs>
          {data.relations.map((r: any, i: number) => {
            const [x1, y1] = POS[r.from] || [0, 0];
            const [x2, y2] = POS[r.to] || [0, 0];
            const on = lit(r);
            if (r.from === r.to) {
              return <g key={i} opacity={on ? 1 : 0.15}><path d={`M${x1 + 30},${y1 - 22} C${x1 + 110},${y1 - 90} ${x1 + 130},${y1 + 30} ${x1 + 48},${y1 + 4}`} fill="none" stroke="var(--border-strong)" strokeWidth={1.4} markerEnd="url(#arr)" />
                <text x={x1 + 110} y={y1 - 40} fontSize={10} className="fill-fg-2">{r.label} · {fmtN(r.count)}</text></g>;
            }
            const dx = x2 - x1, dy = y2 - y1, L = Math.hypot(dx, dy) || 1, ox = (dx / L) * 52, oy = (dy / L) * 30;
            return (
              <g key={i} opacity={on ? 1 : 0.12}>
                <line x1={x1 + ox} y1={y1 + oy} x2={x2 - ox} y2={y2 - oy} stroke={hover && on ? color(hover) : "var(--border-strong)"} strokeWidth={hover && on ? 2 : 1.3} markerEnd="url(#arr)" />
                <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 5} fontSize={10} textAnchor="middle" className="fill-fg-2" style={{ paintOrder: "stroke", stroke: "var(--bg)", strokeWidth: 4 }}>
                  {r.label} <tspan className="fill-muted">{fmtN(r.count)}</tspan></text>
              </g>
            );
          })}
          {Object.entries(POS).map(([id, [x, y]]) => {
            const t = types[id];
            if (!t) return null;
            const dim = hover && hover !== id && !data.relations.some((r: any) => (r.from === hover && r.to === id) || (r.to === hover && r.from === id));
            return (
              <g key={id} transform={`translate(${x},${y})`} className="cursor-pointer" opacity={dim ? 0.3 : 1}
                onMouseEnter={() => setHover(id)} onMouseLeave={() => setHover(null)} onClick={() => onPick(id)}>
                <rect x={-58} y={-26} width={116} height={52} rx={14} fill="var(--surface)" stroke={color(id)} strokeWidth={hover === id ? 2.5 : 1.5}
                  style={{ filter: "drop-shadow(0 4px 10px rgba(0,0,0,.08))" }} />
                <circle cx={-38} cy={0} r={12} fill={color(id)} />
                <text x={-38} y={3.5} fontSize={9} fontWeight={700} textAnchor="middle" fill="white">{TYPE[id]?.tag}</text>
                <text x={-20} y={-4} fontSize={11.5} fontWeight={600} className="fill-fg">{SHORT[id] || t.label}</text>
                <text x={-20} y={12} fontSize={10.5} className="fill-muted">{fmtN(t.count)}</text>
              </g>
            );
          })}
        </svg>
        <div className="absolute bottom-3 left-3 rounded-lg bg-surface/90 px-2.5 py-1.5 text-[11px] text-fg-2 backdrop-blur">Hover a type to see its relationships · click to explore its entities</div>
      </div>
      <div className="space-y-3">
        <div className="rounded-2xl border border-border bg-surface p-3.5 shadow-card">
          <div className="text-[13px] font-semibold">One model of the estate</div>
          <p className="mt-1 text-[12px] leading-relaxed text-fg-2">{data.types.length} entity types and {data.relations.length} relationship types, built live from the console's sources. The assistant walks the same graph for context, and every answer can say where a fact came from.</p>
        </div>
        <div className="max-h-[330px] overflow-y-auto rounded-2xl border border-border bg-surface p-1.5 shadow-card scroll-thin">
          {data.types.map((t: any) => (
            <button key={t.id} onClick={() => onPick(t.id)} onMouseEnter={() => setHover(t.id)} onMouseLeave={() => setHover(null)}
              className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-surface-2">
              <span className="size-2.5 shrink-0 rounded-full" style={{ background: color(t.id) }} />
              <span className="min-w-0 flex-1"><span className="block truncate text-[12.5px]">{t.label}</span><span className="block truncate text-[10.5px] text-muted">{t.source}</span></span>
              <span className="text-[12px] tabular text-fg-2">{fmtN(t.count)}</span>
            </button>
          ))}
        </div>
        <div className="rounded-2xl border border-dashed border-border p-3">
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">Next sources</div>
          {data.planned.map((p: any) => <div key={p.id} className="flex items-center gap-2 py-0.5 text-[12px]"><span className="size-1.5 rounded-full bg-muted" />{p.label}<span className="ml-auto text-[10.5px] text-muted">joins on {p.joins}</span></div>)}
        </div>
      </div>
    </div>
  );
}

/* ---------------- explorer: walk the instance graph ---------------- */
type GNode = { id: string; type: string; label: string; tone?: string | null; x: number; y: number; vx: number; vy: number; pinned?: boolean };
type GEdge = { a: string; b: string; rel: string };

function layout(nodes: GNode[], edges: GEdge[], iters = 160) {
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  for (let it = 0; it < iters; it++) {
    const k = 1 - it / iters;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
        const f = 5200 / d2;
        const d = Math.sqrt(d2);
        a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
      }
    }
    for (const e of edges) {
      const a = nodes[idx.get(e.a)!], b = nodes[idx.get(e.b)!];
      if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1, f = (d - 120) * 0.04;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      n.vx -= n.x * 0.004; n.vy -= n.y * 0.004;
      if (!n.pinned) { n.x += Math.max(-30, Math.min(30, n.vx * k)); n.y += Math.max(-30, Math.min(30, n.vy * k)); }
      n.vx *= 0.5; n.vy *= 0.5;
    }
  }
}

export function GraphExplorer({ start, typeHint }: { start?: string; typeHint?: string }) {
  const [nodes, setNodes] = React.useState<GNode[]>([]);
  const [edges, setEdges] = React.useState<GEdge[]>([]);
  const [sel, setSel] = React.useState<string | null>(null);
  const [details, setDetails] = React.useState<Record<string, any>>({});
  const [view, setView] = React.useState({ x: 0, y: 0, k: 1 });
  const [q, setQ] = React.useState("");
  const [pathMode, setPathMode] = React.useState(false);
  const [pathA, setPathA] = React.useState<any>(null);
  const [pathB, setPathB] = React.useState<any>(null);
  const [path, setPath] = React.useState<string[]>([]);
  const drag = React.useRef<{ x: number; y: number; vx: number; vy: number; node?: string } | null>(null);
  const svgRef = React.useRef<SVGSVGElement>(null);
  const { data: hits } = useQuery({ queryKey: ["fabric-search", q], queryFn: () => api<any>("/api/fabric/search", { params: { q } }), enabled: q.trim().length >= 2 });

  const expand = React.useCallback(async (id: string, reset = false) => {
    try {
      const r = await api<any>("/api/fabric/node", { params: { id } });
      setDetails((d) => ({ ...d, [r.node.id]: r }));
      const ns = reset ? [] : nodes.map((n) => ({ ...n }));
      const es = reset ? [] : [...edges];
      const center = ns.find((n) => n.id === r.node.id) || { x: 0, y: 0 };
      if (!ns.some((n) => n.id === r.node.id)) ns.push({ id: r.node.id, type: r.node.type, label: r.node.label, tone: r.node.tone, x: 0, y: 0, vx: 0, vy: 0 });
      r.neighbors.forEach((nb: any, i: number) => {
        if (!ns.some((n) => n.id === nb.id)) {
          const a = (2 * Math.PI * i) / Math.max(1, r.neighbors.length);
          ns.push({ id: nb.id, type: nb.type, label: nb.label, tone: nb.tone, x: center.x + Math.cos(a) * 140, y: center.y + Math.sin(a) * 140, vx: 0, vy: 0 });
        }
        const [a, b] = nb.dir === "in" ? [nb.id, r.node.id] : [r.node.id, nb.id];
        if (!es.some((e) => (e.a === a && e.b === b) || (e.a === b && e.b === a))) es.push({ a, b, rel: nb.rel });
      });
      const keep = ns.slice(-160);
      const ids = new Set(keep.map((n) => n.id));
      layout(keep, es.filter((e) => ids.has(e.a) && ids.has(e.b)), reset ? 220 : 120);
      setNodes(keep);
      setEdges(es.filter((e) => ids.has(e.a) && ids.has(e.b)));
      setSel(r.node.id);
      if (reset) setView({ x: 0, y: 0, k: 1 });
    } catch (e: any) { toast.error(e.message); }
  }, [nodes, edges]);

  React.useEffect(() => { if (start) expand(start, true); }, [start]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => { if (typeHint && !start) setQ(""); }, [typeHint, start]);

  const findPath = async () => {
    if (!pathA || !pathB) return;
    try {
      const r = await api<any>("/api/fabric/path", { params: { a: pathA.id, b: pathB.id } });
      if (!r.found) { toast.message("No connection within 6 hops"); return; }
      const infos = await Promise.all(r.path.map((id: string) => api<any>("/api/fabric/node", { params: { id } }).catch(() => null)));
      const ns: GNode[] = r.path.map((id: string, i: number) => {
        const inf = infos[i];
        return { id, type: id.split(":")[0], label: inf?.node.label || id.split(":").slice(1).join(":"), tone: inf?.node.tone, x: (i - (r.path.length - 1) / 2) * 170, y: i % 2 ? 50 : -50, vx: 0, vy: 0, pinned: true };
      });
      setDetails((d) => Object.fromEntries([...Object.entries(d), ...infos.filter(Boolean).map((x: any) => [x.node.id, x])]));
      setNodes(ns); setEdges(r.hops.map((h: any) => ({ a: h.from, b: h.to, rel: h.rel }))); setPath(r.path); setSel(r.path[0]); setView({ x: 0, y: 0, k: 1 });
    } catch (e: any) { toast.error(e.message); }
  };

  const W = 900, H = 560;
  const toSvg = (cx: number, cy: number) => {
    const r = svgRef.current!.getBoundingClientRect();
    return [((cx - r.left) / r.width) * W, ((cy - r.top) / r.height) * H];
  };
  const onDown = (e: React.PointerEvent, node?: string) => {
    e.stopPropagation();
    (e.target as Element).setPointerCapture?.(e.pointerId);
    const [x, y] = toSvg(e.clientX, e.clientY);
    drag.current = { x, y, vx: view.x, vy: view.y, node };
  };
  const onMove = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const [x, y] = toSvg(e.clientX, e.clientY);
    if (d.node) {
      setNodes((ns) => ns.map((n) => (n.id === d.node ? { ...n, x: (x - W / 2 - view.x) / view.k, y: (y - H / 2 - view.y) / view.k, pinned: true } : n)));
    } else setView((v) => ({ ...v, x: d.vx + x - d.x, y: d.vy + y - d.y }));
  };
  const zoom = (f: number) => setView((v) => ({ ...v, k: Math.max(0.3, Math.min(2.5, v.k * f)) }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const cur = sel ? details[sel] : null;
  const onPath = (a: string, b: string) => path.length > 1 && path.some((p, i) => i < path.length - 1 && ((path[i] === a && path[i + 1] === b) || (path[i] === b && path[i + 1] === a)));

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="overflow-hidden rounded-2xl border border-border bg-surface shadow-card">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          {!pathMode ? (
            <div className="relative w-full max-w-md flex-1">
              <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={typeHint ? `Find a ${TYPE[typeHint]?.label.toLowerCase() || typeHint}…` : "Find anything: host, IP, LOB, user, CVE, tactic, file…"}
                className="h-9 w-full rounded-xl border border-border-strong bg-bg pl-8 pr-3 text-[13px] outline-none focus:border-violet focus:ring-4 focus:ring-violet/15" />
              {q.trim().length >= 2 && hits?.rows && (
                <div className="absolute left-0 right-0 top-10 z-20 max-h-80 overflow-y-auto rounded-xl border border-border bg-surface p-1 shadow-xl scroll-thin">
                  {hits.rows.filter((h: any) => !typeHint || h.type === typeHint || true).map((h: any) => (
                    <button key={h.id} onClick={() => { setQ(""); setPath([]); expand(h.id, true); }} className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left hover:bg-surface-2">
                      <span className="flex size-6 items-center justify-center rounded-md text-[9px] font-bold text-white" style={{ background: color(h.type) }}>{TYPE[h.type]?.tag}</span>
                      <span className="min-w-0 flex-1 truncate text-[12.5px]">{h.label}</span><span className="truncate text-[11px] text-muted">{h.sub || TYPE[h.type]?.label}</span>
                    </button>))}
                  {!hits.rows.length && <div className="p-2 text-[12px] text-muted">Nothing found</div>}
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-1 flex-wrap items-center gap-2">
              <PathPick value={pathA} onPick={setPathA} placeholder="From (e.g. a user)" />
              <ArrowRight className="size-4 text-muted" />
              <PathPick value={pathB} onPick={setPathB} placeholder="To (e.g. a LOB, CVE)" />
              <Button size="sm" variant="primary" onClick={findPath} disabled={!pathA || !pathB}><Route /> Connect</Button>
            </div>
          )}
          <Button size="sm" variant={pathMode ? "primary" : "ghost"} onClick={() => setPathMode(!pathMode)} title="How are two entities connected?"><GitBranch /> {pathMode ? "Explore" : "Find a connection"}</Button>
          <div className="flex-1" />
          <span className="text-[11px] text-muted">{nodes.length} nodes</span>
          <Button size="sm" variant="ghost" onClick={() => zoom(1.2)}><Plus /></Button>
          <Button size="sm" variant="ghost" onClick={() => zoom(1 / 1.2)}><Minus /></Button>
          <Button size="sm" variant="ghost" title="Re-centre" onClick={() => setView({ x: 0, y: 0, k: 1 })}><Maximize /></Button>
          <Button size="sm" variant="ghost" title="Clear" onClick={() => { setNodes([]); setEdges([]); setSel(null); setPath([]); }}><Trash2 /></Button>
        </div>
        <div className="relative bg-[radial-gradient(var(--border)_1px,transparent_1px)] [background-size:22px_22px]">
          {!nodes.length && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-center">
              <div className="flex size-12 items-center justify-center rounded-2xl bg-gradient-to-br from-violet to-accent text-white shadow-lg"><Locate className="size-6" /></div>
              <div className="text-[14px] font-semibold">Start from any entity</div>
              <div className="max-w-sm text-[12px] text-fg-2">Search above, then click nodes to expand what they are linked to — agents, IPs, subnets, owners, detections, CVEs, flows, users. Drag to move, scroll buttons to zoom.</div>
              <div className="mt-1 flex flex-wrap justify-center gap-1.5">{["lob:Payments", "tactic:Credential Access", "ioc:sample-c2.example"].map((s) => (
                <button key={s} onClick={() => expand(s, true)} className="rounded-full border border-border bg-surface px-2.5 py-0.5 text-[11.5px] hover:border-violet">{s.split(":").slice(1).join(":")}</button>))}</div>
            </div>
          )}
          <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="h-[560px] w-full touch-none select-none" onPointerDown={(e) => onDown(e)} onPointerMove={onMove} onPointerUp={() => (drag.current = null)}
            onWheel={(e) => zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08)}>
            <g transform={`translate(${W / 2 + view.x},${H / 2 + view.y}) scale(${view.k})`}>
              {edges.map((e, i) => {
                const a = byId.get(e.a), b = byId.get(e.b);
                if (!a || !b) return null;
                const hl = sel && (e.a === sel || e.b === sel);
                const p = onPath(e.a, e.b);
                return <g key={i}>
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={p ? "var(--violet)" : hl ? color(byId.get(sel!)!.type) : "var(--border-strong)"} strokeWidth={p ? 3 : hl ? 1.8 : 1} opacity={hl || p || !sel ? 0.95 : 0.45} />
                  {(hl || p || nodes.length < 25) && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} fontSize={9} textAnchor="middle" className="fill-fg-2" style={{ paintOrder: "stroke", stroke: "var(--surface)", strokeWidth: 3 }}>{e.rel}</text>}
                </g>;
              })}
              {nodes.map((n) => {
                const isSel = n.id === sel;
                const expanded = !!details[n.id];
                return (
                  <g key={n.id} transform={`translate(${n.x},${n.y})`} className="cursor-pointer" onPointerDown={(e) => onDown(e, n.id)}
                    onClick={(e) => { e.stopPropagation(); if (drag.current && false) return; expanded ? setSel(n.id) : expand(n.id); }}>
                    {isSel && <circle r={24} fill={color(n.type)} opacity={0.18} />}
                    <circle r={isSel ? 17 : 14} fill={color(n.type)} stroke={n.tone === "crit" ? "var(--crit)" : n.tone === "warn" ? "var(--warn)" : n.tone === "good" ? "var(--good)" : "var(--surface)"} strokeWidth={n.tone ? 3 : 2} />
                    <text y={3.5} fontSize={8.5} fontWeight={700} textAnchor="middle" fill="white">{TYPE[n.type]?.tag}</text>
                    {!expanded && <circle cx={11} cy={-11} r={5} fill="var(--surface)" stroke={color(n.type)} />}
                    {!expanded && <text x={11} y={-8.3} fontSize={8} textAnchor="middle" fill={color(n.type)} fontWeight={700}>+</text>}
                    <text y={isSel ? 31 : 27} fontSize={10} textAnchor="middle" className="fill-fg" fontWeight={isSel ? 600 : 400} style={{ paintOrder: "stroke", stroke: "var(--surface)", strokeWidth: 3 }}>
                      {n.label.length > 24 ? n.label.slice(0, 23) + "…" : n.label}</text>
                  </g>
                );
              })}
            </g>
          </svg>
          {nodes.length > 0 && <div className="pointer-events-none absolute bottom-2 left-2 flex flex-wrap gap-1.5 rounded-lg bg-surface/90 px-2 py-1 text-[10.5px] backdrop-blur">
            {[...new Set(nodes.map((n) => n.type))].map((t) => <span key={t} className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: color(t) }} />{TYPE[t]?.label || t}</span>)}</div>}
        </div>
      </div>
      <NodePanel cur={cur} onExpand={(id) => expand(id)} onClose={() => setSel(null)} />
    </div>
  );
}

function PathPick({ value, onPick, placeholder }: { value: any; onPick: (v: any) => void; placeholder: string }) {
  const [q, setQ] = React.useState("");
  const { data } = useQuery({ queryKey: ["fabric-search", q], queryFn: () => api<any>("/api/fabric/search", { params: { q } }), enabled: q.trim().length >= 2 });
  if (value) return <span className="flex items-center gap-1.5 rounded-lg border border-border bg-surface-2 px-2 py-1 text-[12px]"><span className="size-2 rounded-full" style={{ background: color(value.type) }} />{value.label}
    <button onClick={() => onPick(null)} className="text-muted hover:text-fg"><X className="size-3" /></button></span>;
  return (
    <div className="relative w-56">
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={placeholder} className="h-8 w-full rounded-lg border border-border-strong bg-bg px-2.5 text-[12.5px] outline-none focus:border-violet" />
      {q.trim().length >= 2 && data?.rows && <div className="absolute left-0 right-0 top-9 z-20 max-h-64 overflow-y-auto rounded-xl border border-border bg-surface p-1 shadow-xl">
        {data.rows.map((h: any) => <button key={h.id} onClick={() => { onPick(h); setQ(""); }} className="flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-[12px] hover:bg-surface-2">
          <span className="size-2 shrink-0 rounded-full" style={{ background: color(h.type) }} /><span className="truncate">{h.label}</span><span className="ml-auto shrink-0 text-[10.5px] text-muted">{TYPE[h.type]?.label}</span></button>)}</div>}
    </div>
  );
}

function NodePanel({ cur, onExpand, onClose }: { cur: any; onExpand: (id: string) => void; onClose: () => void }) {
  if (!cur) return (
    <div className="rounded-2xl border border-dashed border-border p-4 text-[12.5px] text-fg-2">
      <div className="mb-1 font-semibold text-fg">Entity details</div>Select a node to see its properties, where they come from, and its links grouped by relationship.
    </div>
  );
  const n = cur.node;
  const groups: Record<string, any[]> = {};
  cur.neighbors.forEach((x: any) => { (groups[x.rel] ||= []).push(x); });
  const explainKind = n.type === "asset" ? "asset" : n.type === "detection" ? "detection" : n.type === "cve" ? "cve" : n.type === "ip" ? "ip" : null;
  return (
    <div className="max-h-[620px] overflow-y-auto rounded-2xl border border-border bg-surface shadow-card scroll-thin">
      <div className="sticky top-0 z-10 border-b border-border bg-surface/95 p-3 backdrop-blur">
        <div className="flex items-start gap-2">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-lg text-[10px] font-bold text-white" style={{ background: color(n.type) }}>{TYPE[n.type]?.tag}</span>
          <div className="min-w-0 flex-1"><div className="break-words text-[13.5px] font-semibold leading-tight">{n.label}</div><div className="text-[11px] text-muted">{TYPE[n.type]?.label}</div></div>
          <button onClick={onClose} className="text-muted hover:text-fg"><X className="size-4" /></button>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {explainKind && <ExplainButton kind={explainKind} id={n.id.split(":").slice(1).join(":")} label="Explain" />}
          {n.href && <Link href={n.href}><Button size="sm"><ExternalLink /> Open</Button></Link>}
        </div>
      </div>
      <dl className="grid grid-cols-[100px_1fr] gap-x-2 gap-y-1 p-3 text-[12px]">
        {Object.entries(n.props || {}).map(([k, v]) => <React.Fragment key={k}><dt className="text-muted">{k}</dt><dd className="min-w-0 break-words">{String(v)}</dd></React.Fragment>)}
      </dl>
      <div className="border-t border-border p-2">
        {Object.entries(groups).map(([rel, xs]) => (
          <div key={rel} className="mb-1.5">
            <div className="px-1.5 py-1 text-[10.5px] font-semibold uppercase tracking-wider text-muted">{rel} · {cur.more?.[rel] ? `${xs.length} of ${fmtN(cur.more[rel])}` : xs.length}</div>
            {xs.map((x) => (
              <button key={x.id} onClick={() => onExpand(x.id)} className="flex w-full items-center gap-2 rounded-lg px-1.5 py-1 text-left hover:bg-surface-2">
                <span className="size-2 shrink-0 rounded-full" style={{ background: color(x.type) }} />
                <span className="min-w-0 flex-1 truncate text-[12px]">{x.label}</span>
                {x.tone && <Badge tone={x.tone === "crit" ? "crit" : x.tone === "warn" ? "warn" : "good"}>{x.sub || x.tone}</Badge>}
              </button>
            ))}
          </div>
        ))}
        {!cur.neighbors.length && <div className="p-2 text-[12px] text-muted">No links recorded.</div>}
      </div>
    </div>
  );
}
