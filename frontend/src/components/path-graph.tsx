"use client";
import * as React from "react";
import Link from "next/link";
import { Globe2, MoreHorizontal, Server, ShieldAlert, ShieldCheck, ShieldX, Target } from "lucide-react";
import { cn } from "@/lib/utils";

export type GNode = {
  id: string; col: number; title: string; sub?: string; kind: "internet" | "entry" | "source" | "target" | "more";
  weak?: boolean; edr?: string; crit?: number; high?: number; exposed?: boolean; data?: any; hint?: string;
};
export type GEdge = { from: string; to: string; label?: string; hint?: string };

const EDR_DOT: Record<string, string> = { Online: "bg-good", Offline: "bg-warn", "Not Installed": "bg-crit" };

/** Left-to-right path graph: HTML node cards in columns, SVG connectors drawn between them (measured after layout).
 *  Hovering a node lights up every path through it and dims the rest; clicking selects it. */
export function PathGraph({ columns, nodes, edges, selected, onSelect, height }: {
  columns: { title: React.ReactNode; sub?: React.ReactNode }[]; nodes: GNode[]; edges: GEdge[];
  selected?: string | null; onSelect?: (n: GNode) => void; height?: number;
}) {
  const wrap = React.useRef<HTMLDivElement>(null);
  const refs = React.useRef(new Map<string, HTMLDivElement>());
  const [pos, setPos] = React.useState<Record<string, DOMRect>>({});
  const [size, setSize] = React.useState({ w: 0, h: 0 });
  const [hover, setHover] = React.useState<string | null>(null);

  const measure = React.useCallback(() => {
    const el = wrap.current;
    if (!el) return;
    const base = el.getBoundingClientRect();
    const out: Record<string, DOMRect> = {};
    refs.current.forEach((n, id) => {
      const r = n.getBoundingClientRect();
      out[id] = new DOMRect(r.left - base.left, r.top - base.top, r.width, r.height);
    });
    setPos(out);
    setSize({ w: el.scrollWidth, h: el.scrollHeight });
  }, []);
  React.useLayoutEffect(() => {
    measure();
    const ro = new ResizeObserver(measure);
    if (wrap.current) ro.observe(wrap.current);
    return () => ro.disconnect();
  }, [measure, nodes, edges]);

  // everything upstream and downstream of the focused node
  const focus = hover || selected || null;
  const lit = React.useMemo(() => {
    if (!focus) return null;
    const on = new Set([focus]);
    const walk = (dir: "up" | "down") => {
      const q = [focus];
      while (q.length) {
        const cur = q.pop()!;
        for (const e of edges) {
          const [a, b] = dir === "down" ? [e.from, e.to] : [e.to, e.from];
          if (a === cur && !on.has(b)) { on.add(b); q.push(b); }
        }
      }
    };
    walk("down"); walk("up");
    return on;
  }, [focus, edges]);

  const byCol = columns.map((_, i) => nodes.filter((n) => n.col === i));
  const weakIds = new Set(nodes.filter((n) => n.weak).map((n) => n.id));
  return (
    <div className="overflow-x-auto scroll-thin" style={height ? { maxHeight: height } : undefined}>
      <div ref={wrap} className="relative flex w-max min-w-full gap-14 p-4">
        <svg className="pointer-events-none absolute left-0 top-0" width={size.w} height={size.h} aria-hidden>
          <defs>
            {["muted", "accent", "crit"].map((k) => (
              <marker key={k} id={`arr-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={k === "muted" ? "var(--border-strong)" : `var(--${k})`} />
              </marker>
            ))}
          </defs>
          {edges.map((e, i) => {
            const a = pos[e.from], b = pos[e.to];
            if (!a || !b) return null;
            const x1 = a.right, y1 = a.top + a.height / 2, x2 = b.left - 2, y2 = b.top + b.height / 2;
            const dx = Math.max(30, (x2 - x1) / 2);
            const on = lit ? lit.has(e.from) && lit.has(e.to) : false;
            const hot = weakIds.has(e.to);
            const color = on ? (hot ? "var(--crit)" : "var(--accent)") : hot ? "color-mix(in srgb, var(--crit) 45%, var(--border-strong))" : "var(--border-strong)";
            return (
              <g key={i} opacity={lit && !on ? 0.12 : 1}>
                <path d={`M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`} fill="none" stroke={color} strokeWidth={on ? 2.2 : 1.3}
                  strokeDasharray={on ? "6 4" : undefined} className={on ? "path-flow" : undefined}
                  markerEnd={`url(#arr-${on ? (hot ? "crit" : "accent") : "muted"})`} />
                {on && e.label && (
                  <g transform={`translate(${(x1 + x2) / 2},${(y1 + y2) / 2})`}>
                    <rect x={-e.label.length * 3.4 - 6} y={-9} width={e.label.length * 6.8 + 12} height={18} rx={9} fill="var(--surface)" stroke={color} />
                    <text textAnchor="middle" y={4} fontSize="10.5" fill="var(--fg)" fontFamily="ui-monospace, monospace">{e.label}</text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>
        {columns.map((c, i) => (
          <div key={i} className="relative z-10 flex w-[210px] shrink-0 flex-col gap-2">
            <div className="mb-1">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-fg-2">{c.title}</div>
              {c.sub && <div className="text-[11px] text-muted">{c.sub}</div>}
            </div>
            <div className="flex flex-1 flex-col justify-center gap-2">
              {byCol[i].map((n) => (
                <div key={n.id} ref={(el) => { if (el) refs.current.set(n.id, el); else refs.current.delete(n.id); }}
                  onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}
                  onClick={() => n.kind !== "more" && onSelect?.(n)} title={n.hint}
                  className={cn("transition-opacity", lit && !lit.has(n.id) && "opacity-30", onSelect && n.kind !== "more" && "cursor-pointer")}>
                  <NodeCard n={n} selected={selected === n.id} />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function NodeCard({ n, selected }: { n: GNode; selected?: boolean }) {
  if (n.kind === "more") return (
    <div className="flex items-center gap-2 rounded-lg border border-dashed border-border-strong px-2.5 py-2 text-[11.5px] text-muted">
      <MoreHorizontal className="size-3.5" /> {n.title}
    </div>
  );
  if (n.kind === "internet") return (
    <div className="flex items-center gap-2.5 rounded-xl border border-crit/40 bg-crit-soft/40 px-3 py-2.5">
      <div className="grid size-8 place-items-center rounded-full bg-crit text-white"><Globe2 className="size-4" /></div>
      <div className="min-w-0 text-[12px]"><div className="font-semibold">{n.title}</div><div className="truncate text-[11px] text-muted">{n.sub}</div></div>
    </div>
  );
  const Icon = n.kind === "entry" ? Target : n.weak ? ShieldAlert : n.edr === "Online" ? ShieldCheck : n.edr === "Not Installed" ? ShieldX : Server;
  return (
    <div className={cn("relative overflow-hidden rounded-xl border bg-surface px-2.5 py-2 shadow-card",
      n.kind === "entry" ? "border-2 border-accent" : n.weak ? "border-crit/50" : "border-border",
      selected && "ring-2 ring-accent/50")}>
      {n.weak && <span className="absolute inset-y-0 left-0 w-[3px] bg-crit" />}
      <div className="flex items-center gap-2">
        <Icon className={cn("size-4 shrink-0", n.kind === "entry" ? "text-accent-fg" : n.weak ? "text-crit-fg" : "text-muted")} />
        <span className="truncate text-[12.5px] font-semibold">{n.title}</span>
        {n.edr && <span className={cn("ml-auto size-2 shrink-0 rounded-full", EDR_DOT[n.edr] || "bg-muted")} title={`EDR: ${n.edr}`} />}
      </div>
      <div className="mt-0.5 flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[10.5px] text-muted">{n.sub}</span>
        {(n.crit || n.high) ? (
          <span className="flex gap-0.5 text-[10px] font-semibold">
            {n.crit ? <span className="rounded bg-crit-soft px-1 text-crit-fg">{n.crit}C</span> : null}
            {n.high ? <span className="rounded bg-serious-soft px-1 text-serious-fg">{n.high}H</span> : null}
          </span>
        ) : null}
      </div>
      {(n.edr === "Not Installed" || n.exposed) && n.kind !== "entry" && (
        <div className="mt-1 flex gap-1 text-[10px]">
          {n.edr === "Not Installed" && <span className="rounded bg-crit-soft px-1 text-crit-fg">no EDR</span>}
          {n.exposed && <span className="rounded bg-warn-soft px-1 text-warn-fg">also exposed</span>}
        </div>
      )}
    </div>
  );
}

export function GraphLegend() {
  const dot = (c: string) => <span className={cn("inline-block size-2 rounded-full", c)} />;
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted">
      <span className="flex items-center gap-1.5"><span className="h-3 w-[3px] rounded bg-crit" /> weak: critical vulnerability or no EDR</span>
      <span className="flex items-center gap-1.5">{dot("bg-good")} EDR online</span>
      <span className="flex items-center gap-1.5">{dot("bg-warn")} EDR offline</span>
      <span className="flex items-center gap-1.5">{dot("bg-crit")} no EDR</span>
      <span>Hover a node to trace its paths · click for details</span>
    </div>
  );
}

const tgt = (t: any, col: number): GNode => ({
  id: t.ip, col, title: t.name || t.ip, sub: t.ip, kind: "target", weak: t.weak, edr: t.edr_status, crit: t.crit, high: t.high, exposed: !!t.exposed, data: t,
  hint: [t.lobs, t.os, t.node_type].filter(Boolean).join(" · "),
});

/** Build graph columns from /api/attack-paths/detail. `sources` adds the exposed assets that can reach this one. */
export function buildPathGraph(d: any, { weakOnly, limit = 12, sources = false }: { weakOnly: boolean; limit?: number; sources?: boolean }) {
  const e = d.entry;
  const nodes: GNode[] = [], edges: GEdge[] = [];
  const hasInternet = d.internet.length > 0 || e.exposed;
  const reached = sources ? (d.reached_by || []) : [];
  const showLeft = hasInternet || reached.length > 0;
  const c0 = showLeft ? 0 : -1, c1 = c0 + 1, c2 = c1 + 1, c3 = c2 + 1;
  if (hasInternet) {
    nodes.push({ id: "internet", col: c0, kind: "internet", title: "Internet",
      sub: d.internet.length ? `${d.internet.length} inbound rule${d.internet.length > 1 ? "s" : ""}` : "public IP / scan", data: { internet: d.internet } });
    edges.push({ from: "internet", to: e.ip, label: d.internet.length ? `${d.internet[0].protocol || "any"}/${d.internet[0].ports}` : "public" });
  }
  const rb = reached.slice(0, limit - (hasInternet ? 1 : 0));
  rb.forEach((x: any) => {
    nodes.push({ ...tgt(x, c0), kind: "source", id: "src:" + x.ip, sub: `${x.ip} · ${x.hops} hop${x.hops > 1 ? "s" : ""}` });
    edges.push({ from: "src:" + x.ip, to: e.ip, label: x.via?.[0]?.ports });
  });
  if (reached.length > rb.length) nodes.push({ id: "src:more", col: c0, kind: "more", title: `${reached.length - rb.length} more exposed assets reach it` });
  nodes.push({ id: e.ip, col: c1, kind: "entry", title: e.name || e.ip, sub: e.ip, edr: e.edr_status, crit: e.crit, high: e.high, data: { ...e, weak: false } });
  const f = (xs: any[]) => (weakOnly ? xs.filter((t) => t.weak) : xs);
  const h2 = f(d.hop2).slice(0, limit);
  const need = new Set(h2.map((t: any) => t.via[0].from));
  const h1all = f(d.hop1);
  const h1 = [...h1all.slice(0, limit), ...d.hop1.filter((t: any) => need.has(t.ip) && !h1all.slice(0, limit).includes(t))];
  const shown1 = new Set(h1.map((t: any) => t.ip));
  h1.forEach((t: any) => {
    nodes.push(tgt(t, c2));
    edges.push({ from: e.ip, to: t.ip, label: t.via[0].ports, hint: t.via[0].rule_id });
  });
  if (h1all.length > limit) nodes.push({ id: "h1:more", col: c2, kind: "more", title: `${h1all.length - limit} more${weakOnly ? " weak" : ""}` });
  h2.forEach((t: any) => {
    nodes.push(tgt(t, c3));
    t.via.filter((v: any) => shown1.has(v.from)).slice(0, 3).forEach((v: any) => edges.push({ from: v.from, to: t.ip, label: v.ports, hint: v.rule_id }));
  });
  const more2 = f(d.hop2).length - h2.length;
  if (more2 > 0) nodes.push({ id: "h2:more", col: c3, kind: "more", title: `${more2} more${weakOnly ? " weak" : ""}` });
  const columns = [
    ...(showLeft ? [{ title: reached.length ? "Reachable from" : "Source", sub: reached.length ? `${reached.length} exposed asset(s)${hasInternet ? " + internet" : ""}` : "internet" }] : []),
    { title: "Entry point", sub: e.os || e.node_type || "" },
    { title: "Hop 1", sub: `${d.hop1_total} reachable · ${d.hop1.filter((t: any) => t.weak).length} weak` },
    ...(d.hop2_total || d.hop2.length ? [{ title: "Hop 2", sub: `${d.hop2_total} reachable · ${d.hop2.filter((t: any) => t.weak).length} weak` }] : []),
  ];
  return { columns, nodes: nodes.filter((n) => n.col < columns.length), edges };
}

/** The single worst path as numbered steps: internet -> entry -> ... -> the weakest target. */
export function worstPath(d: any) {
  const score = (t: any) => (t.weak ? 100 : 0) + t.crit * 10 + t.high + (t.edr_status === "Not Installed" ? 20 : 0);
  const best2 = [...d.hop2].sort((a, b) => score(b) - score(a))[0];
  const best1 = [...d.hop1].sort((a, b) => score(b) - score(a))[0];
  const steps: { label: string; ip?: string; how?: string; why?: string; weak?: boolean }[] = [];
  const inb = d.internet[0];
  steps.push({ label: "Internet", how: inb ? `${(inb.protocol || "any").toUpperCase()} ${inb.ports} · ${inb.rule_id}${inb.public ? ` · public ${inb.public}` : ""}` : "public IP" });
  steps.push({ label: d.entry.name || d.entry.ip, ip: d.entry.ip, why: why(d.entry), how: inb ? `${(inb.protocol || "any").toUpperCase()} ${inb.ports}` : "public" });
  const why2 = (t: any) => why(t);
  if (best2 && (!best1 || score(best2) >= score(best1))) {
    const mid = d.hop1.find((t: any) => t.ip === best2.via[0].from);
    if (mid) steps.push({ label: mid.name || mid.ip, ip: mid.ip, how: `TCP ${mid.via[0].ports} · ${mid.via[0].rule_id}`, why: why2(mid), weak: mid.weak });
    steps.push({ label: best2.name || best2.ip, ip: best2.ip, how: `TCP ${best2.via[0].ports} · ${best2.via[0].rule_id}`, why: why2(best2), weak: best2.weak });
  } else if (best1) {
    steps.push({ label: best1.name || best1.ip, ip: best1.ip, how: `TCP ${best1.via[0].ports} · ${best1.via[0].rule_id}`, why: why2(best1), weak: best1.weak });
  }
  return steps.length > 2 ? steps : null;
}

function why(t: any) {
  return [t.crit ? `${t.crit} critical` : "", t.high ? `${t.high} high` : "", t.edr_status === "Not Installed" ? "no EDR" : t.edr_status === "Offline" ? "EDR offline" : ""]
    .filter(Boolean).join(" · ");
}

export function PathSteps({ steps }: { steps: ReturnType<typeof worstPath> }) {
  if (!steps) return null;
  return (
    <ol className="flex flex-wrap items-stretch gap-1.5">
      {steps.map((s, i) => (
        <li key={i} className="flex items-center gap-1.5">
          {i > 0 && <span className="flex flex-col items-center px-1 text-[10px] text-muted"><span className="font-mono">{steps[i].how?.split(" · ")[0]}</span><span>→</span></span>}
          <div className={cn("rounded-lg border px-2.5 py-1.5 text-[12px]", s.weak ? "border-crit/50 bg-crit-soft/40" : i === 0 ? "border-crit/40 bg-crit-soft/30" : "border-border bg-surface")}>
            <div className="flex items-center gap-1.5"><span className="grid size-4 place-items-center rounded-full bg-surface-3 text-[10px] font-bold">{i + 1}</span>
              {s.ip ? <Link className="font-semibold hover:underline" href={`/ip-search/?q=${encodeURIComponent(s.ip)}`}>{s.label}</Link> : <b>{s.label}</b>}</div>
            {(s.why || (i === 0 && s.how)) && <div className={cn("mt-0.5 text-[11px]", s.weak ? "text-crit-fg" : "text-muted")}>{i === 0 ? s.how : s.why}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}
