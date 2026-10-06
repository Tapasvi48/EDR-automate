"use client";
import * as React from "react";
import { createPortal } from "react-dom";
import Link from "next/link";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtN, pct, shortDay } from "@/lib/format";
import { cn } from "@/lib/utils";

export type Series = { key: string; label: string; color: string };
export const COLORS = {
  s1: "var(--s1)", s2: "var(--s2)", s3: "var(--s3)", s4: "var(--s4)", s5: "var(--s5)", s7: "var(--s7)", s8: "var(--s8)",
  good: "var(--good)", warn: "var(--warn)", serious: "var(--serious)", crit: "var(--crit)", muted: "var(--border-strong)",
};

function ChartTip({ active, payload, label, series, xFmt }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="min-w-[140px] rounded-lg border border-border bg-surface px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-semibold">{xFmt ? xFmt(label) : label}</div>
      {(series as Series[]).map((s) => {
        const p = payload.find((x: any) => x.dataKey === s.key);
        return (
          <div key={s.key} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-fg-2">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: s.color }} />
              {s.label}
            </span>
            <b className="tabular">{fmtN(p?.value ?? 0)}</b>
          </div>
        );
      })}
    </div>
  );
}

export function Legend({ series }: { series: Series[] }) {
  if (series.length < 2) return null;
  return (
    <div className="mb-2 flex flex-wrap gap-4 text-xs text-fg-2">
      {series.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5">
          <span className="inline-block size-2.5 rounded-sm" style={{ background: s.color }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}

export function DayBars({ data, series, height = 210, onClick, xKey = "day", stacked = true }: {
  data: any[]; series: Series[]; height?: number; onClick?: (row: any) => void; xKey?: string; stacked?: boolean;
}) {
  return (
    <div>
      <Legend series={series} />
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 4, right: 4, left: -14, bottom: 0 }} barCategoryGap="22%"
          onClick={(e: any) => { const idx = e?.activeTooltipIndex ?? e?.activeIndex; if (onClick && idx !== undefined && data[+idx]) onClick(data[+idx]); }}>
          <CartesianGrid vertical={false} />
          <XAxis dataKey={xKey} tickFormatter={shortDay} tickLine={false} minTickGap={18} />
          <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={44} tickFormatter={(v) => fmtN(v)} />
          <Tooltip cursor={{ fill: "var(--surface-3)", opacity: 0.6 }} content={<ChartTip series={series} xFmt={shortDay} />} />
          {series.map((s, i) => (
            <Bar key={s.key} dataKey={s.key} stackId={stacked ? "a" : undefined} fill={s.color} maxBarSize={28}
              radius={!stacked || i === series.length - 1 ? [4, 4, 0, 0] : 0} style={{ cursor: onClick ? "pointer" : "default" }} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** "2026-10-05T18:00:00Z" -> "5 Oct 18:00" (hourly series) */
export const shortHour = (v: string) => {
  const d = new Date(v);
  return isNaN(+d) ? String(v) : `${d.getDate()} ${d.toLocaleString("en", { month: "short" })} ${String(d.getHours()).padStart(2, "0")}:00`;
};

export function TrendLines({ data, series, height = 230, xKey = "day", xFmt }: { data: any[]; series: Series[]; height?: number; xKey?: string; xFmt?: (v: string) => string }) {
  const fmt = xFmt || (xKey === "hour" ? shortHour : shortDay);
  const animate = data.length * series.length < 400;  // big series render at once (no slow animation)
  return (
    <div>
      <Legend series={series} />
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 6, right: 10, left: -8, bottom: 0 }}>
          <CartesianGrid vertical={false} />
          <XAxis dataKey={xKey} tickFormatter={fmt} tickLine={false} minTickGap={36} />
          <YAxis tickLine={false} axisLine={false} width={48} tickFormatter={(v) => fmtN(v)} />
          <Tooltip cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }} content={<ChartTip series={series} xFmt={fmt} />} />
          {series.map((s) => (
            <Line key={s.key} dataKey={s.key} stroke={s.color} strokeWidth={series.length > 4 ? 1.6 : 2} dot={false} isAnimationActive={animate}
              activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--surface)" }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export type Seg = { label: string; n: number; color: string };
/** Stacked bar; hovering shows every part with its number and share. `scale` sets the 100% width (default: sum of parts). */
export function StackBar({ parts, scale, height = 10, className, title }: { parts: Seg[]; scale?: number; height?: number; className?: string; title?: string }) {
  const sum = parts.reduce((a, p) => a + (p.n || 0), 0);
  const denom = scale || sum;
  const [pos, setPos] = React.useState<{ x: number; y: number } | null>(null);
  return (
    <div className={cn("relative min-w-0", className)}
      onMouseEnter={(e) => { const r = e.currentTarget.getBoundingClientRect(); setPos({ x: r.left + r.width / 2, y: r.bottom }); }}
      onMouseMove={(e) => { if (!pos) { const r = e.currentTarget.getBoundingClientRect(); setPos({ x: r.left + r.width / 2, y: r.bottom }); } }}
      onMouseLeave={() => setPos(null)}>
      <div className="flex overflow-hidden rounded-full bg-surface-3" style={{ height }}>
        {parts.filter((p) => p.n > 0).map((p, i) => (
          <div key={p.label} className={cn("h-full", i > 0 && "border-l-2 border-surface")} style={{ width: `${denom ? (100 * p.n) / denom : 0}%`, background: p.color }} />
        ))}
      </div>
      {pos && sum > 0 && typeof document !== "undefined" && createPortal(
        <div className="pointer-events-none fixed z-[100] min-w-[170px] -translate-x-1/2 rounded-lg border border-border bg-surface px-3 py-2 text-xs shadow-xl"
          style={{ left: pos.x, top: pos.y + 8 }}>
          {title && <div className="mb-1 font-semibold">{title}</div>}
          {parts.map((p) => (
            <div key={p.label} className="flex items-center justify-between gap-4 py-0.5">
              <span className="flex items-center gap-1.5 text-fg-2"><span className="inline-block size-2 rounded-sm" style={{ background: p.color }} />{p.label}</span>
              <span className="tabular"><b>{fmtN(p.n)}</b> <span className="text-muted">{pct(p.n, sum)}%</span></span>
            </div>
          ))}
          <div className="mt-1 flex justify-between border-t border-border pt-1"><span className="text-muted">Total</span><b className="tabular">{fmtN(sum)}</b></div>
        </div>, document.body)}
    </div>
  );
}

export type HBarItem = { label: string; n: number; color?: string; parts?: { n: number; color: string; label?: string }[]; href?: string; title?: string };
export function HBars({ items, total, color = COLORS.s1, max }: { items: HBarItem[]; total?: number; color?: string; max?: number }) {
  if (!items?.length) return <div className="py-6 text-center text-muted">No data</div>;
  const m = max || Math.max(1, ...items.map((i) => i.n));
  return (
    <div className="flex flex-col gap-2">
      {items.map((i) => {
        const parts = i.parts || [{ n: i.n, color: i.color || color }];
        const row = (
          <div
            title={i.title || `${i.label}: ${fmtN(i.n)}`}
            className={cn("grid grid-cols-[minmax(80px,40%)_1fr_62px] items-center gap-2.5 text-[12.5px]", i.href && "group cursor-pointer")}
          >
            <div className="truncate text-fg-2 group-hover:text-accent-fg">{i.label}</div>
            <StackBar height={10} scale={m} title={i.label} parts={parts.map((p, j) => ({ label: (p as any).label || (i.parts ? ["Online", "Offline", "Pending"][j] || `Part ${j + 1}` : i.label), n: p.n, color: p.color }))} />
            <div className="text-right font-semibold tabular">
              {fmtN(i.n)}
              {total ? <span className="ml-1 text-[11px] font-normal text-muted">{pct(i.n, total)}%</span> : null}
            </div>
          </div>
        );
        return i.href ? <Link key={i.label} href={i.href}>{row}</Link> : <React.Fragment key={i.label}>{row}</React.Fragment>;
      })}
    </div>
  );
}

/** Single stacked proportion bar, e.g. online / stale / offline split */
export function SplitBar({ parts, height = 12 }: { parts: { label: string; n: number; color: string; href?: string }[]; height?: number }) {
  const total = parts.reduce((a, p) => a + p.n, 0) || 1;
  return (
    <div>
      <StackBar parts={parts} height={height} />
      <div className="mt-2.5 flex flex-wrap gap-x-5 gap-y-1 text-xs">
        {parts.map((p) => {
          const inner = (
            <span className="flex items-center gap-1.5 text-fg-2 hover:text-fg">
              <span className="inline-block size-2.5 rounded-sm" style={{ background: p.color }} />
              {p.label} <b className="tabular text-fg">{fmtN(p.n)}</b>
              <span className="text-muted">{pct(p.n, total)}%</span>
            </span>
          );
          return p.href ? <Link key={p.label} href={p.href}>{inner}</Link> : <span key={p.label}>{inner}</span>;
        })}
      </div>
    </div>
  );
}

/** Tiny trend line for tables and cards (no axes). */
export function Sparkline({ data, k, color = COLORS.s1, width = 110, height = 30 }: { data: any[]; k: string; color?: string; width?: number; height?: number }) {
  const pts = data.filter((d) => d[k] !== null && d[k] !== undefined);
  if (pts.length < 2) return <span className="text-xs text-muted">no history yet</span>;
  return (
    <LineChart width={width} height={height} data={pts} margin={{ top: 3, right: 2, left: 2, bottom: 3 }}>
      <YAxis hide domain={["dataMin", "dataMax"]} />
      <Line dataKey={k} stroke={color} strokeWidth={1.8} dot={false} isAnimationActive={false} />
    </LineChart>
  );
}
