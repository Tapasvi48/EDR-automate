"use client";
import * as React from "react";
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

export function TrendLines({ data, series, height = 230, xKey = "day" }: { data: any[]; series: Series[]; height?: number; xKey?: string }) {
  return (
    <div>
      <Legend series={series} />
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 6, right: 10, left: -8, bottom: 0 }}>
          <CartesianGrid vertical={false} />
          <XAxis dataKey={xKey} tickFormatter={shortDay} tickLine={false} minTickGap={24} />
          <YAxis tickLine={false} axisLine={false} width={48} tickFormatter={(v) => fmtN(v)} />
          <Tooltip cursor={{ stroke: "var(--border-strong)", strokeDasharray: "3 3" }} content={<ChartTip series={series} xFmt={shortDay} />} />
          {series.map((s) => (
            <Line key={s.key} dataKey={s.key} stroke={s.color} strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--surface)" }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export type HBarItem = { label: string; n: number; color?: string; parts?: { n: number; color: string }[]; href?: string; title?: string };
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
            <div className="flex h-2.5 overflow-hidden rounded-full bg-surface-3">
              {parts.filter((p) => p.n > 0).map((p, j) => (
                <div key={j} className={cn("h-full", j > 0 && "border-l-2 border-surface")} style={{ width: `${(100 * p.n) / m}%`, background: p.color }} />
              ))}
            </div>
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
      <div className="flex overflow-hidden rounded-full bg-surface-3" style={{ height }}>
        {parts.filter((p) => p.n > 0).map((p, i) => (
          <div key={p.label} title={`${p.label}: ${fmtN(p.n)} (${pct(p.n, total)}%)`} className={cn("h-full", i > 0 && "border-l-2 border-surface")} style={{ width: `${(100 * p.n) / total}%`, background: p.color }} />
        ))}
      </div>
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
