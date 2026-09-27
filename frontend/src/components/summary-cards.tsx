"use client";
import * as React from "react";
import Link from "next/link";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Card } from "./ui";
import { StackBar } from "./charts";

/** Big-number summary card with a bar and detail lines (Overview, LOB page). */
export function Hero({ title, value, sub, href, children }: { title: string; value: React.ReactNode; sub: string; href: string; children: React.ReactNode }) {
  return (
    <Card className="flex flex-col p-5">
      <Link href={href} className="group">
        <div className="text-[12.5px] font-medium text-fg-2 group-hover:text-fg">{title}</div>
        <div className="mt-1 text-[34px] font-semibold leading-none tracking-tight">{value}</div>
        <div className="mt-1.5 text-[12px] text-muted">{sub}</div>
      </Link>
      <div className="mt-4 flex-1">{children}</div>
    </Card>
  );
}

/** proportional bar with a clickable legend underneath */
export function Split({ parts }: { parts: { label: string; n: number; color: string; href: string }[] }) {
  const tot = parts.reduce((a, p) => a + (p.n || 0), 0);
  return (
    <div>
      <StackBar parts={parts} height={10} />
      <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
        {parts.map((p) => (
          <Link key={p.label} href={p.href} className="flex items-center gap-1.5 text-[12.5px] hover:underline">
            <span className="size-2 rounded-full" style={{ background: p.color }} />
            <span className="text-fg-2">{p.label}</span> <b className="tabular">{fmtN(p.n)}</b>
          </Link>
        ))}
      </div>
    </div>
  );
}

export function Line2({ items }: { items: [string, number, string][] }) {
  return (
    <div className="mt-3 space-y-1 border-t border-border pt-3">
      {items.map(([l, n, href]) => (
        <Link key={l} href={href} className={cn("flex items-center justify-between text-[12.5px] hover:text-fg", l.startsWith("  ·") ? "pl-3 text-muted" : "text-fg-2")}>
          <span>{l.replace(/^ {2}· /, "")}</span><b className={cn("tabular", l.startsWith("  ·") && "font-medium")}>{fmtN(n || 0)}</b>
        </Link>
      ))}
    </div>
  );
}

