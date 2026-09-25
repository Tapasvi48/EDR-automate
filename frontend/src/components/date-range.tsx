"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { CalendarDays, X } from "lucide-react";
import { daysAgo, today } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Input } from "./ui";

type Preset = { label: string; from?: string; to?: string };

/** Compact date-range filter: a button that opens presets + custom from/to. */
export function DateRange({ label, from, to, onChange, older }: {
  label: string; from?: string; to?: string; onChange: (from?: string, to?: string) => void; older?: boolean;
}) {
  const presets: Preset[] = [
    { label: "Today", from: today(), to: today() },
    { label: "Yesterday", from: daysAgo(1), to: daysAgo(1) },
    { label: "Last 7 days", from: daysAgo(6) },
    { label: "Last 30 days", from: daysAgo(29) },
    { label: "Last 90 days", from: daysAgo(89) },
    ...(older ? [
      { label: "Older than 7 days", to: daysAgo(8) },
      { label: "Older than 30 days", to: daysAgo(31) },
      { label: "Older than 90 days", to: daysAgo(91) },
    ] : []),
  ];
  const active = presets.find((p) => (p.from || "") === (from || "") && (p.to || "") === (to || ""));
  const text = !from && !to ? "Any time" : active ? active.label : `${from || "…"} → ${to || "…"}`;
  const set = !!(from || to);
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button className={cn("inline-flex h-8.5 items-center gap-1.5 rounded-lg border px-2.5 text-[13px]",
          set ? "border-accent bg-accent-soft text-accent-fg" : "border-border-strong bg-surface text-fg-2 hover:text-fg")}>
          <CalendarDays className="size-4 opacity-70" />
          <span className="text-muted">{label}:</span> <span className="font-medium">{text}</span>
          {set && <X className="size-3.5 opacity-70 hover:opacity-100" onClick={(e) => { e.stopPropagation(); onChange(undefined, undefined); }} />}
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={6} className="z-50 w-64 rounded-xl border border-border bg-surface p-2 shadow-xl">
          {presets.map((p) => (
            <Popover.Close asChild key={p.label}>
              <button onClick={() => onChange(p.from, p.to)}
                className={cn("flex w-full items-center rounded-md px-2.5 py-1.5 text-left text-[13px] hover:bg-surface-2", active?.label === p.label && "font-semibold text-accent-fg")}>
                {p.label}
              </button>
            </Popover.Close>
          ))}
          <div className="mt-2 border-t border-border px-1 pt-2">
            <div className="mb-1 text-[11.5px] text-muted">Custom range</div>
            <div className="flex items-center gap-1.5">
              <Input type="date" className="h-8 w-full px-1.5 text-xs" value={from || ""} onChange={(e) => onChange(e.target.value || undefined, to)} />
              <span className="text-muted">→</span>
              <Input type="date" className="h-8 w-full px-1.5 text-xs" value={to || ""} onChange={(e) => onChange(from, e.target.value || undefined)} />
            </div>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
