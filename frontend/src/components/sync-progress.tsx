"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Circle, Loader2, MinusCircle, PlugZap, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { fmtDt, fmtN, fmtRel, parseTs } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button } from "./ui";

export function useSyncStatus() {
  return useQuery({
    queryKey: ["sync-status"],
    queryFn: () => api<any>("/api/sync/status"),
    refetchInterval: (q) => ((q.state.data as any)?.running ? 1500 : 30000),
  });
}

const ICON: Record<string, React.ReactNode> = {
  pending: <Circle className="size-4 text-border-strong" />,
  running: <Loader2 className="size-4 animate-spin text-accent" />,
  done: <CheckCircle2 className="size-4 text-good" />,
  skipped: <MinusCircle className="size-4 text-muted" />,
  warning: <AlertTriangle className="size-4 text-warn" />,
  error: <XCircle className="size-4 text-crit" />,
};

function elapsed(from?: string | null) {
  const d = parseTs(from);
  if (!d) return "";
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

/** Step-by-step view of the running (or last) sync with live log lines. */
export function SyncProgress({ status, compact }: { status: any; compact?: boolean }) {
  const [, tick] = React.useState(0);
  React.useEffect(() => {
    if (!status?.running) return;
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, [status?.running]);
  const steps: any[] = status?.steps || [];
  if (!steps.length) return null;
  return (
    <div className={cn("rounded-xl border border-border bg-surface-2", compact ? "p-3" : "p-4")}>
      <div className="mb-3 flex items-center gap-2 text-[13px]">
        {status.running ? <Loader2 className="size-4 animate-spin text-accent" /> : steps.some((s) => s.status === "error") ? <XCircle className="size-4 text-crit" /> : <CheckCircle2 className="size-4 text-good" />}
        <b>{status.running ? "Sync in progress" : steps.some((s) => s.status === "error") ? "Last sync failed" : "Last sync completed"}</b>
        {status.running && <span className="text-muted">· {elapsed(status.started_at)}</span>}
      </div>
      <ol className="space-y-2">
        {steps.map((s) => {
          const pctDone = s.total ? Math.min(100, (100 * s.done) / s.total) : 0;
          return (
            <li key={s.key} className="grid grid-cols-[18px_minmax(0,1fr)] gap-x-2.5">
              <span className="mt-0.5">{ICON[s.status] || ICON.pending}</span>
              <div className="min-w-0">
                <div className="flex items-baseline gap-2 text-[13px]">
                  <span className={cn(s.status === "pending" ? "text-muted" : "font-medium")}>{s.label}</span>
                  {s.status === "running" && s.total > 0 && <span className="tabular text-xs text-muted">{fmtN(s.done)} / {fmtN(s.total)}</span>}
                </div>
                {s.status === "running" && s.total > 0 && (
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-3"><div className="h-full rounded-full bg-accent transition-all" style={{ width: `${pctDone}%` }} /></div>
                )}
                {s.detail && s.status !== "running" && (
                  <div className={cn("text-xs", s.status === "error" ? "text-crit-fg" : s.status === "warning" ? "text-warn-fg" : "text-muted")}>{s.detail}</div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      {!compact && status.log_tail?.length > 0 && (
        <div className="mt-4 max-h-44 overflow-y-auto rounded-lg bg-[#0b0e14] p-3 font-mono text-[11.5px] leading-relaxed text-[#c9d1d9] scroll-thin">
          {status.log_tail.map((l: any, i: number) => (
            <div key={i} className={l.level === "error" ? "text-[#ff7b72]" : l.level === "warn" ? "text-[#e3b341]" : ""}>
              <span className="text-[#6e7681]">{fmtDt(l.ts).slice(11)}</span> {l.message}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Banner / empty state shown when the CrowdStrike API is not connected, or the first sync is running. */
export function NotConnected({ big }: { big?: boolean }) {
  const { data: st } = useSyncStatus();
  if (!st) return null;
  const synced = st.runs?.some((r: any) => r.status === "ok");
  if (st.configured && synced) return null;
  if (st.configured && st.running) {
    return (
      <div className="mb-5">
        <div className="mb-2 text-[13px] text-fg-2">The first sync with CrowdStrike is running — data appears as soon as it finishes.</div>
        <SyncProgress status={st} compact={!big} />
      </div>
    );
  }
  return (
    <div className={cn("mb-5 flex flex-wrap items-center gap-4 rounded-2xl border border-accent/40 bg-accent-soft/50", big ? "p-8" : "p-4")}>
      <div className="grid size-11 place-items-center rounded-xl bg-accent text-white"><PlugZap className="size-5" /></div>
      <div className="min-w-0 flex-1">
        <div className="text-[15px] font-semibold">{st.configured ? "No data yet" : "Connect CrowdStrike Falcon"}</div>
        <div className="text-[12.5px] text-fg-2">
          {st.configured
            ? `The last sync did not complete${st.runs?.[0]?.message ? `: ${st.runs[0].message}` : ""}.`
            : "Add an API client (Hosts: Read scope) to start syncing your hosts. Everything is stored in the local database and refreshed automatically."}
        </div>
      </div>
      <Link href="/settings/"><Button variant="primary">{st.configured ? "Open sync settings" : "Connect now"}</Button></Link>
    </div>
  );
}

export function nextSyncLabel(st: any) {
  if (!st?.configured) return "Not connected";
  if (st.running) return st.stage;
  if (!st.interval_minutes) return "Automatic sync is off";
  const d = parseTs(st.next_sync_at);
  if (!d) return "";
  return d.getTime() <= Date.now() ? "Next sync starting shortly" : `Next sync at ${fmtDt(st.next_sync_at).slice(11)}`;
}
