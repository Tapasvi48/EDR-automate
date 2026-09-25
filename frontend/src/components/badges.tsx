"use client";
import * as React from "react";
import { fmtDt, fmtRel, hoursSince } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, type Tone } from "./ui";
import { useHostDrawer } from "./host-drawer";

export function useStaleHours() {
  const [h, setH] = React.useState(1);
  React.useEffect(() => {
    const v = (globalThis as any).__staleHours;
    if (v) setH(v);
  }, []);
  return h;
}

export function HostStatus({ r }: { r: any }) {
  const stale = (globalThis as any).__staleHours || 1;
  const dot = (cls: string) => <span className={cn("inline-block size-2 shrink-0 rounded-full", cls)} />;
  if (r.console_state === "removed")
    return <span className="inline-flex items-center gap-1.5 text-fg-2">{dot("bg-muted")}Removed</span>;
  if (r.console_state === "hidden")
    return <span className="inline-flex items-center gap-1.5 text-fg-2">{dot("bg-muted")}Hidden</span>;
  const hs = hoursSince(r.last_seen);
  if (r.online_state === "online") {
    if (hs !== null && hs > stale)
      return (
        <span className="inline-flex items-center gap-1.5" title={`Online per Falcon, but last seen ${fmtRel(r.last_seen)}`}>
          {dot("bg-warn ring-3 ring-warn-soft")}Online <span className="text-[11.5px] text-muted">· seen {fmtRel(r.last_seen)}</span>
        </span>
      );
    return <span className="inline-flex items-center gap-1.5">{dot("bg-good ring-3 ring-good-soft")}Online</span>;
  }
  if (r.online_state === "offline")
    return (
      <span className="inline-flex items-center gap-1.5">
        {dot("bg-crit")}Offline <span className="text-[11.5px] text-muted">· {fmtRel(r.last_seen)}</span>
      </span>
    );
  return <span className="inline-flex items-center gap-1.5 text-fg-2">{dot("bg-muted")}Unknown</span>;
}

export function HostFlags({ r }: { r: any }) {
  const out: React.ReactNode[] = [];
  if (r.dup_count > 1) out.push(<Badge key="d" tone="serious" title={`${r.dup_count} active agents share IP ${r.local_ip}`}>DUP ×{r.dup_count}</Badge>);
  if (r.is_reinstall) out.push(<Badge key="r" tone="violet" title={`Reinstall – older agent matched by ${r.reinstall_reason}`}>REINSTALL</Badge>);
  if ((r.rfm || "").toLowerCase() === "yes") out.push(<Badge key="f" tone="warn" title="Reduced functionality mode">RFM</Badge>);
  if (r.containment_status && r.containment_status !== "normal") out.push(<Badge key="c" tone="crit">{r.containment_status.toUpperCase()}</Badge>);
  const fs = hoursSince(r.first_seen);
  if (fs !== null && fs < 24 * 7) out.push(<Badge key="n" tone="info">NEW</Badge>);
  return out.length ? <span className="ml-1.5 inline-flex gap-1 align-middle">{out}</span> : null;
}

export function HostLink({ aid, children, className }: { aid: string; children: React.ReactNode; className?: string }) {
  const { open } = useHostDrawer();
  return (
    <a className={cn("cursor-pointer text-accent-fg hover:underline", className)} onClick={(e) => { e.stopPropagation(); open(aid); }}>
      {children}
    </a>
  );
}

const VERIF: Record<string, Tone> = {
  Verified: "good", "Installed - Inactive": "warn", "Claimed - Not Found": "crit", "Claimed - Removed from Console": "crit",
  "Installed - Marked No": "serious", "Installed - Marked Not Feasible": "serious", "Pending Install": "warn",
  "Not Feasible": "neutral", "Found - No Claim": "info", "Not Found - No Claim": "warn",
};
export const VERIFICATION_HELP: Record<string, string> = {
  Verified: "Inventory says installed and an active Falcon agent was found.",
  "Installed - Inactive": "Agent exists but has not checked in for longer than the inventory stale threshold.",
  "Claimed - Not Found": "Inventory says EDR installed, but no Falcon agent matches the IP or hostname.",
  "Claimed - Removed from Console": "Inventory says installed, but the only matching agent was removed/hidden from the console.",
  "Installed - Marked No": "Inventory says NOT installed, but an active Falcon agent exists – update the inventory.",
  "Installed - Marked Not Feasible": "Marked not feasible, but a Falcon agent is running on it.",
  "Pending Install": "Feasible, marked not installed, and no agent found – deployment backlog.",
  "Not Feasible": "Marked not feasible for EDR and no agent found.",
  "Found - No Claim": "No EDR Installed value in inventory; an agent was found.",
  "Not Found - No Claim": "No EDR Installed value in inventory; no agent found.",
};
export const VerifBadge = ({ v }: { v?: string }) => (v ? <Badge tone={VERIF[v] || "neutral"} title={VERIFICATION_HELP[v]}>{v}</Badge> : <span className="text-muted">–</span>);
const ACTUAL: Record<string, Tone> = { Online: "good", Offline: "warn", Inactive: "serious", Removed: "crit", Hidden: "crit", "Not Found": "crit", "IP Used by Other Host": "serious" };
export const ActualBadge = ({ v }: { v?: string }) => (v ? <Badge tone={ACTUAL[v] || "neutral"}>{v}</Badge> : <span className="text-muted">–</span>);
export const ChangeTag = ({ t }: { t?: string }) =>
  t === "new" ? <Badge tone="info">NEW</Badge> : t === "modified" ? <Badge tone="warn">MODIFIED</Badge> : null;
export const YN = ({ v }: { v?: string }) =>
  v === "Yes" ? <Badge tone="good">Yes</Badge> : v === "No" ? <Badge tone="crit">No</Badge> : <span className={v ? "" : "text-muted"}>{v || "–"}</span>;
export const Live = ({ v }: { v?: string }) =>
  v === "Live" ? <Badge tone="good">Live</Badge> : v === "Non Live" ? <Badge>Non Live</Badge> : <span className={v ? "" : "text-muted"}>{v || "–"}</span>;
export const Mono = ({ children }: { children: React.ReactNode }) => <span className="font-mono text-[12px]">{children}</span>;
export const When = ({ ts }: { ts?: string }) => (
  <span title={ts}>
    {fmtDt(ts)} <span className="text-[11.5px] text-muted">{ts ? fmtRel(ts) : ""}</span>
  </span>
);

export const EVENT_LABEL: Record<string, string> = {
  new: "New install", removed: "Removed from console", hidden: "Hidden", restored: "Restored", ip_change: "IP changed",
  hostname_change: "Hostname changed", agent_update: "Sensor updated", reinstall: "Reinstall detected",
};
const EVENT_TONE: Record<string, Tone> = { new: "info", removed: "crit", hidden: "crit", restored: "good", ip_change: "warn", hostname_change: "warn", agent_update: "neutral", reinstall: "violet" };
export const EventBadge = ({ e }: { e: string }) => <Badge tone={EVENT_TONE[e] || "neutral"}>{EVENT_LABEL[e] || e}</Badge>;
export function EventDetails({ e }: { e: any }) {
  const d = e.details || {};
  switch (e.event) {
    case "ip_change":
    case "hostname_change":
    case "agent_update":
      return <span>{d.old} → <b>{d.new}</b></span>;
    case "removed":
      return <span>{d.type === "auto_inactive" ? "Auto-removed (inactive)" : "Deleted from console"}, last seen {fmtDt(d.last_seen)}</span>;
    case "reinstall":
      return (
        <span>
          Matched by <b>{d.reason}</b> to{" "}
          {(d.previous || []).map((a: string, i: number) => (
            <React.Fragment key={a}>{i > 0 && ", "}<HostLink aid={a}><Mono>{a.slice(0, 10)}…</Mono></HostLink></React.Fragment>
          ))}
        </span>
      );
    case "restored":
      return <span>Was {d.from}</span>;
    case "new":
      return <span>{d.hostname} <Mono>{d.ip}</Mono></span>;
    default:
      return null;
  }
}
export const removalLabel = (t?: string) => ({ auto_inactive: "Auto-removed (inactive)", deleted: "Deleted", hidden: "Hidden" } as any)[t || ""] || t || "";

const COVERAGE_TONE: Record<string, Tone> = { Online: "good", Offline: "warn", Hidden: "violet", Removed: "crit", "Not Installed": "crit", "Not Feasible": "neutral", "Non Live": "outline" };
export const COVERAGE_HELP: Record<string, string> = {
  Online: "Applicable node with an agent that is online now",
  Offline: "Applicable node whose agent is offline",
  Hidden: "Agent exists but is hidden in the Falcon console",
  Removed: "Agent was removed from the console (manually or after the inactivity window)",
  "Not Installed": "Applicable node with no matching Falcon agent",
  "Not Feasible": "Inventory marks EDR as not feasible — excluded from coverage",
  "Non Live": "Inventory marks the node Non Live — excluded from coverage",
};
export const CoverageBadge = ({ v }: { v?: string }) => (v ? <Badge tone={COVERAGE_TONE[v] || "neutral"} title={COVERAGE_HELP[v]}>{v}</Badge> : <span className="text-muted">–</span>);
