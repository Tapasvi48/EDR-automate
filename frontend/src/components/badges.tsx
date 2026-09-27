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
    return (
      <span className="inline-flex items-center gap-1.5">{dot("bg-warn")}Offline
        <span className="text-[11.5px] text-muted">· {r.removal_type === "imported" ? "old EDR import" : r.removal_type === "deleted" ? "deleted" : "removed from console"}</span>
      </span>
    );
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
  if (r.dup_count > 1) out.push(<Badge key="d" tone="serious" title={`${r.dup_count} agents with connection IP ${r.connection_ip} and local IP ${r.local_ip} (at most one online)`}>DUP ×{r.dup_count}</Badge>);
  if (r.rc_count > 1) out.push(<Badge key="rc" tone="crit" title={`${r.rc_count} online agents share connection IP ${r.connection_ip} and local IP ${r.local_ip}`}>ROUTING ×{r.rc_count}</Badge>);
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
/** OS with where it came from: the agent (EDR), the inventory sheet (INV) or the VA scan's OS Identification plugin (VA). */
export const OS_SRC: Record<string, [string, string]> = {
  edr: ["EDR", "Reported by the CrowdStrike agent"], inventory: ["INV", "From the inventory OS column"],
  scan: ["VA", "Detected by the VA scan (Nessus plugin 11936 OS Identification)"],
};
export const OsCell = ({ os, src }: { os?: string; src?: string }) =>
  os ? (
    <span title={src ? OS_SRC[src]?.[1] : undefined}>
      {os}{src && OS_SRC[src] && <span className="ml-1.5 rounded bg-surface-3 px-1 py-px text-[10px] font-semibold tracking-wide text-muted">{OS_SRC[src][0]}</span>}
    </span>
  ) : <span className="text-muted">Unknown</span>;
/** Decided EDR feasibility (rules / manual / agent installed) with the reason on hover. */
export const FeasibleBadge = ({ v, reason }: { v?: string; reason?: string }) =>
  v === "Yes" ? <Badge tone="good" title={reason}>Feasible</Badge> : v === "No" ? <Badge tone="crit" title={reason}>Not feasible</Badge>
    : v === "Legacy" ? <Badge tone="serious" title={reason}>Legacy</Badge>
    : v === "To be decided" ? <Badge tone="warn" title={reason}>To be decided</Badge>
    : v === "Unidentified" ? <Badge tone="violet" title={reason}>Unidentified</Badge> : <span className="text-muted">–</span>;
/** OS support status from the OS support catalog (what the N-2 or newer sensors run on). */
export const OsSupportBadge = ({ v }: { v?: string }) =>
  v === "Supported" ? <Badge tone="good">Supported</Badge> : v === "Legacy" ? <Badge tone="serious">Legacy</Badge>
    : v === "Not supported" ? <Badge tone="crit">Not supported</Badge> : <span className="text-muted">Not in catalog</span>;
const LEVEL_TONE: Record<string, Tone> = { N: "good", "N-1": "good", "N-2": "warn", older: "crit" };
/** Sensor version with its level against the published N / N-1 / N-2 builds. */
export const SensorCell = ({ v, level }: { v?: string; level?: string }) =>
  v ? <span className="inline-flex items-center gap-1.5"><span className="font-mono text-[12px]">{v}</span>{level && <Badge tone={LEVEL_TONE[level] || "neutral"} title={level === "older" ? "Older than N-2: end of support, upgrade the sensor" : undefined}>{level === "older" ? "Older than N-2" : level}</Badge>}</span>
    : <span className="text-muted">–</span>;
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
  hostname_change: "Hostname changed", agent_update: "Sensor updated", reinstall: "Reinstall detected", imported: "Imported (old EDR)",
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
export const removalLabel = (t?: string) => ({ auto_inactive: "Auto-removed (inactive)", deleted: "Deleted", hidden: "Hidden", imported: "Old EDR import" } as any)[t || ""] || t || "";

const SEV_TONE: Record<string, Tone> = { Critical: "crit", High: "serious", Medium: "warn", Low: "info", Info: "neutral" };
export const SeverityBadge = ({ s }: { s?: string }) => (s ? <Badge tone={SEV_TONE[s] || "neutral"}>{s}</Badge> : null);
const EDR_TONE: Record<string, Tone> = { Online: "good", Offline: "warn", Hidden: "violet", Removed: "crit", "Old EDR import": "outline", "Not Installed": "crit" };
export const EdrBadge = ({ s }: { s?: string }) => (s ? <Badge tone={EDR_TONE[s] || "neutral"}>{s === "Not Installed" ? "No EDR" : s}</Badge> : <span className="text-muted">–</span>);
/** Compact open-vulnerability counts: C / H / M / L */
export function SevCounts({ c = 0, h = 0, m = 0, l = 0 }: { c?: number; h?: number; m?: number; l?: number }) {
  const cell = (n: number, cls: string, t: string) => (
    <span title={`${n} ${t}`} className={cn("inline-flex min-w-[26px] justify-center rounded px-1 text-[11px] font-semibold tabular", n ? cls : "bg-surface-3 text-muted")}>{n}</span>
  );
  return (
    <span className="inline-flex gap-1">
      {cell(c, "bg-crit-soft text-crit-fg", "critical")}{cell(h, "bg-serious-soft text-serious-fg", "high")}
      {cell(m, "bg-warn-soft text-warn-fg", "medium")}{cell(l, "bg-accent-soft text-accent-fg", "low")}
    </span>
  );
}

const COVERAGE_TONE: Record<string, Tone> = { Online: "good", Offline: "warn", Hidden: "violet", Removed: "crit", "Not Installed": "crit", "Not Feasible": "neutral", "Legacy OS": "serious", "Non Live": "outline" };
export const COVERAGE_HELP: Record<string, string> = {
  Online: "Applicable node with an agent that is online now",
  Offline: "Applicable node whose agent is offline",
  Hidden: "Agent exists but is hidden in the Falcon console",
  Removed: "Agent was removed from the console (manually or after the inactivity window)",
  "Not Installed": "Applicable node with no matching Falcon agent",
  "Not Feasible": "Not EDR feasible (OS not supported by CrowdStrike, node type rule or manual decision) — excluded from coverage",
  "Legacy OS": "Legacy OS: no current (N-2) sensor runs on it and no agent is installed — excluded from coverage",
  "Non Live": "Inventory marks the node Non Live — excluded from coverage",
};
export const CoverageBadge = ({ v }: { v?: string }) => (v ? <Badge tone={COVERAGE_TONE[v] || "neutral"} title={COVERAGE_HELP[v]}>{v}</Badge> : <span className="text-muted">–</span>);
/** Duplicate tag for an inventory row: repeated in the uploaded file and/or sharing IP / node name with other rows of the LOB */
export function dupReasons(r: any) {
  const out: string[] = [];
  if (r.file_dups > 0) out.push(`${r.file_dups + 1} rows in the uploaded file`);
  if (r.dup_ip > 1) out.push(`IP shared by ${r.dup_ip} rows`);
  if (r.dup_name > 1) out.push(`node name shared by ${r.dup_name} rows`);
  return out;
}
export const DupBadge = ({ r }: { r: any }) => {
  const why = dupReasons(r);
  return why.length ? <Badge tone="serious" title={"Duplicate: " + why.join(", ")}>DUP</Badge> : null;
};

const RISK_TONE: Record<string, Tone> = { Critical: "crit", High: "serious", Medium: "warn", Low: "good" };
/** Risk score pill; hover lists what the score is made of. */
export function RiskBadge({ score, level, factors }: { score?: number | null; level?: string | null; factors?: [string, number][] }) {
  if (score === null || score === undefined) return <span className="text-muted">–</span>;
  const why = (factors || []).map(([n, p]) => (p ? `+${p}  ${n}` : n)).join("\n");
  return (
    <Badge tone={RISK_TONE[level || ""] || "neutral"} title={why || undefined} className="tabular">
      {score} · {level}
    </Badge>
  );
}
