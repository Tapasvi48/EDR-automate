"use client";
import * as React from "react";
import Link from "next/link";
import { fmtN, pct } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StackBar } from "./charts";

const SUM_KEYS = ["nodes", "applicable", "installed", "online", "offline", "offline_console", "removed_import", "removed_console",
                  "offline_removed", "pending", "to_be_decided", "legacy", "in_niam", "live_nodes", "scanned_live", "unlisted"];

/** LOB- or MSP-level coverage: EDR, NIAM and vulnerability-scan coverage of the inventory side by side. */
export function CoverageTable({ rows, mode, showLob = true, maxHeight, actions, showMspCount = true, days }: {
  rows: any[]; mode: "lob" | "msp"; showLob?: boolean; maxHeight?: string; actions?: (r: any) => React.ReactNode; compact?: boolean;
  showMspCount?: boolean; days?: number | string;
}) {
  if (!rows?.length) return <div className="py-8 text-center text-muted">No data yet — create a LOB and upload its inventory.</div>;
  const lobId = (r: any) => (mode === "lob" ? r.id : r.lob_id);
  const [split, setSplit] = React.useState(false);
  const inv = (r: any, extra: string) => (r.__total ? `/inventory/?${extra.slice(1)}` : `/lob/?id=${lobId(r)}&tab=inventory${mode === "msp" ? `&msp=${r.msp_id ?? "none"}` : ""}${extra}`);
  const tot = rows.reduce((a, r) => { SUM_KEYS.forEach((k) => (a[k] = (a[k] || 0) + (r[k] || 0))); return a; }, {} as Record<string, number>);
  const all = rows.length > 1 ? [...rows, { ...tot, __total: true, coverage: tot.applicable ? Math.round((1000 * tot.installed) / tot.applicable) / 10 : null }] : rows;
  const Num = ({ n, href, cls }: { n: number; href: string; cls?: string }) =>
    !n ? <span className="text-muted">0</span> : <Link href={href} className={cn("font-medium hover:underline", cls)}>{fmtN(n)}</Link>;
  const th = "sticky top-0 z-10 whitespace-nowrap bg-surface-2 px-3 py-2 text-xs font-semibold text-fg-2";
  const grp = "sticky top-0 z-10 bg-surface-2 px-3 pt-2 text-[10.5px] font-semibold uppercase tracking-wider text-muted";
  const td = "border-b border-border px-3 py-2.5 tabular";
  const sep = "border-l border-border";
  const nameCols = (mode === "lob" || showLob ? 1 : 0) + (mode === "msp" ? 1 : 0) + (mode === "lob" && showMspCount ? 1 : 0) + 1;
  return (
    <div className="overflow-auto scroll-thin" style={{ maxHeight }}>
      <table className="w-full border-separate border-spacing-0 text-[13px]">
        <thead>
          <tr>
            <th className={grp} colSpan={nameCols} />
            <th className={cn(grp, sep, "text-left")} colSpan={6}>EDR (CrowdStrike)</th>
            <th className={cn(grp, sep, "text-left")}>NIAM</th>
            <th className={cn(grp, sep, "text-left")}>Vulnerability scan</th>
            <th className={cn(grp, sep)} colSpan={actions ? 2 : 1}>
              <button onClick={() => setSplit(!split)} className="font-semibold uppercase tracking-wider hover:text-fg"
                title="Show how much of Offline is still in the console, removed from it, or only in the old EDR upload">
                {split ? "Offline split ✓" : "Split Offline"}
              </button>
            </th>
          </tr>
          <tr className="[&>th]:border-b [&>th]:border-border">
            {(mode === "lob" || showLob) && <th className={cn(th, "text-left")}>LOB</th>}
            {mode === "msp" && <th className={cn(th, "text-left")}>MSP</th>}
            {mode === "lob" && showMspCount && <th className={cn(th, "text-right")}>MSPs</th>}
            <th className={cn(th, "text-right")} title="All inventory nodes">Nodes</th>
            <th className={cn(th, sep, "text-right")} title="Live and EDR-feasible nodes">EDR applicable</th>
            <th className={cn(th, "text-left")} title="Installed (online + offline) ÷ EDR applicable">Coverage</th>
            <th className={cn(th, "text-right")}>Online</th>
            <th className={cn(th, "text-right")} title={`Offline in the console, the agent left the console (offline > ${days || 90} days, or an old EDR upload), or a legacy sensor`}>Offline</th>
            <th className={cn(th, "text-right")} title="Applicable nodes with no agent at all">Not installed</th>
            <th className={cn(th, "text-right")} title="Feasibility not decided yet: the OS is unknown or not in the support catalog">To be decided</th>
            <th className={cn(th, sep, "text-left")} title="Inventory nodes whose IP is in the latest NIAM dump">In NIAM</th>
            <th className={cn(th, sep, "text-left")} title="Live nodes whose IP appears in an uploaded scan">Scanned</th>
            <th className={cn(th, sep, "text-right")} title="EDR installed, but the node is not in the uploaded LOB inventory (tagged agents are not counted twice)">Not in inventory</th>
            {actions && <th className={th} />}
          </tr>
        </thead>
        <tbody>
          {all.map((r) => (
            <tr key={r.__total ? "total" : mode === "lob" ? r.id : `${r.lob_id}-${r.msp_id}`} className={cn("group", r.__total ? "font-semibold [&>td]:bg-surface-2" : "hover:[&>td]:bg-surface-2")}>
              {(mode === "lob" || showLob) && <td className={cn(td, "whitespace-nowrap font-semibold")}>{r.__total ? "Total" : <Link href={`/lob/?id=${lobId(r)}`} className="hover:underline">{mode === "lob" ? r.name : r.lob}</Link>}</td>}
              {mode === "msp" && <td className={cn(td, "whitespace-nowrap")}>{r.__total ? (showLob ? "" : "Total") : <Link href={inv(r, "")} className={cn("font-medium hover:underline", r.msp_id === null && "text-muted")}>{r.msp}</Link>}</td>}
              {mode === "lob" && showMspCount && <td className={cn(td, "text-right")}>{r.__total ? "" : r.msp_count}</td>}
              <td className={cn(td, "text-right")}><Num n={r.nodes} href={inv(r, "&")} /></td>
              <td className={cn(td, sep, "text-right")}><Num n={r.applicable} href={inv(r, "&applicable=1")} /></td>
              <td className={td}>
                <div className="flex min-w-[150px] items-center gap-2">
                  <StackBar className="flex-1" scale={r.applicable} parts={[{ label: "Online", n: r.online || 0, color: "var(--good)" }, { label: "Offline", n: r.offline || 0, color: "var(--warn)" }, { label: "Not installed", n: r.pending || 0, color: "var(--crit)" }]} />
                  <b className="w-11 text-right">{r.coverage === null || r.coverage === undefined ? "–" : `${r.coverage}%`}</b>
                </div>
              </td>
              <td className={cn(td, "text-right")}><Num n={r.online} href={inv(r, "&coverage_status=Online")} cls="text-good-fg" /></td>
              <td className={cn(td, "text-right")}
                title={r.offline_console || r.offline_removed ? `${fmtN(r.offline_console)} offline in the console · ${fmtN(r.removed_console)} removed from the console · ${fmtN(r.removed_import)} old EDR import only` : undefined}>
                <Num n={r.offline} href={inv(r, "&coverage_status=Offline")} cls="text-warn-fg" />
                {split && <div className="whitespace-nowrap text-[10.5px] font-normal text-muted">
                  <Link href={inv(r, "&coverage_status=Offline&offline_kind=console")} className="hover:underline">{fmtN(r.offline_console)} in console</Link>
                  {" · "}<Link href={inv(r, "&coverage_status=Offline&offline_kind=removed")} className="hover:underline">{fmtN(r.removed_console)} removed</Link>
                </div>}
              </td>
              <td className={cn(td, "text-right")}><Num n={r.pending} href={inv(r, "&pending=1")} cls="text-crit-fg" /></td>
              <td className={cn(td, "text-right")} title="OS unknown or not in the support catalog: needs a decision">
                <Num n={r.to_be_decided} href={inv(r, "&coverage_status=To+Be+Decided")} cls="text-warn-fg" />
              </td>
              <td className={cn(td, sep)}>
                <Coverage n={r.in_niam || 0} of={r.nodes || 0} missHref={inv(r, "&niam=0")} missLabel="not in NIAM" />
              </td>
              <td className={cn(td, sep)}>
                <Coverage n={r.scanned_live || 0} of={r.live_nodes || 0} missHref={inv(r, "&scanned=0")} missLabel="never scanned" />
              </td>
              <td className={cn(td, sep, "text-right")}><Num n={r.unlisted} href={r.__total ? "/assets/?unlisted=1" : `/lob/?id=${lobId(r)}&tab=unlisted${mode === "msp" && r.msp_id ? `&msp=${r.msp_id}` : ""}`} cls="text-violet-fg" /></td>
              {actions && <td className={cn(td, "whitespace-nowrap text-right")}>{r.__total ? null : actions(r)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Coverage({ n, of, missHref, missLabel }: { n: number; of: number; missHref: string; missLabel: string }) {
  if (!of) return <span className="text-muted">–</span>;
  const miss = of - n;
  return (
    <div className="min-w-[120px]">
      <div className="flex items-center gap-2">
        <StackBar className="flex-1" height={6} parts={[{ label: "Covered", n, color: "var(--s1)" }, { label: missLabel, n: miss, color: "var(--border-strong)" }]} />
        <b className="w-10 text-right">{pct(n, of)}%</b>
      </div>
      <div className="mt-0.5 text-[10.5px] font-normal text-muted">{fmtN(n)} of {fmtN(of)}{miss > 0 && <> · <Link href={missHref} className="hover:underline">{fmtN(miss)} {missLabel}</Link></>}</div>
    </div>
  );
}
