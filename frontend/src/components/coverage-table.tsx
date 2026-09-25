"use client";
import * as React from "react";
import Link from "next/link";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Meter } from "./ui";

/** One table for LOB-level or MSP-level coverage rows (from lob_summaries / msp_summaries). */
export function CoverageTable({ rows, mode, showLob = true, maxHeight, actions, compact }: { rows: any[]; mode: "lob" | "msp"; showLob?: boolean; maxHeight?: string; actions?: (r: any) => React.ReactNode; compact?: boolean }) {
  const dup = !compact;
  if (!rows?.length) return <div className="py-8 text-center text-muted">No data yet — create a LOB and upload its inventory.</div>;
  const lobId = (r: any) => (mode === "lob" ? r.id : r.lob_id);
  const inv = (r: any, extra: string) => `/lob/?id=${lobId(r)}&tab=inventory${mode === "msp" ? `&msp=${r.msp_id ?? "none"}` : ""}${extra}`;
  const tot = rows.reduce((a, r) => {
    ["nodes", "applicable", "installed", "online", "offline", "not_installed", "hidden", "removed", "unlisted", "edr_dup_ips", "cross_msp_dup_ips"].forEach((k) => (a[k] = (a[k] || 0) + (r[k] || 0)));
    return a;
  }, {} as Record<string, number>);
  const Num = ({ n, href, tone }: { n: number; href?: string; tone?: string }) =>
    !n ? <span className="text-muted">0</span> : href ? <Link href={href} className={cn("font-medium hover:underline", tone)}>{fmtN(n)}</Link> : <span className={tone}>{fmtN(n)}</span>;
  const th = "sticky top-0 z-10 whitespace-nowrap border-b border-border bg-surface-2 px-3 py-2 text-xs font-semibold text-fg-2";
  const td = "border-b border-border px-3 py-2 tabular";
  return (
    <div className="overflow-auto scroll-thin" style={{ maxHeight }}>
      <table className="w-full border-separate border-spacing-0 text-[12.8px]">
        <thead>
          <tr>
            {(mode === "lob" || showLob) && <th className={cn(th, "text-left")}>LOB</th>}
            {mode === "msp" && <th className={cn(th, "text-left")}>MSP</th>}
            {mode === "lob" && <th className={cn(th, "text-right")}>MSPs</th>}
            <th className={cn(th, "text-right")} title="All inventory nodes">Nodes</th>
            <th className={cn(th, "text-right")} title="Live and EDR feasible">Applicable</th>
            <th className={cn(th, "text-right")} title="Applicable nodes with an agent in the console">Installed</th>
            <th className={cn(th, "text-left")} title="Installed ÷ Applicable">Coverage</th>
            <th className={cn(th, "text-right")}>Online</th>
            <th className={cn(th, "text-right")}>Offline</th>
            <th className={cn(th, "text-right")} title="Applicable nodes with no Falcon agent">Not installed</th>
            <th className={cn(th, "text-right")} title="Agent removed from / hidden in the console">Removed / hidden</th>
            <th className={cn(th, "text-right")} title="Agents tagged to this LOB/MSP that are missing from its inventory">Not in inventory</th>
            {dup && <th className={cn(th, "text-right")} title="Installed nodes whose IP is shared by several active agents">Dup IPs (EDR)</th>}
            {dup && mode === "lob" && <th className={cn(th, "text-right")} title="Same IP listed under more than one MSP">IPs in &gt;1 MSP</th>}
            {actions && <th className={th} />}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={mode === "lob" ? r.id : `${r.lob_id}-${r.msp_id}`} className="group hover:[&>td]:bg-surface-2">
              {(mode === "lob" || showLob) && <td className={cn(td, "font-semibold")}><Link href={`/lob/?id=${lobId(r)}`} className="hover:underline">{mode === "lob" ? r.name : r.lob}</Link></td>}
              {mode === "msp" && <td className={td}><Link href={inv(r, "")} className={cn("font-medium hover:underline", r.msp_id === null && "text-muted")}>{r.msp}</Link></td>}
              {mode === "lob" && <td className={cn(td, "text-right")}>{r.msp_count}</td>}
              <td className={cn(td, "text-right")}><Num n={r.nodes} href={inv(r, "")} /></td>
              <td className={cn(td, "text-right")}><Num n={r.applicable} href={inv(r, "&applicable=1")} /></td>
              <td className={cn(td, "text-right")}><Num n={r.installed} href={inv(r, "&installed=1")} /></td>
              <td className={td}>{r.coverage === null ? <span className="text-muted">–</span> : <div className="flex min-w-[120px] items-center gap-2"><div className="w-20"><Meter value={r.coverage} /></div><b>{r.coverage}%</b></div>}</td>
              <td className={cn(td, "text-right")}><Num n={r.online} href={inv(r, "&coverage_status=Online")} tone="text-good-fg" /></td>
              <td className={cn(td, "text-right")}><Num n={r.offline} href={inv(r, "&coverage_status=Offline")} tone="text-warn-fg" /></td>
              <td className={cn(td, "text-right")}><Num n={r.not_installed} href={inv(r, "&coverage_status=Not Installed")} tone="text-crit-fg" /></td>
              <td className={cn(td, "text-right")}><Num n={r.hidden + r.removed} href={inv(r, "&pending=1")} tone="text-crit-fg" /></td>
              <td className={cn(td, "text-right")}><Num n={r.unlisted} href={`/lob/?id=${lobId(r)}&tab=unlisted${mode === "msp" && r.msp_id ? `&msp=${r.msp_id}` : ""}`} tone="text-violet-fg" /></td>
              {dup && <td className={cn(td, "text-right")}>{r.edr_dup_ips ? <Badge tone="serious">{fmtN(r.edr_dup_ips)}</Badge> : <span className="text-muted">0</span>}</td>}
              {dup && mode === "lob" && <td className={cn(td, "text-right")}>{r.cross_msp_dup_ips ? <Link href={`/lob/?id=${r.id}&tab=inventory&cross_msp_dup=1`}><Badge tone="serious">{fmtN(r.cross_msp_dup_ips)}</Badge></Link> : <span className="text-muted">0</span>}</td>}
              {actions && <td className={cn(td, "whitespace-nowrap text-right")}>{actions(r)}</td>}
            </tr>
          ))}
          {rows.length > 1 && (
            <tr className="font-semibold [&>td]:bg-surface-2">
              {(mode === "lob" || showLob) && <td className={td}>Total</td>}
              {mode === "msp" && <td className={td}>{showLob ? "" : "Total"}</td>}
              {mode === "lob" && <td className={td} />}
              <td className={cn(td, "text-right")}>{fmtN(tot.nodes)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.applicable)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.installed)}</td>
              <td className={td}>{tot.applicable ? `${Math.round((1000 * tot.installed) / tot.applicable) / 10}%` : "–"}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.online)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.offline)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.not_installed)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.hidden + tot.removed)}</td>
              <td className={cn(td, "text-right")}>{fmtN(tot.unlisted)}</td>
              {dup && <td className={cn(td, "text-right")}>{fmtN(tot.edr_dup_ips)}</td>}
              {dup && mode === "lob" && <td className={cn(td, "text-right")}>{fmtN(tot.cross_msp_dup_ips)}</td>}
              {actions && <td className={td} />}
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
