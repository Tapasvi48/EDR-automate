"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { FileSpreadsheet } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtN, fmtRel, pct } from "@/lib/format";
import { cn, qs } from "@/lib/utils";
import { Button, Card, CardHeader, Loading, PageHeader } from "@/components/ui";
import { StackBar } from "@/components/charts";
import { Drill, Hero, Line2, Split } from "@/components/summary-cards";
import { NotConnected } from "@/components/sync-progress";

const H = (p: Record<string, any>) => "/assets/" + qs(p);

/** one data-source status cell: Yes / No with detail */

const COV_PARTS = [
  { k: "online", label: "Online", color: "var(--good)", q: "&coverage_status=Online" },
  { k: "offline", label: "Offline", color: "var(--warn)", q: "&coverage_status=Offline" },
  { k: "pending", label: "Not installed", color: "var(--crit)", q: "&pending=1" },
];

/** Offline is one bucket here but has three very different causes - show them on demand instead of forcing a guess. */
const OFFLINE_PARTS = [
  { k: "offline_console", label: "Offline in the console", color: "var(--warn)", q: "&coverage_status=Offline&offline_kind=console",
    hint: "Agent is in the console, just not checking in (proxies, sleeping laptops, RFM)." },
  { k: "removed_console", label: "Removed from console", color: "var(--serious)", q: "&coverage_status=Offline&offline_kind=removed",
    hint: "The agent left the console: auto-removed after the inactivity window, or deleted. Our sync saw it go." },
  { k: "removed_import", label: "Old EDR import only", color: "var(--violet)", q: "&coverage_status=Offline&offline_kind=import",
    hint: "Known only from the uploaded old EDR inventory: no live agent record at all." },
];

function Th({ children, right, title }: { children: React.ReactNode; right?: boolean; title?: string }) {
  return <th title={title} className={cn("whitespace-nowrap px-3 py-2 text-xs font-semibold text-fg-2 first:pl-4 last:pr-4", right ? "text-right" : "text-left")}>{children}</th>;
}
function Bar({ parts, of }: { parts: { n: number; color: string; label: string }[]; of: number }) {
  return <StackBar className="min-w-[120px] flex-1" scale={of} parts={parts} />;
}
const Num = ({ n, href, color }: { n: number; href?: string; color?: string }) =>
  n ? (href ? <Link href={href} className="font-medium hover:underline" style={{ color }}>{fmtN(n)}</Link> : <span style={{ color }}>{fmtN(n)}</span>) : <span className="text-muted">0</span>;

/** EDR coverage per LOB: applicable nodes and where they stand */
function LobCoverage({ rows, total, reg }: { rows: any[]; total: Record<string, number>; reg: Record<string, number> }) {
  const [split, setSplit] = React.useState(false);
  if (!rows.length) return <div className="px-4 pb-6 text-center text-muted">No LOBs yet — <Link href="/lobs/" className="text-accent-fg hover:underline">create one</Link> and upload its inventory.</div>;
  const all = [...rows, { ...total, id: 0, name: "All LOBs", coverage: total.applicable ? Math.round((1000 * total.installed) / total.applicable) / 10 : null }];
  return (
    <div className="overflow-auto scroll-thin">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2 text-[12px]">
        <button onClick={() => setSplit(!split)} className={cn("rounded-md border px-2 py-0.5 font-medium",
          split ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-accent")}>
          {split ? "Hide offline split" : "Split offline"}
        </button>
        {split && OFFLINE_PARTS.map((p) => (
          <span key={p.k} className="inline-flex items-center gap-1.5 text-muted" title={p.hint}>
            <span className="size-2 rounded-full" style={{ background: p.color }} />{p.label}
          </span>
        ))}
      </div>
      <table className="w-full text-[13px]">
        <thead className="border-b border-border bg-surface-2"><tr>
          <Th>LOB</Th><Th right title="Live and EDR-feasible inventory nodes">EDR applicable</Th><Th right title="Applicable nodes with an agent in the console">Installed</Th>
          <Th>Coverage</Th><Th right>Online</Th>
          {split ? OFFLINE_PARTS.map((p) => <Th key={p.k} right title={p.hint}>{p.label}</Th>)
            : <Th right title="Offline in the console, or the agent left the console (removed / old EDR import)">Offline</Th>}
          <Th right title="Applicable nodes with no agent in the live console (never installed, or its agent was removed)">Not installed</Th>
          <Th right title="Feasibility not decided yet: the OS is unknown or not in the support catalog">To be decided</Th>
          <Th right title="Agents tagged to this LOB (agent tags) that its inventory does not list">Tagged, not in inventory</Th>
        </tr></thead>
        <tbody>
          {all.map((r) => {
            const inv = (q: string) => (r.id ? `/lob/?id=${r.id}&tab=inventory${q}` : `/inventory/?${q.slice(1)}`);
            const vals: Record<string, number> = { online: r.online || 0, offline: r.offline || 0, pending: r.pending || 0 };
            return (
              <tr key={r.id} className={cn("border-b border-border last:border-0", r.id ? "hover:bg-surface-2" : "bg-surface-2 font-semibold")}>
                <td className="whitespace-nowrap py-2.5 pl-4 pr-3">{r.id ? <Link href={`/lob/?id=${r.id}`} className="font-semibold hover:underline">{r.name}</Link> : r.name}
                  <div className="text-[11.5px] font-normal text-muted">{fmtN(r.nodes || 0)} nodes in inventory</div></td>
                <td className="px-3 text-right tabular"><Num n={r.applicable} href={inv("&applicable=1")} /></td>
                <td className="px-3 text-right tabular"><Num n={r.installed} href={inv("&installed=1")} /></td>
                <td className="px-3"><div className="flex min-w-[200px] items-center gap-3">
                  {split
                    ? <Bar of={r.applicable || 0} parts={[{ label: "Online", n: vals.online, color: "var(--good)" },
                      ...OFFLINE_PARTS.map((p) => ({ label: p.label, n: r[p.k] || 0, color: p.color })),
                      { label: "Not installed", n: vals.pending, color: "var(--crit)" }]} />
                    : <Bar of={r.applicable || 0} parts={COV_PARTS.map((p) => ({ label: p.label, n: vals[p.k], color: p.color }))} />}
                  <b className="w-12 text-right tabular">{r.coverage === null || r.coverage === undefined ? "–" : `${r.coverage}%`}</b></div></td>
                <td className="px-3 text-right tabular"><Num n={vals.online} href={inv("&coverage_status=Online")} /></td>
                {split
                  ? OFFLINE_PARTS.map((p) => <td key={p.k} className="px-3 text-right tabular"><Num n={r[p.k]} href={inv(p.q)} color={p.color} /></td>)
                  : <td className="px-3 text-right tabular"><Num n={vals.offline} href={inv("&coverage_status=Offline")} color="var(--warn)" /></td>}
                <td className="px-3 text-right tabular"><Num n={vals.pending} href={inv("&pending=1")} color="var(--crit)" /></td>
                <td className="px-3 text-right tabular"><Num n={r.to_be_decided} href={inv("&coverage_status=To+Be+Decided")} color="var(--warn)" /></td>
                <td className="pl-3 pr-4 text-right tabular"><Num n={r.unlisted} href={r.id ? `/lob/?id=${r.id}&tab=unlisted` : "/assets/?unlisted=1"} color="var(--violet)" /></td>
              </tr>
            );
          })}
          <OwnerUnknownEdr reg={reg} split={split} />
        </tbody>
      </table>
    </div>
  );
}

/** Assets no inventory claims: CrowdStrike shows them online / offline; without an agent (VA scan / NIAM only) they
 *  count as not installed - their EDR feasibility is unknown, so they are not part of any coverage %. */
function OwnerUnknownEdr({ reg, split }: { reg: Record<string, number>; split: boolean }) {
  const on = reg.not_inv_online || 0, off = reg.not_inv_offline || 0, none = reg.not_inv_no_edr || 0, tot = reg.not_in_inventory || 0;
  if (!tot) return null;
  const R = "/inventory/?missing=inventory";
  const offParts: Record<string, number> = { offline_console: reg.not_inv_offline_console || 0, removed_console: reg.not_inv_removed_console || 0,
    removed_import: reg.not_inv_removed_import || 0 };
  return (
    <tr className="border-t-2 border-border bg-violet-soft/40">
      <td className="whitespace-nowrap py-2.5 pl-4 pr-3"><span className="font-semibold text-violet-fg">Owner unknown</span>
        <div className="text-[11.5px] text-muted">{fmtN(tot)} assets not in any inventory</div></td>
      <td className="px-3 text-right tabular" title="EDR is installed, so they are feasible"><Num n={on + off} href={`${R}&edr_applicable=1`} /></td>
      <td className="px-3 text-right tabular"><Num n={on + off} href={`${R}&edr_applicable=1`} /></td>
      <td className="px-3"><div className="flex min-w-[200px] items-center gap-3">
        <Bar of={tot} parts={split
          ? [{ label: "Online", n: on, color: "var(--good)" }, ...OFFLINE_PARTS.map((p) => ({ label: p.label, n: offParts[p.k], color: p.color })), { label: "Not installed", n: none, color: "var(--crit)" }]
          : [{ label: "Online", n: on, color: "var(--good)" }, { label: "Offline", n: off, color: "var(--warn)" }, { label: "Not installed", n: none, color: "var(--crit)" }]} />
        <b className="w-12 text-right tabular text-muted" title="No coverage %: owner and feasibility unknown">–</b></div></td>
      <td className="px-3 text-right tabular"><Num n={on} href={`${R}&edr_status=Online`} /></td>
      {split
        ? OFFLINE_PARTS.map((p) => <td key={p.k} className="px-3 text-right tabular"><Num n={offParts[p.k]} href={`${R}&edr_status=Offline`} color={p.color} /></td>)
        : <td className="px-3 text-right tabular"><Num n={off} href={`${R}&edr_status=Offline`} color="var(--warn)" /></td>}
      <td className="px-3 text-right tabular" title="Found only by a VA scan or the NIAM dump: no agent"><Num n={none} href="/inventory/?feasibility=Unidentified" color="var(--crit)" /></td>
      <td className="px-3 text-right tabular" title="Feasibility unknown: no inventory row and no agent"><Num n={none} href="/inventory/?feasibility=Unidentified" color="var(--warn)" /></td>
      <td className="pl-3 pr-4 text-right tabular text-muted">–</td>
    </tr>
  );
}

function NiamByLob({ rows, reg }: { rows: any[]; reg: Record<string, number> }) {
  return (
    <div className="overflow-auto scroll-thin">
      <table className="w-full text-[13px]">
        <thead className="border-b border-border bg-surface-2"><tr>
          <Th>LOB</Th><Th right>Inventory nodes</Th><Th right>NIAM integrated</Th><Th right>Not integrated</Th><Th>NIAM coverage</Th>
        </tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-border last:border-0 hover:bg-surface-2">
              <td className="whitespace-nowrap py-2.5 pl-4 pr-3"><Link href={`/lob/?id=${r.id}`} className="font-semibold hover:underline">{r.name}</Link></td>
              <td className="px-3 text-right tabular">{fmtN(r.nodes)}</td>
              <td className="px-3 text-right tabular"><Num n={r.in_niam} href={`/lob/?id=${r.id}&tab=inventory&niam=1`} color="var(--good)" /></td>
              <td className="px-3 text-right tabular"><Num n={r.not_in_niam} href={`/lob/?id=${r.id}&tab=inventory&niam=0`} color="var(--crit)" /></td>
              <td className="pl-3 pr-4"><div className="flex min-w-[200px] items-center gap-3">
                <Bar of={r.nodes} parts={[{ label: "NIAM integrated", n: r.in_niam, color: "var(--good)" }, { label: "Not integrated", n: r.not_in_niam, color: "var(--crit)" }]} />
                <b className="w-12 text-right tabular">{r.niam_coverage === null ? "–" : `${r.niam_coverage}%`}</b></div></td>
            </tr>
          ))}
          {(reg.not_in_inventory || 0) > 0 && (() => {
            const tot = reg.not_in_inventory || 0, yes = reg.not_inv_niam || 0, no = reg.not_inv_not_niam || 0;
            return (
              <tr className="border-t-2 border-border bg-violet-soft/40">
                <td className="whitespace-nowrap py-2.5 pl-4 pr-3"><span className="font-semibold text-violet-fg">Owner unknown</span>
                  <div className="text-[11.5px] text-muted">not in any inventory (CrowdStrike, VA scan or NIAM)</div></td>
                <td className="px-3 text-right tabular">{fmtN(tot)}</td>
                <td className="px-3 text-right tabular"><Num n={yes} href="/inventory/?missing=inventory&has=niam" color="var(--good)" /></td>
                <td className="px-3 text-right tabular"><Num n={no} href="/inventory/?missing=inventory|niam" color="var(--crit)" /></td>
                <td className="pl-3 pr-4"><div className="flex min-w-[200px] items-center gap-3">
                  <Bar of={tot} parts={[{ label: "NIAM integrated", n: yes, color: "var(--good)" }, { label: "Not integrated", n: no, color: "var(--crit)" }]} />
                  <b className="w-12 text-right tabular">{tot ? `${Math.round((1000 * yes) / tot) / 10}%` : "–"}</b></div></td>
              </tr>
            );
          })()}
        </tbody>
      </table>
    </div>
  );
}

function VulnByLob({ rows, notInInv }: { rows: any[]; notInInv: number }) {
  const sev = [["Critical", "crit", "var(--crit)"], ["High", "high", "var(--serious)"], ["Medium", "med", "var(--warn)"], ["Low", "low", "var(--s1)"]] as const;
  return (
    <div className="grid gap-3 px-4 pb-4 md:grid-cols-2 xl:grid-cols-3">
      {rows.map((r) => (
        <div key={r.id} className="rounded-xl border border-border bg-surface-2/40 p-4">
          <div className="flex items-baseline justify-between gap-2">
            <Link className="truncate text-[14px] font-semibold hover:underline" href={`/lob/?id=${r.id}&tab=vulns`}>{r.name}</Link>
            <span className="shrink-0 text-[11.5px] text-muted">scanned {fmtRel(r.last_scan)}</span>
          </div>
          <div className="mt-3 grid grid-cols-4 gap-2">
            {sev.map(([l, k, c]) => (
              <Link key={k} href={`/vulnerabilities/?vtab=findings&lob=${r.id}&severity=${l}`} className="rounded-lg bg-surface px-2 py-1.5 text-center hover:ring-1 hover:ring-accent">
                <div className="text-[17px] font-semibold tabular" style={{ color: r[k] ? c : undefined }}>{fmtN(r[k] || 0)}</div>
                <div className="text-[10.5px] text-muted">{l}</div>
              </Link>
            ))}
          </div>
          <StackBar className="mt-3" height={6} parts={sev.map(([l, k, c]) => ({ label: l, n: r[k] || 0, color: c }))} />
          <div className="mt-3 space-y-1 text-[12.5px]">
            <div className="flex justify-between text-fg-2"><span>Vulnerable hosts</span><b className="tabular text-fg">{fmtN(r.vulnerable)} <span className="font-normal text-muted">/ {fmtN(r.scanned)} scanned</span></b></div>
            <Link href={`/lob/?id=${r.id}&tab=vulns&vtab=hosts&min_sev=3&no_edr=1`} className="flex justify-between text-fg-2 hover:text-fg">
              <span>Crit / high with no EDR</span><b className="tabular" style={{ color: r.crit_high_no_edr ? "var(--crit)" : undefined }}>{fmtN(r.crit_high_no_edr || 0)}</b>
            </Link>
            <Link href={`/lob/?id=${r.id}&tab=vulns&vtab=hosts&in_inventory=0`} className="flex justify-between text-fg-2 hover:text-fg">
              <span>Scanned hosts not in inventory</span><b className="tabular" style={{ color: r.not_in_inventory ? "var(--violet)" : undefined }}>{fmtN(r.not_in_inventory || 0)}</b>
            </Link>
          </div>
        </div>
      ))}
      {notInInv > 0 && (
        <div className="rounded-xl border border-dashed border-border bg-surface-2/20 p-4">
          <div className="text-[14px] font-semibold text-violet-fg">Scanned, not in inventory</div>
          <div className="mt-2 text-[12.5px] text-fg-2">
            <Link href="/vulnerabilities/?vtab=hosts&in_inventory=0" className="flex justify-between hover:text-fg">
              <span>Hosts with an open finding</span><b className="tabular text-violet-fg">{fmtN(notInInv)}</b>
            </Link>
          </div>
          <div className="mt-2 text-[11.5px] text-muted">A VA scan covered them, but no uploaded LOB inventory claims them: unknown owner.</div>
        </div>
      )}
    </div>
  );
}

/** Internet-exposed assets: total hosts, EDR installed (online / offline), crit+high vulns, not in inventory, and how we know. */
function ExposureSection() {
  const { data: e } = useQuery({ queryKey: ["exposure-summary"], queryFn: () => api<any>("/api/exposure/summary") });
  if (!e) return null;
  const tiles: [string, number, string, string, React.ReactNode][] = [
    ["Exposed hosts", e.exposed, "/exposure/", "var(--crit)", "reachable from the internet"],
    ["EDR installed", e.edr_installed, "/exposure/?edr_status=Online|Offline", "var(--fg)",
      <span><b className="text-good-fg">{fmtN(e.edr_online)}</b> online · <b className="text-warn-fg">{fmtN(e.edr_offline)}</b> offline</span>],
    ["Crit / high vulns", e.crit_high, "/exposure/?vulns=crit_high", "var(--serious)", `${fmtN(e.crit_high)} of ${fmtN(e.exposed)} exposed hosts`],
    ["Not in inventory", e.not_in_inventory, "/exposure/?missing=inventory", "var(--violet)", "unknown owner"],
  ];
  const know = e.know || {};
  const knowRows: [string, number, string, string][] = [
    ["CrowdStrike", know.by_crowdstrike, "crowdstrike", "the agent reports a public IP on the host"],
    ["LOB inventory", know.by_inventory, "inventory", "facing / zone column, or a public / NAT IP column"],
    ["VA scan", know.by_scan, "scan", "a scan covered a public IP (includes public-IP-only assets)"],
    ["Communication matrix", know.by_matrix, "matrix", "an inbound Internet / ISP rule reaches the host"],
  ];
  return (
    <Card className="mt-4">
      <CardHeader title="Internet exposed" hint="assets reachable from the internet (inventory, CrowdStrike, communication matrix or a VA scan of a public IP)"
        right={<Link className="text-xs text-accent-fg hover:underline" href="/exposure/">Open internet exposed</Link>} />
      <div className="grid gap-4 px-4 pb-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {tiles.map(([l, n, href, c, foot]) => (
            <Link key={l} href={href} className="rounded-xl border border-border p-3 transition-colors hover:border-accent">
              <div className="text-[12px] font-medium text-fg-2">{l}</div>
              <div className="mt-1 text-[24px] font-semibold leading-none tabular" style={{ color: n ? c : undefined }}>{fmtN(n || 0)}</div>
              <div className="mt-1 text-[11px] text-muted">{foot}</div>
            </Link>
          ))}
        </div>
        <div className="rounded-xl border border-border p-3">
          <div className="mb-2 text-[12px] font-medium text-fg-2">How we know (an asset can have several)</div>
          <div className="space-y-1 text-[12.5px]">
            {knowRows.map(([l, n, k, hint]) => (
              <Link key={k} href={`/exposure/?exposure_src=${k}`} title={hint}
                className="flex justify-between text-fg-2 hover:text-fg"><span>{l}</span><b className="tabular">{fmtN(n || 0)}</b></Link>
            ))}
          </div>
          <div className="mt-3 border-t border-border pt-3">
            <div className="mb-1.5 text-[12px] font-medium text-fg-2">Exposure via LOB inventory</div>
            <StackBar height={8} parts={[{ label: "In LOB inventory", n: e.in_inventory, color: "var(--s1)" },
              { label: "Not in any inventory", n: e.not_in_inventory, color: "var(--violet)" }]} />
            <div className="mt-2 space-y-1 text-[12.5px]">
              <Link href="/exposure/?missing=inventory" className="flex justify-between text-fg-2 hover:text-fg">
                <span className="text-violet-fg">Not in inventory</span><b className="tabular text-violet-fg">{fmtN(e.not_in_inventory)}</b>
              </Link>
              <Link href="/exposure/" className="flex justify-between text-fg-2 hover:text-fg">
                <span>In inventory</span><b className="tabular">{fmtN(e.in_inventory)}</b>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

/** Vulnerability exceptions (SOD / risk acceptance): what is accepted and what is about to expire. */
function SodSection() {
  const { data: d } = useQuery({ queryKey: ["sod-summary"], queryFn: () => api<any>("/api/sod/summary") });
  if (!d) return null;
  const up = d.last_upload;
  const tiles: [string, number, string, string, string][] = [
    ["Active exceptions", d.active, "/exceptions/?status=Active", "var(--good)", `${fmtN(d.expiring)} expire within 30 days`],
    ["Expiring soon", d.expiring, "/exceptions/?status=Expiring", "var(--warn)", "valid till inside 30 days"],
    ["Expired", d.expired, "/exceptions/?status=Expired", "var(--crit)", "findings are open again"],
    ["Accepted crit / high", d.accepted_crit + d.accepted_high, "/vulnerabilities/?vtab=findings&status=accepted", "var(--serious)",
      `${fmtN(d.accepted_crit)} critical · ${fmtN(d.accepted_high)} high`],
    ["Hosts covered", d.accepted_hosts, "/vulnerabilities/?vtab=hosts&status=accepted", "var(--violet)", `${fmtN(d.accepted)} accepted findings`],
  ];
  return (
    <Card className="mt-4">
      <CardHeader title="Exceptions (SOD)"
        hint={up ? `risk acceptance register · last upload ${fmtRel(up.uploaded_at)} · ${fmtN(d.exceptions)} exceptions` : "no exception register uploaded yet"}
        right={<Link className="text-xs text-accent-fg hover:underline" href="/exceptions/">Open exceptions (SOD)</Link>} />
      {d.exceptions ? (
        <div className="grid grid-cols-2 gap-3 px-4 pb-4 sm:grid-cols-3 xl:grid-cols-5">
          {tiles.map(([l, n, href, c, foot]) => (
            <Link key={l} href={href} className="rounded-xl border border-border p-3 transition-colors hover:border-accent">
              <div className="text-[12px] font-medium text-fg-2">{l}</div>
              <div className="mt-1 text-[24px] font-semibold leading-none tabular" style={{ color: n ? c : undefined }}>{fmtN(n || 0)}</div>
              <div className="mt-1 text-[11px] text-muted">{foot}</div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="px-4 pb-5 text-[13px] text-muted">No exception register uploaded — <Link href="/exceptions/" className="text-accent-fg hover:underline">upload the SOD sheet</Link> to accept findings with a justification and a validity date.</div>
      )}
    </Card>
  );
}

export default function Overview() {
  const { data: d, error: dErr, refetch: dRetry } = useQuery({ queryKey: ["overview"], queryFn: () => api<any>("/api/overview"), refetchInterval: 60_000 });
  if (!d) return <Loading error={dErr} retry={() => dRetry()} />;
  const k = d.kpi;
  const lobT = d.lobs.reduce((a: any, l: any) => {
    ["nodes", "applicable", "installed", "online", "offline", "offline_console", "removed_console", "removed_import",
      "offline_removed", "pending", "unlisted", "to_be_decided", "in_niam", "not_in_niam"].forEach((x) => (a[x] = (a[x] || 0) + (l[x] || 0)));
    return a;
  }, {} as Record<string, number>);
  const rd = { devices: 0, from_console: 0, import_only: 0, ...(d.removed_devices || {}) };
  const reg = d.registry || {};
  const n = d.niam || {};
  const v = d.vulns;
  const hasVulns = v?.assets?.scanned > 0;

  return (
    <div>
      <NotConnected />
      <PageHeader
        title="Overview"
        sub={d.last_sync ? `Last sync ${fmtRel(d.last_sync.finished_at)} · EDR coverage counts EDR-applicable inventory nodes (decided by OS and node type)` : "No successful sync yet"}
        actions={<Button variant="primary" onClick={() => downloadExcel("/api/reports/executive")}><FileSpreadsheet /> Executive report</Button>}
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Hero title="EDR coverage" href="/coverage/" value={lobT.applicable ? `${pct(lobT.installed, lobT.applicable)}%` : "–"}
          sub={`${fmtN(lobT.installed)} installed of ${fmtN(lobT.applicable)} EDR-applicable nodes · ${fmtN(lobT.nodes)} total hosts in inventory`}>
          <Split parts={[{ label: "Online", n: lobT.online, color: "var(--good)", href: "/inventory/?coverage_status=Online" },
            { label: "Offline", n: lobT.offline, color: "var(--warn)", href: "/inventory/?coverage_status=Offline" },
            { label: "Not installed", n: lobT.pending, color: "var(--crit)", href: "/inventory/?pending=1" }]} />
          <Drill rows={[
            { label: "Total hosts (CrowdStrike)", n: k.active + rd.devices, href: "/assets/" },
            { label: "Online", n: k.online, href: "/assets/?status=online", color: "var(--good)", parts: [
              { label: "In inventory", n: k.online - (k.online_not_inv || 0), href: "/assets/?status=online&inventory=any" },
              { label: "Not in inventory", n: k.online_not_inv || 0, href: "/assets/?status=online&unmapped=1" },
            ] },
            { label: "Offline", n: k.offline + rd.devices, href: "/assets/?status=offline", color: "var(--warn)", parts: [
              { label: "Offline in the console", n: k.offline, href: "/assets/?status=offline" },
              { label: "EDR history · removed from console (tracked by sync)", n: rd.from_console, href: "/edr-history/?view=console",
                hint: "Agents that left the console (auto-removed after the inactivity window, or deleted), one per device" },
              { label: "EDR history · old EDR sheet only", n: rd.import_only, href: "/edr-history/?view=import",
                hint: "Devices known only from the uploaded old EDR inventory, one per device" },
            ] },
            { label: "Feasibility to be decided", n: (lobT.to_be_decided || 0) + (reg.unidentified || 0), href: "/feasibility/?feasible=To+be+decided", color: "var(--violet)", parts: [
              { label: "In inventory", n: lobT.to_be_decided || 0, href: "/feasibility/?feasible=To+be+decided",
                hint: "Inventory nodes whose node type has no agent anywhere yet: mark the node type on the EDR feasibility page" },
              { label: "Not in inventory", n: reg.unidentified || 0, href: "/inventory/?feasibility=Unidentified",
                hint: "Found only by a VA scan or the NIAM dump (no inventory row, no EDR): feasibility unknown" },
            ] },
          ]} />
        </Hero>
        <Hero title="NIAM coverage" href="/inventory/?gap=niam" value={n.nodes ? (lobT.nodes ? `${pct(lobT.in_niam, lobT.nodes)}%` : "–") : "No data"}
          sub={n.nodes ? `${fmtN(lobT.in_niam)} of ${fmtN(lobT.nodes)} LOB inventory nodes are NIAM integrated` : "upload a NIAM dump to see which inventory nodes are in NIAM"}>
          {n.nodes ? <>
            <Split parts={[{ label: "NIAM integrated", n: lobT.in_niam, color: "var(--good)", href: "/inventory/?niam=1" },
              { label: "Not integrated", n: lobT.not_in_niam, color: "var(--crit)", href: "/inventory/?gap=niam" }]} />
            <Line2 items={[["Nodes in the latest NIAM dump", n.nodes, "/integrations/"], ["NIAM nodes not in inventory", n.not_in_inventory, "/integrations/?in_inventory=0"]]} />
          </> : <Link href="/upload/" className="text-[13px] text-accent-fg hover:underline">Upload NIAM dump →</Link>}
        </Hero>
        <Hero title="Vulnerabilities" href="/vulnerabilities/" value={hasVulns ? fmtN(v.severity.crit + v.severity.high) : "No data"}
          sub={hasVulns ? `open critical + high on ${fmtN(v.assets.scanned)} scanned hosts` : "no scans uploaded yet"}>
          {hasVulns ? <>
            <Split parts={[{ label: "Critical", n: v.severity.crit, color: "var(--crit)", href: "/vulnerabilities/?vtab=findings&severity=Critical" },
              { label: "High", n: v.severity.high, color: "var(--serious)", href: "/vulnerabilities/?vtab=findings&severity=High" },
              { label: "Medium", n: v.severity.med, color: "var(--warn)", href: "/vulnerabilities/?vtab=findings&severity=Medium" }]} />
            <Line2 items={[["Crit / high hosts with no active EDR", v.assets.crit_high_no_edr, "/vulnerabilities/?vtab=hosts&min_sev=3&no_edr=1"], ["Scanned, not in inventory", v.assets.not_in_inventory, "/vulnerabilities/?vtab=hosts&in_inventory=0"]]} />
          </> : <Link href="/upload/" className="text-[13px] text-accent-fg hover:underline">Upload a Nessus scan →</Link>}
        </Hero>
      </div>

      <ExposureSection />

      <SodSection />

      <Card className="mt-4">
        <CardHeader title="EDR coverage by LOB"
          hint="EDR applicable = EDR-feasible nodes (OS and node type) · Offline can be split into its three causes · To be decided = OS unknown or not in the support catalog · Not in inventory = EDR installed but not in the uploaded LOB inventory" />
        <LobCoverage rows={d.lobs} total={lobT} reg={reg} />
      </Card>

      <Card className="mt-4">
        <CardHeader title="NIAM coverage by LOB" hint={n.nodes ? "LOB inventory nodes whose IP is in the latest NIAM dump" : "no NIAM dump uploaded"}
          right={<Link className="text-xs text-accent-fg hover:underline" href="/integrations/">Open NIAM</Link>} />
        {n.nodes ? <NiamByLob rows={d.lobs} reg={reg} /> : <div className="px-4 pb-5 text-[13px] text-muted">NIAM integration: <b>No</b> — <Link href="/integrations/" className="text-accent-fg hover:underline">upload a NIAM dump</Link>.</div>}
      </Card>

      <Card className="mt-4">
        <CardHeader title="Vulnerabilities by LOB" hint={hasVulns ? `${fmtN(v.assets.scanned)} scanned hosts · last scan ${fmtRel(v.assets.last_scan)} · scanned hosts not in inventory are listed separately` : "no scans uploaded"}
          right={<Link className="text-xs text-accent-fg hover:underline" href="/vulnerabilities/">Open vulnerabilities</Link>} />
        {hasVulns ? <VulnByLob rows={v.by_lob} notInInv={v.assets.not_in_inventory} /> : <div className="px-4 pb-5 text-[13px] text-muted">No vulnerability scans yet — <Link href="/upload/" className="text-accent-fg hover:underline">upload one</Link>.</div>}
      </Card>
    </div>
  );
}
