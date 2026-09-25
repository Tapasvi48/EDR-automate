"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, CheckCircle2, FileSpreadsheet } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { daysAgo, fmtN, fmtRel, pct } from "@/lib/format";
import { qs } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Segmented } from "@/components/ui";
import { COLORS, HBars, Legend } from "@/components/charts";
import { CoverageTable } from "@/components/coverage-table";
import { NotConnected } from "@/components/sync-progress";

const H = (p: Record<string, any>) => "/assets/" + qs(p);

export default function Overview() {
  const { data: d } = useQuery({ queryKey: ["overview"], queryFn: () => api<any>("/api/overview"), refetchInterval: 60_000 });
  const [covMode, setCovMode] = React.useState<"lob" | "msp">("lob");
  const [gapMode, setGapMode] = React.useState<"lob" | "msp">("msp");
  if (!d) return <Loading />;
  const k = d.kpi;
  const t = d.lobs.reduce((a: any, l: any) => ({ app: a.app + l.applicable, inst: a.inst + l.installed, pend: a.pend + l.pending, unl: a.unl + l.unlisted }), { app: 0, inst: 0, pend: 0, unl: 0 });

  const gapRows = (gapMode === "lob" ? d.lobs : d.msps)
    .map((r: any) => ({
      label: gapMode === "lob" ? r.name : `${r.msp} · ${r.lob}`,
      href: gapMode === "lob" ? `/lob/?id=${r.id}` : `/lob/?id=${r.lob_id}&tab=inventory&msp=${r.msp_id ?? "none"}`,
      offline: r.offline, notInst: r.not_installed, gone: r.hidden + r.removed,
    }))
    .filter((r: any) => r.offline + r.notInst + r.gone > 0)
    .sort((a: any, b: any) => b.offline + b.notInst + b.gone - (a.offline + a.notInst + a.gone));

  const attention = [
    { n: t.pend, tone: "crit", label: "Applicable inventory nodes without an EDR agent", href: "/coverage/?pending=1" },
    { n: k.offline_gt30d, tone: "crit", label: `Agents offline > 30 days (auto-removed at ${d.auto_remove_days} days)`, href: H({ status: "offline", last_to: daysAgo(31) }) },
    { n: t.unl, tone: "violet", label: "Agents reporting to EDR for a LOB/MSP but not in its inventory", href: H({ unlisted: 1 }) },
    { n: k.unmapped, tone: "violet", label: "Devices not claimed by any LOB", href: H({ unmapped: 1 }) },
    { n: k.outdated_sensor, tone: "warn", label: "Agents on an outdated sensor (older than N-2)", href: H({ outdated: 1 }) },
    { n: k.rfm, tone: "warn", label: "Sensors in reduced functionality mode", href: H({ rfm: 1 }) },
  ].filter((a) => a.n > 0);

  return (
    <div>
      <NotConnected />
      <PageHeader
        title="Overview"
        sub={d.last_sync ? `Last sync ${fmtRel(d.last_sync.finished_at)} · coverage counts only Live & EDR-feasible inventory nodes` : "No successful sync yet"}
        actions={<Button variant="primary" onClick={() => downloadExcel("/api/reports/executive")}><FileSpreadsheet /> Executive report</Button>}
      />

      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Devices in console" value={k.active} tone="info" href="/assets/" foot={k.agents > k.active ? `${fmtN(k.agents - k.active)} duplicate agents merged` : "one per device"} />
        <Kpi label="Online" value={k.online} foot={`${pct(k.online, k.active)}% of devices`} tone="good" href={H({ status: "online" })} />
        <Kpi label="Offline" value={k.offline} foot={`${pct(k.offline, k.active)}% of devices`} tone="crit" href={H({ status: "offline" })} />
        <Kpi label="Hidden" value={k.hidden} foot="hidden in the console" tone="violet" href="/health/?tab=removed&view=hidden" />
        <Kpi label="EDR coverage" value={t.app ? `${pct(t.inst, t.app)}%` : "–"} foot={`${fmtN(t.inst)} of ${fmtN(t.app)} applicable`} tone="info" href="/coverage/" />
        <Kpi label="Not installed" value={t.pend} foot="applicable, no agent" tone="crit" href="/coverage/?pending=1" />
        <Kpi label="Not in inventory" value={t.unl} foot="on EDR, missing from LOB inventory" tone="violet" href={H({ unlisted: 1 })} />
        <Kpi label="New · 7 days" value={k.new_7d} foot={`${fmtN(k.reinstall_7d)} reinstalls`} href={`/installs/?first_from=${daysAgo(6)}`} />
      </KpiGrid>

      <Card className="mt-4">
        <CardHeader title="LOB inventory coverage" hint="click any number to open the matching nodes"
          right={<Segmented value={covMode} onChange={setCovMode} options={[["lob", "By LOB"], ["msp", "By MSP"]]} />} />
        <CoverageTable compact rows={covMode === "lob" ? d.lobs : d.msps} mode={covMode} maxHeight="420px" />
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        <Card>
          <CardHeader title="Offline & not installed" right={<Segmented value={gapMode} onChange={setGapMode} options={[["msp", "MSP"], ["lob", "LOB"]]} />} />
          <div className="px-4 pb-4">
            <Legend series={[{ key: "o", label: "Offline", color: COLORS.warn }, { key: "n", label: "Not installed", color: COLORS.crit }, { key: "g", label: "Removed / hidden", color: COLORS.s7 }]} />
            <div className="max-h-[340px] overflow-y-auto pr-1 scroll-thin">
              <HBars items={gapRows.map((r: any) => ({
                label: r.label, n: r.offline + r.notInst + r.gone, href: r.href,
                title: `${r.label}: ${r.offline} offline · ${r.notInst} not installed · ${r.gone} removed/hidden`,
                parts: [{ n: r.offline, color: COLORS.warn }, { n: r.notInst, color: COLORS.crit }, { n: r.gone, color: COLORS.s7 }],
              }))} />
            </div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Sensor version" hint="green = online" right={<Link className="text-xs text-accent-fg hover:underline" href={H({ outdated: 1 })}>{fmtN(k.outdated_sensor)} outdated</Link>} />
          <div className="max-h-[372px] overflow-y-auto px-4 pb-4 scroll-thin">
            <HBars items={d.sensors.map((r: any) => ({
              label: r.label + (r.outdated ? " · outdated" : ""), n: r.n, href: H({ agent_version: r.label }),
              title: `${r.label}: ${r.n} agents, ${r.online} online${r.outdated ? " — outdated" : ""}`,
              parts: [{ n: r.online, color: r.outdated ? COLORS.serious : COLORS.good }, { n: r.n - r.online, color: COLORS.muted }],
            }))} />
          </div>
        </Card>
        <Card>
          <CardHeader title="Operating system" hint="green = online" />
          <div className="px-4 pb-4">
            <HBars items={d.os.map((r: any) => ({ label: r.label, n: r.n, href: H({ os: r.label }), parts: [{ n: r.online, color: COLORS.good }, { n: r.n - r.online, color: COLORS.muted }], title: `${r.label}: ${r.n} (${r.online} online)` }))} />
          </div>
        </Card>
        <Card>
          <CardHeader title="Node type coverage" hint="applicable inventory nodes" />
          <div className="px-4 pb-4">
            <Legend series={[{ key: "i", label: "Installed", color: COLORS.good }, { key: "p", label: "Not installed", color: COLORS.crit }]} />
            <HBars items={d.node_types.filter((r: any) => r.applicable > 0).map((r: any) => ({
              label: r.label, n: r.applicable, href: `/coverage/?node_type=${encodeURIComponent(r.label)}&applicable=1`,
              title: `${r.label}: ${r.installed}/${r.applicable} installed (${r.offline} offline), ${r.pending} not installed`,
              parts: [{ n: r.installed, color: COLORS.good }, { n: r.pending, color: COLORS.crit }],
            }))} />
          </div>
        </Card>
        <Card className="2xl:col-span-2">
          <CardHeader title={<span className="flex items-center gap-2"><AlertTriangle className="size-4 text-serious" />Attention needed</span>} />
          <div className="grid gap-x-4 px-2 pb-2 md:grid-cols-2">
            {attention.length === 0 && <div className="flex items-center gap-2 px-3 py-6 text-good-fg"><CheckCircle2 className="size-5" /> Nothing needs attention.</div>}
            {attention.map((a) => (
              <Link key={a.label} href={a.href} className="group flex items-center gap-3 rounded-lg px-2.5 py-2 hover:bg-surface-2">
                <Badge tone={a.tone as any} className="min-w-[46px] justify-center tabular">{fmtN(a.n)}</Badge>
                <span className="flex-1 text-[13px] text-fg-2 group-hover:text-fg">{a.label}</span>
                <ArrowRight className="size-4 text-muted opacity-0 group-hover:opacity-100" />
              </Link>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
