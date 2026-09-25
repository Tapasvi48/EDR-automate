"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, CheckCircle2, FileSpreadsheet } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtN, fmtRel, pct } from "@/lib/format";
import { cn, qs } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Segmented } from "@/components/ui";
import { CoverageTable } from "@/components/coverage-table";
import { NotConnected } from "@/components/sync-progress";

const H = (p: Record<string, any>) => "/assets/" + qs(p);

/** one clickable row: label, proportional bar, count */
function BarRow({ label, sub, n, of, href, color, title, parts }: {
  label: React.ReactNode; sub?: React.ReactNode; n: number; of: number; href: string; color?: string; title?: string;
  parts?: { n: number; color: string }[];
}) {
  const segs = parts || [{ n, color: color || "var(--accent)" }];
  return (
    <Link href={href} title={title} className="group grid grid-cols-[minmax(0,9.5rem)_1fr_auto] items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-surface-2">
      <span className="min-w-0">
        <span className="block truncate text-[13px] text-fg-2 group-hover:text-fg">{label}</span>
        {sub && <span className="block truncate text-[11px] text-muted">{sub}</span>}
      </span>
      <span className="flex h-2 overflow-hidden rounded-full bg-surface-3">
        {segs.map((s, i) => <span key={i} className="h-full" style={{ width: `${of ? (100 * s.n) / of : 0}%`, background: s.color }} />)}
      </span>
      <b className="min-w-[3.5rem] text-right text-[13px] tabular">{fmtN(n)}</b>
    </Link>
  );
}

export default function Overview() {
  const { data: d } = useQuery({ queryKey: ["overview"], queryFn: () => api<any>("/api/overview"), refetchInterval: 60_000 });
  const [covMode, setCovMode] = React.useState<"lob" | "msp">("lob");
  if (!d) return <Loading />;
  const k = d.kpi;
  const t = d.lobs.reduce((a: any, l: any) => ({ app: a.app + l.applicable, inst: a.inst + l.installed, pend: a.pend + l.pending, unl: a.unl + l.unlisted }), { app: 0, inst: 0, pend: 0, unl: 0 });

  const offline = [
    { key: "lt24h", label: "Went offline today", n: k.offline_lt24h, color: "var(--warn)" },
    { key: "1-7d", label: "1 – 7 days", n: k.offline_1_7d, color: "var(--serious)" },
    { key: "7-30d", label: "7 – 30 days", n: k.offline_7_30d, color: "var(--crit)" },
    { key: "gt30d", label: "More than 30 days", n: k.offline_gt30d, color: "var(--crit)", sub: `auto-removed at ${d.auto_remove_days} days` },
  ];
  const notInst = [...d.msps].filter((m: any) => m.not_installed > 0).sort((a: any, b: any) => b.not_installed - a.not_installed).slice(0, 5);
  const sensorTotal = d.sensors.reduce((a: number, s: any) => a + s.n, 0);

  const attention = [
    { n: k.routing_conflict_hosts, tone: "crit", label: "Agents in a routing conflict (same connection + local IP, several online)", href: "/routing/" },
    { n: k.dup_ip_hosts, tone: "serious", label: "Duplicate agents to clean up (same connection + local IP)", href: "/duplicates/" },
    { n: k.unmapped, tone: "violet", label: "Devices not claimed by any LOB", href: H({ unmapped: 1 }) },
    { n: k.outdated_sensor, tone: "warn", label: "Devices on a sensor older than N-2", href: H({ sensor_level: "older" }) },
    { n: k.rfm, tone: "warn", label: "Sensors in reduced functionality mode", href: H({ rfm: 1 }) },
    { n: k.stale_online, tone: "warn", label: "Online, but last seen is stale", href: "/health/?tab=stale" },
  ].filter((a) => a.n > 0);

  return (
    <div>
      <NotConnected />
      <PageHeader
        title="Overview"
        sub={d.last_sync ? `Last sync ${fmtRel(d.last_sync.finished_at)} · coverage counts only Live & EDR-feasible inventory nodes` : "No successful sync yet"}
        actions={<Button variant="primary" onClick={() => downloadExcel("/api/reports/executive")}><FileSpreadsheet /> Executive report</Button>}
      />

      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(165px,1fr))]">
        <Kpi label="Devices in console" value={k.active} tone="info" href="/assets/" foot={k.agents > k.active ? `${fmtN(k.agents - k.active)} duplicate agents merged` : "one per device"} />
        <Kpi label="Online" value={k.online} foot={`${pct(k.online, k.active)}% of devices`} tone="good" href={H({ status: "online" })} />
        <Kpi label="Offline" value={k.offline} foot={`${pct(k.offline, k.active)}% of devices`} tone="warn" href="/health/?tab=offline" />
        <Kpi label="EDR coverage" value={t.app ? `${pct(t.inst, t.app)}%` : "–"} foot={`${fmtN(t.inst)} of ${fmtN(t.app)} applicable`} tone="info" href="/coverage/" />
        <Kpi label="Not installed" value={t.pend} foot="applicable, no agent" tone="crit" href="/coverage/?pending=1" />
        <Kpi label="Not in inventory" value={t.unl} foot="on EDR, missing from LOB inventory" tone="violet" href={H({ unlisted: 1 })} />
        <Kpi label="Auto-removed" value={k.auto_removed} foot={`offline > ${d.auto_remove_days} days, removed by Falcon`} tone="serious" href="/health/?tab=removed&view=auto" />
      </KpiGrid>

      <Card className="mt-4">
        <CardHeader title="LOB inventory coverage" hint="click any number to open the matching nodes"
          right={<Segmented value={covMode} onChange={setCovMode} options={[["lob", "By LOB"], ["msp", "By MSP"]]} />} />
        <CoverageTable compact rows={covMode === "lob" ? d.lobs : d.msps} mode={covMode} maxHeight="420px" />
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        <Card>
          <CardHeader title="Offline & not installed" />
          <div className="px-2 pb-3">
            <div className="flex items-baseline justify-between px-2 pb-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted">Offline devices</span>
              <Link href="/health/?tab=offline" className="text-[13px] font-semibold tabular text-warn-fg hover:underline">{fmtN(k.offline)}</Link>
            </div>
            {offline.map((o) => (
              <BarRow key={o.key} label={o.label} sub={o.sub} n={o.n} of={k.offline} color={o.color} href={`/health/?tab=offline&seen_bucket=${o.key}`} />
            ))}
            <div className="mx-2 my-2 border-t border-border" />
            <div className="flex items-baseline justify-between px-2 pb-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted">Not installed · top MSPs</span>
              <Link href="/coverage/?pending=1" className="text-[13px] font-semibold tabular text-crit-fg hover:underline">{fmtN(t.pend)}</Link>
            </div>
            {notInst.length ? notInst.map((m: any) => (
              <BarRow key={`${m.lob_id}-${m.msp_id}`} label={m.msp} sub={m.lob} n={m.not_installed} of={notInst[0].not_installed} color="var(--crit)"
                href={`/lob/?id=${m.lob_id}&tab=inventory&coverage_status=Not+Installed&msp=${m.msp_id ?? "none"}`} />
            )) : <div className="px-2 py-2 text-[13px] text-muted">Every applicable inventory node has an agent.</div>}
          </div>
        </Card>

        <Card>
          <CardHeader title="Sensor version" hint="by release (7.40 = every 7.40.x build) · per platform · N = newest release in the console" />
          <div className="px-2 pb-3">
            {d.sensors.map((s: any) => (
              <BarRow key={s.level} href={H({ sensor_level: s.level })}
                label={<span className="flex items-center gap-1.5">{s.level === "older" ? "Older than N-2" : s.level}{s.level === "older" && s.n > 0 && <Badge tone="serious">outdated</Badge>}</span>}
                sub={s.versions.length ? s.versions.slice(0, 3).join(", ") + (s.versions.length > 3 ? ` +${s.versions.length - 3}` : "") : "none"}
                title={s.versions.join(", ")}
                n={s.n} of={sensorTotal}
                parts={[{ n: s.online, color: s.level === "older" ? "var(--serious)" : "var(--good)" }, { n: s.n - s.online, color: "var(--border-strong)" }]} />
            ))}
            <div className="px-2 pt-2 text-[11.5px] text-muted">
              <span className="mr-3 inline-flex items-center gap-1"><span className="size-2 rounded-full bg-good" /> online</span>
              <span className="inline-flex items-center gap-1"><span className="size-2 rounded-full bg-border-strong" /> offline</span>
              <span className={cn("ml-3", sensorTotal ? "" : "hidden")}>{pct(sensorTotal - (d.sensors.find((s: any) => s.level === "older")?.n || 0), sensorTotal)}% within N-2</span>
            </div>
          </div>
        </Card>

        <Card className="lg:col-span-2 2xl:col-span-1">
          <CardHeader title={<span className="flex items-center gap-2"><AlertTriangle className="size-4 text-serious" />Attention needed</span>} />
          <div className="px-2 pb-2">
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
