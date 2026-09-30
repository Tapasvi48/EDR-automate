"use client";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Download, Route } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { useMeta, useUrlState } from "@/lib/hooks";
import { daysAgo } from "@/lib/format";
import { Badge, Button, Card, Checkbox, Loading, PageHeader, Select } from "@/components/ui";
import { DateRange } from "@/components/date-range";
import { EdrBadge, SevCounts } from "@/components/badges";

/** Date filter start: defaults to the last 30 days; "all" in the URL = any time. */
export function useFrom(v?: string) {
  return v === "all" ? undefined : v ?? daysAgo(29);
}

export function tone(score: number) {
  return score >= 80 ? "bg-crit text-white" : score >= 60 ? "bg-serious text-white" : score >= 40 ? "bg-warn text-white" : "bg-surface-3 text-fg-2";
}

/** The assets to fix first: one explained score across exposure, EDR, vulnerabilities, detections, NDR, MBSS and reach. */
export default function TopRisks() {
  const [state, set] = useUrlState();
  const { data: meta } = useMeta();
  const from = useFrom(state.from);
  const params = { from: from || "2000-01-01", to: state.to, lob: state.lob, limit: state.limit || "10", exposed: state.exposed };
  const { data, error, refetch, isFetching } = useQuery({ queryKey: ["top-risks", params], queryFn: () => api<any>("/api/top-risks", { params }) });
  return (
    <div>
      <PageHeader title="Top riskiest assets"
        sub="One score per asset, every point explained: internet exposure and shadow ports, EDR gap, critical / exploitable vulnerabilities, CrowdStrike detections and Seceon NDR alerts in the date range, failed MBSS rules and uninstalled errata, and how many weak internal assets it can reach through the communication matrix."
        actions={<Button onClick={() => downloadExcel("/api/top-risks/export", params)}><Download /> Excel</Button>} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <DateRange label="Detections" from={from} to={state.to} onChange={(f, t) => set({ from: f ?? "all", to: t })} />
        <Select value={state.lob} onChange={(v) => set({ lob: v })} placeholder="All LOBs" options={(meta?.lobs || []).map((l: any) => ({ value: l.id, label: l.name }))} />
        <Select value={state.limit || "10"} onChange={(v) => set({ limit: v })} options={[["10", "Top 10"], ["25", "Top 25"], ["50", "Top 50"], ["100", "Top 100"]] as [string, string][]} />
        <Checkbox checked={state.exposed === "1"} onChange={(v) => set({ exposed: v ? "1" : undefined })} label="Internet / indirectly exposed only" />
        {isFetching && <span className="text-xs text-muted">Updating…</span>}
      </div>
      {!data ? <Loading error={error} retry={() => refetch()} /> : (
        <div className="flex flex-col gap-3">
          {data.rows.map((r: any) => (
            <Card key={r.ip || r.name} className="flex flex-wrap items-start gap-4 p-4">
              <div className="flex w-14 flex-col items-center">
                <div className="text-[11px] text-muted">#{r.rank}</div>
                <div className={`grid size-12 place-items-center rounded-xl text-lg font-bold ${tone(r.score)}`} title="Risk points">{r.score}</div>
              </div>
              <div className="min-w-[240px] flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Link className="text-[15px] font-semibold hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip || r.name)}`}>{r.name || r.ip}</Link>
                  <span className="font-mono text-[12px] text-fg-2">{r.ip}</span>
                  {r.public_ips && <span className="font-mono text-[12px] text-muted">→ {r.public_ips}</span>}
                  {r.exposed ? <Badge tone="crit">Internet exposed</Badge> : r.indirect ? <Badge tone="warn">Indirectly exposed</Badge> : null}
                  <EdrBadge s={r.edr_status} />
                </div>
                <div className="mt-0.5 text-[12px] text-muted">{[r.lobs || "Not in inventory", r.msps, r.node_type, r.os].filter(Boolean).join(" · ")}</div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {r.factors.filter((f: any) => f[1]).map(([n, p]: any) => (
                    <span key={n} className="whitespace-nowrap rounded bg-surface-3 px-1.5 py-0.5 text-[11.5px] text-fg-2">{n} <b>+{p}</b></span>
                  ))}
                </div>
              </div>
              <div className="flex min-w-[230px] flex-col gap-1.5 text-[12.5px]">
                <div className="flex items-center gap-2"><span className="w-24 text-muted">Vulns</span><SevCounts c={r.crit} h={r.high} /></div>
                <div className="flex items-center gap-2"><span className="w-24 text-muted">Detections</span>
                  <b className={r.detections_high ? "text-crit-fg" : ""}>{r.detections}</b> CrowdStrike · <b>{r.ndr}</b> NDR</div>
                <div className="flex items-center gap-2"><span className="w-24 text-muted">MBSS / ports</span>{r.mbss_failed} failed · {r.shadow} shadow</div>
                {r.weak_reach > 0 && <Link className="flex items-center gap-1 text-accent-fg hover:underline" href={`/attack-paths/?ip=${encodeURIComponent(r.ip)}`}>
                  <Route className="size-3.5" /> Reaches {r.weak_reach} weak assets: attack path</Link>}
              </div>
              <div className="basis-full rounded-lg bg-accent-soft px-3 py-1.5 text-[12.5px] text-accent-fg"><b>Next action:</b> {r.action}</div>
            </Card>
          ))}
          {!data.rows.length && <Card className="p-6 text-center text-muted">No assets with risk in this selection.</Card>}
        </div>
      )}
    </div>
  );
}
