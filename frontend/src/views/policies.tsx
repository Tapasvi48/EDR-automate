"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Callout, Card, CardHeader, Kpi, KpiGrid, Loading, PageHeader, Sheet } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";

/** CrowdStrike prevention policies: what each one switches on, and which agents run it (applied or still pending). */
export default function Policies() {
  const [state, , replaceAll] = useUrlState();
  const { data, error, refetch } = useQuery({ queryKey: ["cs-policies"], queryFn: () => api<any>("/api/crowdstrike/policies") });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const rows: any[] = data.rows;
  const agents = rows.reduce((a, r) => a + r.agents, 0);
  const pending = rows.reduce((a, r) => a + r.pending, 0);
  const off = rows.filter((r) => r.agents && (!r.enabled || r.settings_on === 0));
  return (
    <div>
      <PageHeader title="Prevention policies" sub="The prevention policies in your CrowdStrike console (fetched on each sync), what each one turns on, and how many agents run it. Click a policy for its settings; click a number to list the agents." />
      {!rows.length && <Callout tone="warn" className="mb-4">No prevention policies fetched yet. The API client needs the <b>Prevention policies: Read</b> scope; they arrive with the next sync.</Callout>}
      <KpiGrid className="mb-4 grid-cols-[repeat(auto-fill,minmax(180px,1fr))]">
        <Kpi label="Policies" value={rows.length} tone="info" foot={`${fmtN(rows.filter((r) => r.enabled).length)} enabled`} />
        <Kpi label="Agents on a policy" value={agents} tone="good" />
        <Kpi label="Policy not applied yet" value={pending} tone="warn" foot="assigned, waiting for the agent" href="/assets/?prevention_applied=0" />
        <Kpi label="Agents with no policy" value={data.no_policy} tone="crit" href="/assets/?prevention_policy=none" />
        <Kpi label="Detection-only / disabled" value={off.reduce((a, r) => a + r.agents, 0)} tone="serious" foot={`${off.length} policies with prevention off`} />
      </KpiGrid>
      <Card>
        <CardHeader title="Policies" hint={data.fetched_at ? `last changed ${fmtDt(data.fetched_at)}` : undefined} />
        <SimpleTable rows={rows} maxHeight="65vh" empty="No policies" onRowClick={(r: any) => replaceAll({ id: r.id })} columns={[
          { key: "name", label: "Policy", render: (r: any) => <span className="flex flex-col"><b>{r.name}</b>{r.description && <span className="text-[11.5px] text-muted">{r.description}</span>}</span> },
          { key: "platform", label: "Platform" },
          { key: "enabled", label: "State", render: (r: any) => r.enabled ? <Badge tone="good">enabled</Badge> : <Badge tone="crit">disabled</Badge> },
          { key: "settings", label: "Settings on", render: (r: any) => r.settings_total ? (
            <span className="flex items-center gap-2"><span className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-3">
              <span className={cn("block h-full", r.settings_on / r.settings_total >= 0.8 ? "bg-good" : r.settings_on / r.settings_total >= 0.4 ? "bg-warn" : "bg-crit")} style={{ width: `${(100 * r.settings_on) / r.settings_total}%` }} /></span>
              <span className="text-[12px]">{r.settings_on} / {r.settings_total}</span></span>) : <span className="text-muted">–</span> },
          { key: "agents", label: "Agents", num: true, render: (r: any) => <Link onClick={(e) => e.stopPropagation()} className="font-semibold text-accent-fg hover:underline" href={`/assets/?prevention_policy=${encodeURIComponent(r.id)}`}>{fmtN(r.agents)}</Link> },
          { key: "online", label: "Online", num: true },
          { key: "pending", label: "Not applied yet", num: true, render: (r: any) => r.pending ? <Link onClick={(e) => e.stopPropagation()} className="text-warn-fg hover:underline" href={`/assets/?prevention_policy=${encodeURIComponent(r.id)}&prevention_applied=0`}>{fmtN(r.pending)}</Link> : "0" },
          { key: "groups", label: "Host groups", wrap: true, render: (r: any) => <span className="text-[12px] text-fg-2">{r.groups || "–"}</span> },
        ]} />
      </Card>
      <PolicySheet id={state.id || null} onClose={() => replaceAll({})} />
    </div>
  );
}

function PolicySheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data, error } = useQuery({ queryKey: ["cs-policy", id], queryFn: () => api<any>(`/api/crowdstrike/policies/${encodeURIComponent(id!)}`), enabled: !!id });
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()} width={760} title={data?.name || "Policy"}
      sub={data ? `${data.platform} · ${data.enabled ? "enabled" : "disabled"}${data.modified_by ? ` · changed by ${data.modified_by}` : ""}${data.modified_at ? ` · ${fmtDt(data.modified_at)}` : ""}` : undefined}>
      {!data ? <Loading error={error} /> : (
        <div className="space-y-4">
          {data.groups?.length > 0 && <div className="text-[12.5px]"><span className="text-muted">Host groups: </span>{data.groups.join(", ")}</div>}
          {!data.settings.length && <Callout>No settings in the stored record (fetched before settings were kept — they arrive with the next sync).</Callout>}
          {data.settings.map((cat: any) => (
            <Card key={cat.category}>
              <CardHeader title={cat.category} hint={`${cat.settings.filter((s: any) => s.on).length} of ${cat.settings.length} on`} />
              <div className="px-4 pb-3 text-[12.5px]">
                {cat.settings.map((s: any) => (
                  <div key={s.name} className="flex items-center gap-2 border-t border-border py-1.5 first:border-0">
                    <span className={cn("size-2 rounded-full", s.on ? "bg-good" : "bg-crit")} /><span>{s.name}</span>
                    <span className={cn("ml-auto", s.on ? "text-fg-2" : "text-crit-fg")}>{s.value}</span>
                  </div>
                ))}
              </div>
            </Card>
          ))}
          <Link className="text-[12.5px] text-accent-fg hover:underline" href={`/assets/?prevention_policy=${encodeURIComponent(data.id)}`}>List the agents on this policy →</Link>
        </div>
      )}
    </Sheet>
  );
}
