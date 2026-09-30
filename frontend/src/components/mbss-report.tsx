"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, ChevronDown, Download, MinusCircle, XCircle } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Input, Loading, Segmented } from "@/components/ui";

const pctTone = (p?: number | null) => (p == null ? "text-muted" : p >= 90 ? "text-good-fg" : p >= 75 ? "text-warn-fg" : "text-crit-fg");
const barTone = (p?: number | null) => (p == null ? "bg-border" : p >= 90 ? "bg-good" : p >= 75 ? "bg-warn" : "bg-crit");

export function Ring({ pct, size = 64 }: { pct: number | null; size?: number }) {
  const r = size / 2 - 5, c = 2 * Math.PI * r;
  const color = pct == null ? "var(--border)" : pct >= 90 ? "var(--good)" : pct >= 75 ? "var(--warn)" : "var(--crit)";
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} className="absolute inset-0 -rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth="6" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round" strokeDasharray={`${(c * (pct ?? 0)) / 100} ${c}`} />
      </svg>
      <span className="text-[15px] font-bold">{pct == null ? "–" : `${Math.round(pct)}%`}</span>
    </div>
  );
}

export function Bar({ pct, className }: { pct: number | null; className?: string }) {
  return (
    <span className={cn("block h-1.5 overflow-hidden rounded-full bg-surface-3", className)}>
      <span className={cn("block h-full rounded-full", barTone(pct))} style={{ width: `${pct ?? 0}%` }} />
    </span>
  );
}

const RESULT: Record<string, { icon: React.ElementType; cls: string; label: string }> = {
  pass: { icon: CheckCircle2, cls: "text-good-fg", label: "Compliant" },
  fail: { icon: XCircle, cls: "text-crit-fg", label: "Not compliant" },
  other: { icon: MinusCircle, cls: "text-muted", label: "Not applicable" },
};

/** One host's MBSS compliance report: score, compliance per control, and every rule with its result (fix on failed ones). */
export function MbssReport({ hostId }: { hostId: number }) {
  const { data, error, refetch } = useQuery({ queryKey: ["mbss-host", hostId], queryFn: () => api<any>(`/api/satellite/mbss/host/${hostId}`) });
  const [show, setShow] = React.useState<string | null>(null);
  const [ctl, setCtl] = React.useState<string | null>(null);
  const [q, setQ] = React.useState("");
  const [open, setOpen] = React.useState<string | null>(null);
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const h = data.host, n = data.counts;
  const filter = show ?? (n.fail ? "fail" : "all");
  const rules = data.rules.filter((r: any) => (filter === "all" || r.result === filter) && (!ctl || r.control === ctl)
    && (!q || `${r.title} ${r.rule_id} ${r.control}`.toLowerCase().includes(q.toLowerCase())));
  const groups: [string, any[]][] = Object.entries(rules.reduce((a: Record<string, any[]>, r: any) => ((a[r.control || "Other"] ||= []).push(r), a), {}));
  return (
    <div className="space-y-4">
      {/* summary */}
      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-border p-3">
        <Ring pct={h.compliance_pct} />
        <div className="min-w-0 flex-1">
          <div className="text-[13.5px] font-semibold">{h.compliance_policy || "MBSS policy"}</div>
          <div className="text-[12px] text-muted">{h.name} · {h.ip} · report {h.compliance_at ? fmtDt(h.compliance_at).slice(0, 10) : "–"}</div>
          <div className="mt-2 flex flex-wrap gap-1.5 text-[12px]">
            {(["fail", "pass", "other"] as const).map((k) => {
              const R = RESULT[k];
              const cnt = k === "pass" ? h.compliance_passed : k === "fail" ? h.compliance_failed : h.compliance_other;
              return (
                <button key={k} onClick={() => setShow(filter === k ? "all" : k)}
                  className={cn("inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5", filter === k ? "border-accent bg-accent-soft" : "border-border hover:border-border-strong")}>
                  <R.icon className={cn("size-3.5", R.cls)} /><b>{fmtN(cnt ?? 0)}</b> {R.label.toLowerCase()}
                </button>
              );
            })}
          </div>
        </div>
        <Button size="sm" onClick={() => downloadExcel(`/api/satellite/mbss/host/${hostId}/export`)}><Download /> Report</Button>
      </div>

      {/* compliance by control */}
      {data.controls.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center text-[12px] font-semibold text-fg-2">By control
            {ctl && <button className="ml-2 font-normal text-accent-fg hover:underline" onClick={() => setCtl(null)}>show all</button>}</div>
          <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
            {data.controls.map((c: any) => (
              <button key={c.control} onClick={() => setCtl(ctl === c.control ? null : c.control)}
                className={cn("grid grid-cols-[minmax(0,1fr)_90px_42px] items-center gap-2 rounded-md px-1.5 py-1 text-left text-[12px] hover:bg-surface-2", ctl === c.control && "bg-accent-soft")}>
                <span className="truncate">{c.control}{c.fail ? <span className="ml-1 text-crit-fg">· {c.fail} failed</span> : null}</span>
                <Bar pct={c.pct} /><span className={cn("text-right font-semibold tabular", pctTone(c.pct))}>{c.pct == null ? "–" : `${Math.round(c.pct)}%`}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* rules */}
      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Segmented value={filter} onChange={(v) => setShow(v)} options={[["fail", "Not compliant"], ["pass", "Compliant"], ["other", "N/A"], ["all", "All"]]} />
          <Input className="h-8 w-56" placeholder="Search rules…" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="ml-auto text-[11.5px] text-muted">{fmtN(rules.length)} rules</span>
        </div>
        {!groups.length ? <div className="rounded-lg border border-dashed border-border p-4 text-center text-[12.5px] text-muted">
          {filter === "fail" ? "No failed rules: this host meets every checked MBSS point." : "No rules match."}</div> : (
          <div className="divide-y divide-border rounded-xl border border-border">
            {groups.map(([g, rs]) => (
              <div key={g}>
                <div className="bg-surface-2 px-3 py-1.5 text-[11.5px] font-semibold uppercase tracking-wide text-fg-2">{g}</div>
                {rs.map((r: any) => {
                  const R = RESULT[r.result] || RESULT.other;
                  const canOpen = r.result === "fail" && r.fix;
                  const isOpen = open === r.rule_id;
                  return (
                    <div key={r.rule_id} className="border-t border-border first:border-0">
                      <button disabled={!canOpen} onClick={() => setOpen(isOpen ? null : r.rule_id)}
                        className={cn("flex w-full items-center gap-2 px-3 py-2 text-left text-[12.5px]", canOpen && "hover:bg-surface-2")}>
                        <R.icon className={cn("size-4 shrink-0", R.cls)} />
                        <span className={cn("min-w-0 flex-1 truncate", r.result === "fail" && "font-medium")}>{r.title}</span>
                        {r.result === "fail" && r.severity && <Badge tone={r.severity === "High" ? "crit" : r.severity === "Medium" ? "warn" : "neutral"}>{r.severity}</Badge>}
                        {canOpen && <ChevronDown className={cn("size-4 text-muted transition-transform", isOpen && "rotate-180")} />}
                      </button>
                      {isOpen && (
                        <div className="mx-3 mb-2 rounded-lg bg-surface-2 p-2.5">
                          <div className="mb-1 text-[11px] font-semibold text-fg-2">How to fix</div>
                          <pre className="whitespace-pre-wrap font-mono text-[11.5px] text-fg-2">{r.fix}</pre>
                          <div className="mt-1 font-mono text-[10.5px] text-muted">{r.rule_id}</div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}
        {!data.complete && <div className="mt-2 text-[11.5px] text-muted">This Satellite returns only failed rules in its report API; compliant points are counted but not listed.</div>}
      </div>
    </div>
  );
}
