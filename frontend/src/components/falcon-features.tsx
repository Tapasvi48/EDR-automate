"use client";
import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { CheckCircle2, CircleDashed, PlugZap, TriangleAlert, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button, Card, CardHeader, Loading } from "./ui";

const ICON: Record<string, [React.ElementType, string, string]> = {
  ok: [CheckCircle2, "text-good-fg", "Working"], warning: [TriangleAlert, "text-warn-fg", "Partly"], error: [XCircle, "text-crit-fg", "Failing"],
  "not run": [CircleDashed, "text-muted", "Not synced yet"],
};

/** Every CrowdStrike API feature the console uses: scope, last sync result, data now in the console, and a live check. */
export function FalconFeatures() {
  const { data, error, refetch } = useQuery({ queryKey: ["falcon-features"], queryFn: () => api<any>("/api/falcon/features") });
  const [live, setLive] = React.useState<Record<string, any> | null>(null);
  const [busy, setBusy] = React.useState(false);
  const check = async () => {
    setBusy(true);
    try {
      const r = await api<any>("/api/falcon/features/test", { method: "POST" });
      setLive(Object.fromEntries(r.checks.map((c: any) => [c.name, c])));
      toast[r.ok ? "success" : "warning"](r.ok ? "Connection checked" : "Some CrowdStrike features are not available — see the list");
      refetch();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  if (!data) return <Card className="mt-4"><Loading error={error} retry={() => refetch()} /></Card>;
  return (
    <Card className="mt-4">
      <CardHeader title={<span className="flex items-center gap-2"><PlugZap className="size-4" /> CrowdStrike API features</span>}
        hint={data.last_run ? `last sync ${fmtRel(data.last_run.started_at)} · ${data.last_run.status}` : "no sync yet"}
        right={<Button size="sm" variant="primary" loading={busy} disabled={data.demo || !data.configured} onClick={check}>Check every feature now</Button>} />
      {data.demo && <div className="px-4 pb-2 text-[12px] text-muted">Sample data mode: nothing is fetched from CrowdStrike.</div>}
      <div className="overflow-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="bg-surface-2 text-left text-[11.5px] text-fg-2">
            <th className="px-4 py-2">Feature in the console</th><th className="px-3 py-2">API scope (Read)</th><th className="px-3 py-2">Last sync</th>
            <th className="px-3 py-2">Data now</th>{live && <th className="px-3 py-2">Live check</th>}</tr></thead>
          <tbody>
            {data.features.map((f: any) => {
              const [Icon, cls, label] = ICON[f.status] || ICON["not run"];
              const l = live && f.check ? live[f.check] : null;
              return (
                <tr key={f.key} className="border-t border-border align-top">
                  <td className="px-4 py-2 font-medium">{f.feature}</td>
                  <td className="px-3 py-2 font-mono text-[11.5px] text-fg-2">{f.scope}</td>
                  <td className="px-3 py-2">
                    <span className={cn("flex items-center gap-1.5 font-medium", cls)}><Icon className="size-4" />{label}</span>
                    {f.detail && <div className="mt-0.5 max-w-[380px] text-[11.5px] text-muted">{f.detail}</div>}
                  </td>
                  <td className="px-3 py-2">{f.count == null ? <span className="text-muted">–</span>
                    : <span className={f.count ? "" : "font-semibold text-warn-fg"}>{fmtN(f.count)}{f.data_at ? <span className="font-normal text-muted"> · {fmtRel(f.data_at)}</span> : null}</span>}
                    {f.key === "analysts" && f.count === 0 && <div className="mt-0.5 max-w-[300px] text-[11.5px] text-muted">No synced alert is assigned to an analyst, so Analyst workload is empty.</div>}
                  </td>
                  {live && <td className="px-3 py-2">{!l ? <span className="text-muted">–</span> : (
                    <span className={cn("flex items-start gap-1.5", l.ok ? "text-good-fg" : "text-crit-fg")}>
                      {l.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
                      <span className="max-w-[340px] text-[11.5px]">{l.detail}</span>
                    </span>)}</td>}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="border-t border-border px-4 py-2 text-[11.5px] text-muted">
        A missing scope only switches off its feature; the sync carries on. Add the scope to the API client in Falcon (Support and resources → API clients and keys), then run "Check every feature now".
      </div>
    </Card>
  );
}
