"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Radio, ScanSearch, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";
import { useMeta } from "@/lib/hooks";
import { fmtN, pct } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Card, CardHeader, Loading, PageHeader, Segmented } from "@/components/ui";
import { StackBar } from "@/components/charts";
import { CoverageTable } from "@/components/coverage-table";


export default function Coverage() {
  const router = useRouter();
  const { data: meta } = useMeta();
  const [mode, setMode] = React.useState<"lob" | "msp">("lob");
  const { data, error, refetch } = useQuery({ queryKey: ["coverage"], queryFn: () => api<any>("/api/coverage") });
  const { data: reg } = useQuery({ queryKey: ["registry-summary"], queryFn: () => api<any>("/api/registry/summary") });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const t = data.lobs.reduce((a: any, l: any) => {
    ["nodes", "applicable", "installed", "online", "offline", "pending", "in_niam", "not_in_niam", "live_nodes", "scanned_live", "never_scanned"].forEach((k) => (a[k] = (a[k] || 0) + (l[k] || 0)));
    return a;
  }, {} as Record<string, number>);
  const pick = (gap: string) => router.push(`/inventory/?gap=${gap}`);
  const gaps = [
    { k: "edr", icon: ShieldCheck, title: "EDR", gap: t.pending, of: t.applicable, have: t.installed, haveLabel: "Installed (online + offline)", missLabel: "Not installed",
      sub: "EDR-applicable nodes (Live & feasible) with no CrowdStrike agent" },
    { k: "niam", icon: Radio, title: "NIAM", gap: t.not_in_niam, of: t.nodes, have: t.in_niam, haveLabel: "In NIAM", missLabel: "Not in NIAM",
      sub: "Inventory nodes whose IP is not in the latest NIAM dump" },
    { k: "scan", icon: ScanSearch, title: "Vulnerability scan", gap: t.never_scanned, of: t.live_nodes, have: t.scanned_live, haveLabel: "Scanned", missLabel: "Never scanned",
      sub: "Live nodes whose IP has never appeared in an uploaded scan" },
  ];
  return (
    <div>
      <PageHeader title="Coverage gaps"
        sub="Every LOB inventory node checked against the three sources: a CrowdStrike agent, the NIAM dump and a vulnerability scan. Click a gap to open those nodes in All inventory." />
      <div className="grid gap-4 md:grid-cols-3">
        {gaps.map((g) => {
          const on = false;
          return (
            <Card key={g.k} className={cn("cursor-pointer p-5 transition-colors hover:border-accent", on && "border-accent ring-2 ring-accent/20")} onClick={() => pick(g.k)}>
              <div className="flex items-center gap-2 text-[13px] font-medium text-fg-2"><g.icon className="size-4" /> {g.title} gap</div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-[32px] font-semibold leading-none tracking-tight text-crit-fg">{fmtN(g.gap)}</span>
                <span className="text-[13px] text-muted">of {fmtN(g.of)} · {g.of ? `${pct(g.have, g.of)}% covered` : "–"}</span>
              </div>
              <div className="mt-1 text-[12px] text-muted">{g.sub}</div>
              <StackBar className="mt-4" parts={[{ label: g.haveLabel, n: g.have, color: "var(--good)" }, { label: g.missLabel, n: g.gap, color: "var(--crit)" }]} />
            </Card>
          );
        })}
      </div>

      <Card className="mt-4">
        <CardHeader title="Assets in no LOB inventory" hint="found by CrowdStrike, a VA scan or the NIAM dump, but in no uploaded inventory · EDR applicability is unknown for these; NIAM applies to all" />
        <div className="grid gap-3 px-4 pb-4 sm:grid-cols-2 xl:grid-cols-5">
          {[
            ["Not in any inventory", reg?.not_in_inventory, "/inventory/?missing=inventory", "var(--violet)", "total, one per IP"],
            ["Found by CrowdStrike", reg?.not_inv_edr, "/inventory/?missing=inventory&has=edr", "var(--fg)", "agent in the console or EDR history"],
            ["Found by a VA scan", reg?.not_inv_scan, "/inventory/?missing=inventory&has=scan", "var(--fg)", "scanned IP (NAT IPs of inventory nodes excluded)"],
            ["In the NIAM dump", reg?.not_inv_niam, "/inventory/?missing=inventory&has=niam", "var(--fg)", "network element not in any LOB"],
            ["Also missing from NIAM", reg?.not_inv_not_niam, "/inventory/?missing=inventory|niam", "var(--crit)", "NIAM gap outside the inventories"],
          ].map(([l, n, href, color, foot]) => (
            <Link key={l as string} href={href as string} className="rounded-xl border border-border p-3 transition-colors hover:border-accent">
              <div className="text-[12px] font-medium text-fg-2">{l}</div>
              <div className="mt-1 text-[24px] font-semibold leading-none tabular" style={{ color: color as string }}>{reg ? fmtN((n as number) || 0) : "–"}</div>
              <div className="mt-1 text-[11px] text-muted">{foot}</div>
            </Link>
          ))}
        </div>
      </Card>

      <Card className="mt-4">
        <CardHeader title={mode === "lob" ? "Coverage by LOB" : "Coverage by MSP"} hint="hover a bar for numbers · click a number to open those nodes"
          right={<Segmented value={mode} onChange={setMode} options={[["lob", "By LOB"], ["msp", "By MSP"]]} />} />
        <CoverageTable rows={mode === "lob" ? data.lobs : data.msps} mode={mode} showMspCount={false} maxHeight="420px" days={meta?.settings.auto_remove_days} />
      </Card>

    </div>
  );
}
