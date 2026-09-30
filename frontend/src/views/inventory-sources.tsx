"use client";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { Database, FileSpreadsheet, FileText, Upload } from "lucide-react";
import { api } from "@/lib/api";
import { fmtDt } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, Loading, PageHeader } from "@/components/ui";

const ICON: Record<string, any> = { manual: Upload, servicenow: Database, jaspersoft: FileText };
const STATUS: Record<string, [any, string]> = { connected: ["good", "Connected"], empty: ["warn", "No uploads yet"], planned: ["neutral", "Planned"] };

/** Where inventory comes from: manual uploads today; ServiceNow CMDB and Jaspersoft reports are the next connectors. */
export default function InventorySources() {
  const { data, error, refetch } = useQuery({ queryKey: ["inventory-sources"], queryFn: () => api<any>("/api/inventory-sources") });
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  return (
    <div>
      <PageHeader title="Inventory sources"
        sub="Every inventory record says where it came from. Manual uploads work today; ServiceNow CMDB and Jaspersoft reports will feed the same LOB inventories, so coverage, feasibility and Asset 360 work the same whatever the source." />
      <div className="grid gap-4 lg:grid-cols-3">
        {data.sources.map((s: any) => {
          const Icon = ICON[s.key] || FileSpreadsheet;
          const [tone, label] = STATUS[s.status] || STATUS.planned;
          return (
            <Card key={s.key} className={cn("flex flex-col p-5", s.status === "planned" && "border-dashed")}>
              <div className="flex items-center gap-2">
                <span className="grid size-9 place-items-center rounded-lg bg-surface-2"><Icon className="size-4.5" /></span>
                <div className="text-[15px] font-semibold">{s.name}</div>
                <Badge tone={tone} className="ml-auto">{label}</Badge>
              </div>
              <p className="mt-3 text-[13px] text-fg-2">{s.how}</p>
              {s.detail && <p className="mt-2 text-[13px] font-medium">{s.detail}</p>}
              {s.last && <p className="mt-1 text-[12px] text-muted">last upload {fmtDt(s.last)}</p>}
              {s.key === "servicenow" && (
                <div className="mt-3 rounded-lg bg-surface-2 p-3 text-[12px] text-fg-2">
                  Planned: instance URL, a read-only integration user and the CI class (default <code>{s.table}</code>), then a scheduled pull mapped to
                  the standard inventory columns. Records would show <b>ServiceNow CMDB</b> as their source on Asset 360.
                </div>
              )}
              {s.key === "jaspersoft" && (
                <div className="mt-3 rounded-lg bg-surface-2 p-3 text-[12px] text-fg-2">Planned: pull a scheduled report export (CSV) from JasperReports Server and load it like a manual upload.</div>
              )}
              <div className="mt-auto pt-4">
                {s.key === "manual" ? <Link href="/upload/"><Button size="sm" variant="primary"><Upload /> Upload inventory</Button></Link>
                  : <Button size="sm" disabled>Connect (coming soon)</Button>}
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
