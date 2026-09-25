"use client";
import { Download, FileSpreadsheet } from "lucide-react";
import { downloadExcel } from "@/lib/api";
import { daysAgo } from "@/lib/format";
import { Button, Card, PageHeader } from "@/components/ui";

const REPORTS: { title: string; desc: string; path: string; params?: Record<string, string> }[] = [
  { title: "All hosts (incl. removed)", desc: "Every agent ever seen, with Falcon details and inventory fields.", path: "/api/hosts/export", params: { state: "all" } },
  { title: "Offline over 7 days", desc: "Active hosts that have not checked in for more than a week.", path: "/api/hosts/export", params: { online: "offline", seen_bucket: "gt7d", sort: "last_seen", dir: "asc" } },
  { title: "Went offline this week", desc: "Hosts currently offline whose last check-in was in the last 7 days.", path: "/api/hosts/export", params: { online: "offline", last_from: daysAgo(7) } },
  { title: "Online but stale last seen", desc: "Connected per Falcon, but not checking in normally.", path: "/api/hosts/export", params: { online: "online", stale_online: "1" } },
  { title: "New installs · 30 days", desc: "Agents first seen in the last 30 days, with reinstall flags.", path: "/api/hosts/export", params: { state: "all", first_from: daysAgo(30) } },
  { title: "Reinstalls · 30 days", desc: "New agents that replaced an older agent with the same IP/hostname.", path: "/api/hosts/export", params: { state: "all", reinstall: "1", first_from: daysAgo(30) } },
  { title: "Removed from console", desc: "Auto-removed, deleted and hidden hosts retained in the database.", path: "/api/hosts/export", params: { state: "removed" } },
  { title: "Duplicate IPs", desc: "Every agent in every duplicate-IP group.", path: "/api/duplicates/export", params: { by: "ip" } },
  { title: "Duplicate hostnames", desc: "Every agent in every duplicate-hostname group.", path: "/api/duplicates/export", params: { by: "hostname" } },
  { title: "Unmapped agents", desc: "Agents in the console that no LOB inventory or agent tag claims.", path: "/api/hosts/export", params: { unmapped: "1" } },
  { title: "Not in inventory", desc: "Agents tagged to a LOB/MSP but missing from its inventory.", path: "/api/hosts/export", params: { unlisted: "1" } },
  { title: "Pending install (all LOBs)", desc: "Applicable inventory nodes that are not installed, removed or hidden.", path: "/api/lobs/0/inventory/export", params: { pending: "1" } },
  { title: "Outdated sensors", desc: "Hosts older than the three newest sensor versions per platform.", path: "/api/hosts/export", params: { outdated: "1" } },
  { title: "All LOB inventories + verification", desc: "Every inventory row across LOBs with the Falcon verification result.", path: "/api/lobs/0/inventory/export" },
  { title: "Inventory says Yes · no agent", desc: "Inventory claims EDR installed but Falcon has no agent.", path: "/api/lobs/0/inventory/export", params: { claimed_missing: "1" } },
  { title: "Activity log", desc: "All detected changes: installs, removals, IP changes, reinstalls…", path: "/api/events/export" },
];

export default function Reports() {
  return (
    <div>
      <PageHeader title="Reports" sub="One-click Excel exports. Every table in the app also has its own Excel button that exports exactly the current filters." />
      <Card className="mb-5 flex flex-wrap items-center gap-4 border-accent/40 bg-accent-soft/40 p-5">
        <div className="grid size-11 place-items-center rounded-xl bg-accent text-white"><FileSpreadsheet className="size-5" /></div>
        <div className="min-w-0 flex-1">
          <div className="text-[15px] font-semibold">Executive workbook</div>
          <div className="text-[12.5px] text-fg-2">One file with KPI summary, LOB and MSP coverage, pending & offline nodes, stale and offline agents, new installs, reinstalls, removals, duplicates, unlisted and unmapped agents, and outdated sensors.</div>
        </div>
        <Button variant="primary" onClick={() => downloadExcel("/api/reports/executive")}><Download /> Download</Button>
      </Card>
      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(300px,1fr))]">
        {REPORTS.map((r) => (
          <Card key={r.title} className="flex items-start gap-3 p-4">
            <FileSpreadsheet className="mt-0.5 size-5 shrink-0 text-good" />
            <div className="min-w-0 flex-1">
              <div className="font-semibold">{r.title}</div>
              <div className="text-xs text-muted">{r.desc}</div>
            </div>
            <Button size="sm" onClick={() => downloadExcel(r.path, r.params)}><Download /></Button>
          </Card>
        ))}
      </div>
    </div>
  );
}
