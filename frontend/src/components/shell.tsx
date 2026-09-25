"use client";
import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Command } from "cmdk";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Activity, AlertTriangle, Building2, Copy, FileSpreadsheet, FileText, Globe, LayoutDashboard, ListChecks, Menu, Monitor,
  Moon, PackagePlus, PlugZap, RefreshCw, Search, Settings, ShieldCheck, Sun, Target, WifiOff,
} from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button } from "./ui";
import { HostStatus } from "./badges";
import { useHostDrawer } from "./host-drawer";
import { nextSyncLabel, useSyncStatus } from "./sync-progress";

const NAV: { section?: string; items: { href: string; label: string; icon: React.ElementType }[] }[] = [
  { items: [
    { href: "/", label: "Overview", icon: LayoutDashboard },
    { href: "/assets/", label: "All assets", icon: Monitor },
    { href: "/ip-search/", label: "IP & NIC search", icon: Globe },
    { href: "/lookup/", label: "Bulk lookup", icon: ListChecks },
  ] },
  { section: "Hygiene", items: [
    { href: "/health/", label: "Offline & stale", icon: WifiOff },
    { href: "/duplicates/", label: "Duplicates", icon: Copy },
    { href: "/installs/", label: "New installs", icon: PackagePlus },
    { href: "/activity/", label: "Activity log", icon: Activity },
  ] },
  { section: "Inventory", items: [
    { href: "/lobs/", label: "LOB inventory", icon: Building2 },
    { href: "/coverage/", label: "Coverage gaps", icon: Target },
    { href: "/templates/", label: "Templates", icon: FileText },
  ] },
  { section: "System", items: [
    { href: "/reports/", label: "Reports", icon: FileSpreadsheet },
    { href: "/settings/", label: "Sync & settings", icon: Settings },
  ] },
];

function useSync() {
  const qc = useQueryClient();
  const wasRunning = React.useRef(false);
  const q = useSyncStatus();
  React.useEffect(() => {
    const running = !!q.data?.running;
    if (wasRunning.current && !running) {
      const last = q.data?.runs?.[0];
      if (last?.status === "ok") toast.success(`Sync complete · ${last.message || ""}`);
      else if (last) toast.error(`Sync failed: ${last.message}`);
      qc.invalidateQueries({ predicate: (x) => x.queryKey[0] !== "sync-status" });
    }
    wasRunning.current = running;
  }, [q.data, qc]);
  const start = async () => {
    const r = await api<any>("/api/sync", { method: "POST" });
    r.ok ? toast.message("Sync started") : toast.warning(r.message);
    q.refetch();
  };
  return { status: q.data, start };
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [mobileNav, setMobileNav] = React.useState(false);
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const { status, start } = useSync();
  const meta = useQuery({ queryKey: ["meta"], queryFn: () => api<any>("/api/meta"), staleTime: 60_000 });
  if (meta.data) (globalThis as any).__staleHours = parseFloat(meta.data.settings.stale_online_hours || "1");
  const lastOk = status?.runs?.find((r: any) => r.status === "ok");

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  React.useEffect(() => setMobileNav(false), [pathname]);

  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href.replace(/\/$/, "")));

  return (
    <div className="flex min-h-screen">
      <aside className={cn(
        "fixed inset-y-0 left-0 z-40 flex w-[232px] flex-col bg-side text-[#a9b2c3] transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
        mobileNav ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex items-center gap-2.5 px-4 pb-3 pt-4">
          <div className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-[#e5483f] to-[#a3221b] shadow-lg">
            <ShieldCheck className="size-4.5 text-white" />
          </div>
          <div className="leading-tight">
            <div className="text-[14.5px] font-semibold text-white">EDR Asset Console</div>
            <div className="text-[11px]">CrowdStrike Falcon</div>
          </div>
        </div>
        <button onClick={() => setPaletteOpen(true)} className="mx-3 mb-1 flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-left text-xs text-[#8a93a6] hover:bg-white/10">
          <Search className="size-3.5" /> Search hosts, IPs…
          <kbd className="ml-auto rounded bg-white/10 px-1.5 text-[10px]">⌘K</kbd>
        </button>
        <nav className="flex-1 overflow-y-auto px-2.5 pb-4 scroll-thin">
          {NAV.map((g, i) => (
            <div key={i}>
              {g.section && <div className="px-2.5 pb-1.5 pt-4 text-[10.5px] font-semibold uppercase tracking-[.08em] text-[#5f6879]">{g.section}</div>}
              {g.items.map((it) => (
                <Link key={it.href} href={it.href}
                  className={cn("mt-0.5 flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] font-medium transition-colors",
                    isActive(it.href) ? "bg-white/10 text-white" : "hover:bg-white/5 hover:text-white")}>
                  <it.icon className="size-[17px] opacity-90" />
                  {it.label}
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t border-white/10 p-3 text-[11.5px]">
          {status && !status.configured ? (
            <Link href="/settings/" className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-[var(--accent)] py-1.5 font-medium text-white hover:brightness-110">
              <PlugZap className="size-3.5" /> Connect CrowdStrike
            </Link>
          ) : (
            <>
              <div className="mb-2 flex items-center gap-2">
                <span className={cn("size-2 shrink-0 rounded-full", status?.running ? "animate-pulse bg-[var(--accent)]" : status?.runs?.[0]?.status === "error" ? "bg-[var(--crit)]" : lastOk ? "bg-[var(--good)]" : "bg-[var(--warn)]")} />
                <span className="truncate">
                  {status?.running ? status.stage : status?.runs?.[0]?.status === "error" ? "Last sync failed" : lastOk ? `Synced ${fmtRel(lastOk.finished_at)}` : "Never synced"}
                </span>
              </div>
              {!status?.running && <div className="mb-2 truncate text-[10.5px] text-[#6b7384]">{nextSyncLabel(status)}</div>}
              <button onClick={start} disabled={status?.running}
                className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-white/10 py-1.5 font-medium text-white hover:bg-white/15 disabled:opacity-60">
                <RefreshCw className={cn("size-3.5", status?.running && "animate-spin")} /> {status?.running ? "Syncing…" : "Sync now"}
              </button>
            </>
          )}
        </div>
      </aside>
      {mobileNav && <div className="fixed inset-0 z-30 bg-black/40 lg:hidden" onClick={() => setMobileNav(false)} />}

      <main className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-13 items-center gap-3 border-b border-border bg-surface/85 px-4 backdrop-blur lg:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNav(true)}><Menu /></Button>
          <button onClick={() => setPaletteOpen(true)} className="flex h-8.5 w-full max-w-md items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 text-left text-[13px] text-muted hover:border-border-strong">
            <Search className="size-4 shrink-0" /> <span className="truncate">Jump to host, IP, AID or page…</span>
            <kbd className="ml-auto hidden rounded border border-border bg-surface px-1.5 text-[10.5px] sm:block">⌘K</kbd>
          </button>
          <div className="flex-1" />
          {status?.running && <Link href="/settings/"><Badge tone="info"><RefreshCw className="size-3 animate-spin" /> {status.stage}</Badge></Link>}
          {status && !status.configured && <Link href="/settings/"><Badge tone="warn">Not connected</Badge></Link>}
          <ThemeToggle />
        </header>
        <div className="mx-auto w-full max-w-[1720px] px-4 pb-16 pt-5 lg:px-6">{children}</div>
      </main>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}

function ThemeToggle() {
  const [dark, setDark] = React.useState(false);
  React.useEffect(() => setDark(document.documentElement.classList.contains("dark")), []);
  const toggle = () => {
    const d = !dark;
    setDark(d);
    document.documentElement.classList.toggle("dark", d);
    try { localStorage.setItem("theme", d ? "dark" : "light"); } catch {}
  };
  return <Button variant="ghost" size="icon" onClick={toggle} title="Toggle theme">{dark ? <Sun /> : <Moon />}</Button>;
}

function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const router = useRouter();
  const { open: openHost } = useHostDrawer();
  const [q, setQ] = React.useState("");
  const [dq, setDq] = React.useState("");
  React.useEffect(() => { const t = setTimeout(() => setDq(q.trim()), 180); return () => clearTimeout(t); }, [q]);
  React.useEffect(() => { if (!open) setQ(""); }, [open]);
  const hosts = useQuery({
    queryKey: ["palette", dq],
    queryFn: () => api<any>("/api/hosts", { params: { q: dq, state: "all", size: 8, sort: "last_seen" } }),
    enabled: open && dq.length >= 2,
  });
  const go = (href: string) => { onOpenChange(false); router.push(href); };
  const looksIp = /^[\d.\/]+$/.test(dq);
  const pages = NAV.flatMap((g) => g.items);
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 anim-fade" />
        <Dialog.Content aria-describedby={undefined} className="fixed left-1/2 top-[12vh] z-50 w-[min(640px,94vw)] -translate-x-1/2 overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl anim-fade">
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <Command shouldFilter={false} className="flex flex-col">
            <div className="flex items-center gap-2 border-b border-border px-4">
              <Search className="size-4 text-muted" />
              <Command.Input value={q} onValueChange={setQ} autoFocus placeholder="Hostname, IP, AID, serial, or a page name…" className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-muted" />
            </div>
            <Command.List className="max-h-[420px] overflow-y-auto p-2 scroll-thin">
              {dq.length >= 2 && (
                <Command.Group heading="Actions" className="text-[11px] text-muted [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
                  {looksIp && <PaletteItem onSelect={() => go(`/ip-search/?q=${encodeURIComponent(dq)}`)} icon={<Globe />}>Search IP / NIC history for <b>{dq}</b></PaletteItem>}
                  <PaletteItem onSelect={() => go(`/assets/?q=${encodeURIComponent(dq)}&state=all`)} icon={<Monitor />}>Show all assets matching <b>{dq}</b></PaletteItem>
                </Command.Group>
              )}
              {hosts.data?.rows?.length > 0 && (
                <Command.Group heading={`Hosts · ${fmtN(hosts.data.total)} matches`} className="text-[11px] text-muted [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
                  {hosts.data.rows.map((h: any) => (
                    <PaletteItem key={h.aid} onSelect={() => { onOpenChange(false); openHost(h.aid); }} icon={<Monitor />}>
                      <span className="font-medium text-fg">{h.hostname}</span>
                      <span className="font-mono text-[11.5px] text-muted">{h.local_ip}</span>
                      <span className="ml-auto text-xs"><HostStatus r={h} /></span>
                    </PaletteItem>
                  ))}
                </Command.Group>
              )}
              <Command.Group heading="Pages" className="text-[11px] text-muted [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
                {pages.filter((p) => !dq || p.label.toLowerCase().includes(dq.toLowerCase())).map((p) => (
                  <PaletteItem key={p.href} onSelect={() => go(p.href)} icon={<p.icon />}>{p.label}</PaletteItem>
                ))}
              </Command.Group>
              {dq.length >= 2 && hosts.isFetched && !hosts.data?.rows?.length && (
                <div className="px-3 py-4 text-center text-[13px] text-muted"><AlertTriangle className="mx-auto mb-1 size-4" />No hosts match “{dq}”</div>
              )}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function PaletteItem({ children, onSelect, icon }: { children: React.ReactNode; onSelect: () => void; icon?: React.ReactNode }) {
  return (
    <Command.Item onSelect={onSelect} className="flex cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] text-fg-2 data-[selected=true]:bg-accent-soft data-[selected=true]:text-fg [&_svg]:size-4 [&_svg]:text-muted">
      {icon}
      {children}
    </Command.Item>
  );
}


