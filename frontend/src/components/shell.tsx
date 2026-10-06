"use client";
import * as React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Command } from "cmdk";
import * as Dialog from "@radix-ui/react-dialog";
import { BadgeCheck, Boxes, Flame, Globe2, Waypoints, History, Radar, ShieldAlert, Upload, AlertTriangle, Building2, Copy, Network, FileSpreadsheet, FileText, Globe, LayoutDashboard, Menu, Monitor, Moon, PackagePlus, PlugZap, RefreshCw, Search, Settings, ShieldCheck, Sun, Target, WifiOff, ShieldQuestion, GitCompare, Database, PackageCheck, ClipboardCheck, Plug, Route, Siren, UsersRound, ListTree, ScanSearch, ChevronRight, PanelLeftClose, PanelLeftOpen, Earth, BellRing, Bug, Cpu, Bot, Crosshair, Layers, BookOpen } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button } from "./ui";
import { HostStatus } from "./badges";
import { useHostDrawer } from "./host-drawer";
import { ChatDock } from "./ai/chat";
import { nextSyncLabel, useSyncStatus } from "./sync-progress";

const NAV: { section?: string; items: { href: string; label: string; icon: React.ElementType }[] }[] = [
  { items: [
    { href: "/", label: "Overview", icon: LayoutDashboard },
    { href: "/ip-search/", label: "Asset 360 search", icon: Globe },
  ] },
  { section: "AI SOC", items: [
    { href: "/falcon-mcp/", label: "AI SOC assistant", icon: Bot },
    { href: "/ioc/", label: "IOC check", icon: Crosshair },
    { href: "/falcon-mcp/?tab=fabric", label: "Data fabric", icon: Layers },
    { href: "/falcon-mcp/?tab=kb", label: "Knowledge base", icon: BookOpen },
  ] },
  { section: "SIEM & logging", items: [
    { href: "/splunk/", label: "Splunk overview", icon: Database },
    { href: "/splunk/?tab=coverage", label: "Logging coverage", icon: ShieldAlert },
    { href: "/splunk/?tab=notables", label: "Splunk detections", icon: Siren },
    { href: "/splunk/?tab=sync", label: "Splunk sync", icon: RefreshCw },
  ] },
  { section: "Attack surface", items: [
    { href: "/surface/", label: "Attack surface", icon: Earth },
    { href: "/passive-scan/", label: "Internet DB scan", icon: ScanSearch },
    { href: "/subnets/", label: "Subnets & VLANs", icon: Network },
  ] },
  { section: "Leadership & SOC", items: [
    { href: "/alerts/", label: "Alerts", icon: BellRing },
    { href: "/top-risks/", label: "Top riskiest assets", icon: Siren },
    { href: "/attack-paths/", label: "Attack paths", icon: Route },
    { href: "/analysts/", label: "Analyst workload", icon: UsersRound },
  ] },
  { section: "CrowdStrike", items: [
    { href: "/assets/", label: "CrowdStrike assets", icon: Monitor },
    { href: "/detections/", label: "Detections", icon: Siren },
    { href: "/health/", label: "Offline", icon: WifiOff },
    { href: "/duplicates/", label: "Duplicates", icon: Copy },
    { href: "/routing/", label: "Routing conflicts", icon: Network },
    { href: "/installs/", label: "New installs", icon: PackagePlus },
    { href: "/feasibility/", label: "EDR feasibility", icon: ShieldQuestion },
    { href: "/sensors/", label: "Sensor versions & OS", icon: Cpu },
    { href: "/policies/", label: "Prevention policies", icon: ShieldCheck },
    { href: "/spotlight/", label: "Spotlight vulnerabilities", icon: Bug },
  ] },
  { section: "Inventory", items: [
    { href: "/inventory/", label: "All inventory", icon: Boxes },
    { href: "/lobs/", label: "LOB inventory", icon: Building2 },
    { href: "/inventory-sources/", label: "Inventory sources", icon: Database },
    { href: "/exposure/", label: "Internet exposed", icon: Globe2 },
    { href: "/matrix/", label: "Communication matrix", icon: Waypoints },
    { href: "/coverage/", label: "Coverage gaps", icon: Target },
    { href: "/templates/", label: "Templates", icon: FileText },
  ] },
  { section: "Vulnerability", items: [
    { href: "/vulnerabilities/", label: "Vulnerabilities", icon: ShieldAlert },
    { href: "/scan-gaps/", label: "Scan coverage", icon: Radar },
    { href: "/risk/", label: "Risk ranking", icon: Flame },
    { href: "/exceptions/", label: "Exceptions (SOD)", icon: BadgeCheck },
  ] },
  { section: "Patch & MBSS", items: [
    { href: "/patches/", label: "Patches & errata", icon: PackageCheck },
    { href: "/mbss/", label: "MBSS compliance", icon: ClipboardCheck },
  ] },
  { section: "System", items: [
    { href: "/connectors/", label: "Integrations", icon: Plug },
    { href: "/upload/", label: "Upload center", icon: Upload },
    { href: "/reports/", label: "Reports", icon: FileSpreadsheet },
    { href: "/settings/", label: "Sync & settings", icon: Settings },
  ] },
];

function useSync() {
  const qc = useQueryClient();
  const wasRunning = React.useRef(false);
  const wasRefreshing = React.useRef(false);
  const q = useSyncStatus();
  React.useEffect(() => {  // background re-matching after a large upload: refresh every page's data when it ends
    const r = !!q.data?.refresh?.running;
    if (wasRefreshing.current && !r) {
      if (q.data?.refresh?.error) toast.error(`Matching failed: ${q.data.refresh.error}`);
      else toast.success(`Inventory matched with CrowdStrike · ${q.data?.refresh?.seconds ?? ""}s`);
      qc.invalidateQueries({ predicate: (x) => x.queryKey[0] !== "sync-status" });
    }
    wasRefreshing.current = r;
  }, [q.data, qc]);
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
  // desktop: hide the navigation panel for more room (remembered; Ctrl/⌘ + B toggles)
  const [navHidden, setNavHidden] = React.useState(false);
  React.useEffect(() => { try { setNavHidden(localStorage.getItem("nav-hidden") === "1"); } catch {} }, []);
  const toggleNav = React.useCallback(() => setNavHidden((v) => {
    try { localStorage.setItem("nav-hidden", v ? "0" : "1"); } catch {}
    return !v;
  }), []);
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
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleNav();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleNav]);
  React.useEffect(() => setMobileNav(false), [pathname]);

  // sidebar sections fold away; the section of the current page is always open; your choice is remembered
  const [openSections, setOpenSections] = React.useState<Set<string>>(new Set());
  React.useEffect(() => {
    try { const v = localStorage.getItem("nav-open"); if (v) setOpenSections(new Set(JSON.parse(v))); } catch {}
  }, []);
  const toggleSection = (sec: string) => setOpenSections((prev) => {
    const n = new Set(prev);
    n.has(sec) ? n.delete(sec) : n.add(sec);
    try { localStorage.setItem("nav-open", JSON.stringify([...n])); } catch {}
    return n;
  });
  if (pathname.startsWith("/ai")) return <>{children}</>; // AI SOC in its own full window / new tab
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href.replace(/\/$/, "")));

  return (
    <div className="flex min-h-screen">
      <aside className={cn("print:hidden",
        "fixed inset-y-0 left-0 z-40 flex w-[232px] flex-col bg-side text-[#a9b2c3] transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
        mobileNav ? "translate-x-0" : "-translate-x-full", navHidden && "lg:hidden"
      )}>
        <div className="flex items-center gap-2.5 px-4 pb-3 pt-4">
          <div className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-[#e5483f] to-[#a3221b] shadow-lg">
            <ShieldCheck className="size-4.5 text-white" />
          </div>
          <div className="leading-tight">
            <div className="whitespace-nowrap text-[14.5px] font-semibold text-white">EDR Asset Console</div>
            <div className="text-[11px]">CrowdStrike Falcon</div>
          </div>
          <button onClick={toggleNav} title="Hide navigation (Ctrl/⌘ + B)" className="ml-auto hidden rounded-md p-1 text-[#6b7384] hover:bg-white/10 hover:text-white lg:block">
            <PanelLeftClose className="size-4" /></button>
        </div>
        <button onClick={() => setPaletteOpen(true)} className="mx-3 mb-1 flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-left text-xs text-[#8a93a6] hover:bg-white/10">
          <Search className="size-3.5" /> Search hosts, IPs…
          <kbd className="ml-auto rounded bg-white/10 px-1.5 text-[10px]">⌘K</kbd>
        </button>
        <nav className="flex-1 overflow-y-auto px-2.5 pb-4 scroll-thin">
          {NAV.map((g, i) => {
            const hasActive = g.items.some((it) => isActive(it.href));
            const open = !g.section || hasActive || openSections.has(g.section);
            return (
              <div key={i} className={g.section ? "mt-1" : ""}>
                {g.section && (
                  <button onClick={() => toggleSection(g.section!)}
                    className={cn("flex w-full items-center rounded-md px-2.5 pb-1 pt-3 text-[10.5px] font-semibold uppercase tracking-[.08em] transition-colors hover:text-white",
                      hasActive ? "text-[#c3cad6]" : "text-[#5f6879]")}>
                    {g.section}
                    <ChevronRight className={cn("ml-auto size-3.5 transition-transform", open && "rotate-90")} />
                  </button>
                )}
                {open && g.items.map((it) => (
                  <Link key={it.href} href={it.href}
                    className={cn("mt-0.5 flex items-center gap-2.5 rounded-lg px-2.5 py-[6px] text-[13px] font-medium transition-colors",
                      isActive(it.href) ? "bg-white/10 text-white" : "hover:bg-white/5 hover:text-white")}>
                    <it.icon className="size-[16px] opacity-90" />
                    {it.label}
                  </Link>
                ))}
              </div>
            );
          })}
        </nav>
        <div className="border-t border-white/10 p-3 text-[11.5px]">
          {status?.demo ? (
            <div className="rounded-lg bg-white/5 px-2 py-1.5 text-center text-white/70">Sample data · syncing off</div>
          ) : status && !status.configured ? (
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
        <header className="sticky top-0 z-20 flex h-13 print:hidden items-center gap-3 border-b border-border bg-surface/85 px-4 backdrop-blur lg:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileNav(true)}><Menu /></Button>
          {navHidden && <Button variant="ghost" size="icon" className="hidden lg:inline-flex" title="Show navigation (Ctrl/⌘ + B)" onClick={toggleNav}><PanelLeftOpen /></Button>}
          <button onClick={() => setPaletteOpen(true)} className="flex h-8.5 w-full max-w-md items-center gap-2 rounded-lg border border-border bg-surface-2 px-3 text-left text-[13px] text-muted hover:border-border-strong">
            <Search className="size-4 shrink-0" /> <span className="truncate">Jump to host, IP, AID or page…</span>
            <kbd className="ml-auto hidden rounded border border-border bg-surface px-1.5 text-[10.5px] sm:block">⌘K</kbd>
          </button>
          <div className="flex-1" />
          {status?.running && <Link href="/settings/"><Badge tone="info"><RefreshCw className="size-3 animate-spin" /> {status.stage}</Badge></Link>}
          {status?.refresh?.running && <Badge tone="info" title="Inventory, exposure and risk are being re-matched in the background; pages update when it finishes">
            <span className="mr-1 inline-block size-2 animate-pulse rounded-full bg-accent" />{status.refresh.label || "Updating matches"}…</Badge>}
          {status?.demo && <Badge tone="violet" title="Started with --demo: sample data in data/demo.db, syncing off. Your real database is not used.">Sample data</Badge>}
          {status && !status.configured && !status.demo && <Link href="/settings/"><Badge tone="warn">Not connected</Badge></Link>}
          <ThemeToggle />
        </header>
        <div className="mx-auto w-full max-w-[1720px] px-4 pb-16 pt-5 lg:px-6">{children}</div>
      </main>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
      <React.Suspense fallback={null}><ChatDock /></React.Suspense>
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
                  {looksIp && <PaletteItem onSelect={() => go(`/ip-search/?q=${encodeURIComponent(dq)}`)} icon={<Globe />}>Asset 360 for <b>{dq}</b></PaletteItem>}
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


