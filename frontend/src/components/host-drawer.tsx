"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, History, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtDt, fmtRel, hoursSince } from "@/lib/format";
import { Badge, Button, Callout, Card, KV, Loading, SectionTitle, Sheet, Tabs } from "./ui";
import { SimpleTable } from "./data-table";
import { ActualBadge, EventBadge, EventDetails, HostFlags, HostStatus, Live, Mono, VerifBadge, When, YN, removalLabel } from "./badges";

const Ctx = React.createContext<{ open: (aid: string) => void }>({ open: () => {} });
export const useHostDrawer = () => React.useContext(Ctx);

export function HostDrawerProvider({ children }: { children: React.ReactNode }) {
  const [stack, setStack] = React.useState<string[]>([]);
  const open = React.useCallback((aid: string) => setStack((s) => (s[s.length - 1] === aid ? s : [...s, aid])), []);
  const aid = stack[stack.length - 1];
  return (
    <Ctx.Provider value={{ open }}>
      {children}
      {aid && <HostSheet aid={aid} canBack={stack.length > 1} onBack={() => setStack((s) => s.slice(0, -1))} onClose={() => setStack([])} />}
    </Ctx.Provider>
  );
}

function HostSheet({ aid, onClose, onBack, canBack }: { aid: string; onClose: () => void; onBack: () => void; canBack: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["host", aid], queryFn: () => api<any>(`/api/hosts/${encodeURIComponent(aid)}`) });
  const [tab, setTab] = React.useState("overview");
  const [nicLoading, setNicLoading] = React.useState(false);
  React.useEffect(() => setTab("overview"), [aid]);
  const d = q.data;
  const h = d?.host;
  // same connection IP + local IP: at most one online = duplicate agents, two or more online = routing conflict
  const peers = d && h.console_state === "active" ? [h, ...d.same_ip.filter((x: any) => x.console_state === "active")] : [];
  const peersOnline = peers.filter((x: any) => x.online_state === "online").length;
  const dupCount = peersOnline < 2 ? peers.length : 0;
  const rcCount = peersOnline >= 2 ? peers.length : 0;
  const stale = (globalThis as any).__staleHours || 1;

  const refreshNic = async () => {
    setNicLoading(true);
    try {
      const r = await api(`/api/hosts/${aid}/nic-refresh`, { method: "POST" });
      toast.success(`NIC history refreshed (${r.entries} entries)`);
      qc.invalidateQueries({ queryKey: ["host", aid] });
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setNicLoading(false);
    }
  };

  const peerCols = [
    { key: "hostname", label: "Hostname", render: (r: any) => <PeerLink aid={r.aid}>{r.hostname || r.aid}</PeerLink> },
    { key: "local_ip", label: "IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
    { key: "status", label: "Status", render: (r: any) => <HostStatus r={r} /> },
    { key: "first_seen", label: "First seen", render: (r: any) => fmtDt(r.first_seen) },
    { key: "last_seen", label: "Last seen", render: (r: any) => <When ts={r.last_seen} /> },
    { key: "platform_name", label: "Platform" },
  ];

  return (
    <Sheet
      open
      onOpenChange={(o) => !o && onClose()}
      title={h ? <span>{h.hostname || "(no hostname)"} <HostFlags r={{ ...h, dup_count: dupCount, rc_count: rcCount }} /></span> : "Loading…"}
      sub={h ? <span className="flex flex-wrap items-center gap-2"><Mono>{h.aid}</Mono>
        <button title="Copy AID" onClick={() => { navigator.clipboard?.writeText(h.aid); toast.success("AID copied"); }}><Copy className="size-3.5" /></button>
        · <HostStatus r={h} /></span> : undefined}
      actions={canBack ? <Button size="sm" variant="ghost" onClick={onBack}>← Back</Button> : undefined}
    >
      {!d ? <Loading /> : (
        <>
          {h.console_state !== "active" && (
            <Callout tone="crit" className="mb-3">
              This host is <b>{h.console_state}</b> in the Falcon console{h.removed_at ? ` since ${fmtDt(h.removed_at)}` : ""} — {removalLabel(h.removal_type)}. The record is kept in the local database.
            </Callout>
          )}
          {h.online_state === "online" && (hoursSince(h.last_seen) || 0) > stale && (
            <Callout tone="warn" className="mb-3">
              Falcon reports this host <b>online</b> but it last checked in {fmtRel(h.last_seen)}. The sensor may be connected but not reporting normally (proxy, sleep/hibernate, RFM or cloud connectivity).
            </Callout>
          )}
          {h.is_reinstall ? (
            <Callout tone="info" className="mb-3">
              <b>Reinstall:</b> an older agent ID had the same connection IP. See the “Related agents” tab.
            </Callout>
          ) : null}
          <Tabs value={tab} onChange={setTab} tabs={[
            { id: "overview", label: "Overview" },
            { id: "ips", label: "IP / NIC history", count: d.ip_history.length },
            { id: "related", label: "Related agents", count: d.same_ip.length + d.same_hostname.length + (h.reinstall_of?.length || 0) + d.replaced_by.length },
            { id: "inventory", label: "Inventory", count: d.inventory.length },
            { id: "activity", label: "Activity", count: d.events.length },
            { id: "raw", label: "Raw" },
          ]} />

          {tab === "overview" && (
            <div className="space-y-4">
              <Card className="p-4">
                <KV items={[
                  ["Local IP", <Mono key="a">{h.local_ip}</Mono>], ["External IP", <Mono key="b">{h.external_ip}</Mono>],
                  ["Connection IP", <Mono key="c">{h.connection_ip}</Mono>], ["Default gateway", h.default_gateway_ip],
                  ["MAC", <Mono key="d">{h.mac_address}</Mono>], ["Platform", h.platform_name],
                  ["OS", h.os_version], ["OS product", h.os_product_name],
                  ["OS build / kernel", h.os_build || h.kernel_version], ["Host type", h.product_type_desc],
                  ["Chassis", h.chassis_type_desc], ["Manufacturer / model", [h.system_manufacturer, h.system_product_name].filter(Boolean).join(" · ")],
                  ["Serial", h.serial_number], ["Domain", h.machine_domain], ["Site", h.site_name], ["OU", h.ou],
                  ["Last login user", h.last_login_user], ["Host groups", h.groups], ["Falcon tags", h.tags],
                ]} />
              </Card>
              <Card className="p-4">
                <KV items={[
                  ["Sensor version", <Mono key="s">{h.agent_version}</Mono>], ["Containment", h.containment_status],
                  ["Reduced functionality", h.rfm], ["Online state", <span key="o">{h.online_state || "–"} {h.online_checked_at && <span className="text-xs text-muted">checked {fmtRel(h.online_checked_at)}</span>}</span>],
                  ["First seen (install)", <When key="f" ts={h.first_seen} />], ["Last seen", <When key="l" ts={h.last_seen} />],
                  ["Console state", h.console_state], ["Modified", fmtDt(h.modified_timestamp)],
                  ["First synced to DB", fmtDt(h.db_first_synced)], ["Last synced", fmtDt(h.db_last_synced)],
                ]} />
              </Card>
              {d.inventory.length > 0 && (
                <Card className="p-4">
                  <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Inventory ({d.inventory.map((i: any) => i.lob).join(", ")})</div>
                  <KV items={[
                    ["Node type", d.inventory[0].node_type], ["Domain", d.inventory[0].domain], ["Live / Non Live", <Live key="l" v={d.inventory[0].live} />],
                    ["EDR feasible", <YN key="f" v={d.inventory[0].edr_feasible} />], ["EDR installed (inventory)", <YN key="i" v={d.inventory[0].edr_installed} />],
                    ["Verification", <VerifBadge key="v" v={d.inventory[0].verification} />], ["Remarks", d.inventory[0].remarks],
                  ]} />
                </Card>
              )}
            </div>
          )}

          {tab === "ips" && (
            <Card>
              <div className="flex items-center gap-2 px-4 py-3">
                <span className="text-xs text-muted">Every IP this agent reported — from our sync snapshots and Falcon&apos;s network address history.</span>
                <Button size="sm" className="ml-auto" loading={nicLoading} onClick={refreshNic}><RefreshCw /> Refresh from Falcon</Button>
              </div>
              <SimpleTable rows={d.ip_history} empty="No IP history" columns={[
                { key: "ip", label: "IP", render: (r: any) => <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${r.ip}`}>{r.ip}</Link> },
                { key: "kind", label: "Kind" },
                { key: "source", label: "Source", render: (r: any) => <Badge>{r.source}</Badge> },
                { key: "mac", label: "MAC", render: (r: any) => <Mono>{r.mac}</Mono> },
                { key: "first_seen", label: "First seen", render: (r: any) => fmtDt(r.first_seen) },
                { key: "last_seen", label: "Last seen", render: (r: any) => fmtDt(r.last_seen) },
                { key: "cur", label: "", render: (r: any) => r.ip === h.local_ip && r.kind === "local" ? <Badge tone="good">current</Badge> : null },
              ]} />
            </Card>
          )}

          {tab === "related" && (
            <div className="space-y-4">
              {h.reinstall_of?.length > 0 && (
                <div>
                  <SectionTitle className="mt-0">Reinstall of — older agent IDs</SectionTitle>
                  <Card><SimpleTable rows={h.reinstall_of} columns={[
                    { key: "hostname", label: "Hostname", render: (r: any) => <PeerLink aid={r.aid}>{r.hostname || r.aid}</PeerLink> },
                    { key: "shared_ip", label: "Shared connection IP", render: (r: any) => <Mono>{r.shared_ip || r.ip}</Mono> },
                    { key: "ip", label: "Its current connection IP", render: (r: any) => <Mono>{r.ip}</Mono> },
                    { key: "state", label: "Console state" },
                    { key: "first_seen", label: "First seen", render: (r: any) => fmtDt(r.first_seen) },
                    { key: "last_seen", label: "Last seen", render: (r: any) => fmtDt(r.last_seen) },
                  ]} /></Card>
                </div>
              )}
              {d.replaced_by.length > 0 && (
                <div>
                  <SectionTitle className="mt-0">Replaced by newer agent ID</SectionTitle>
                  <Card><SimpleTable rows={d.replaced_by} columns={[
                    { key: "hostname", label: "Hostname", render: (r: any) => <PeerLink aid={r.aid}>{r.hostname}</PeerLink> },
                    { key: "local_ip", label: "IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
                    { key: "first_seen", label: "First seen", render: (r: any) => fmtDt(r.first_seen) },
                  ]} /></Card>
                </div>
              )}
              <div>
                <SectionTitle className="mt-0">Other agents with the same connection IP and local IP ({d.same_ip.length})</SectionTitle>
                <Card><SimpleTable rows={d.same_ip} columns={peerCols} empty="No other agent ID has this connection IP and local IP" /></Card>
              </div>
              <div>
                <SectionTitle className="mt-0">Other agents with the same hostname ({d.same_hostname.length})</SectionTitle>
                <Card><SimpleTable rows={d.same_hostname} columns={peerCols} empty="No other agent ID has this hostname" /></Card>
              </div>
            </div>
          )}

          {tab === "inventory" && (
            <Card>
              <SimpleTable rows={d.inventory} empty="This host is not in any LOB inventory" columns={[
                { key: "lob", label: "LOB", render: (r: any) => <Link className="text-accent-fg hover:underline" href={`/lob/?id=${r.lob_id}&q=${encodeURIComponent(r.ip || r.node_name)}`}>{r.lob}</Link> },
                { key: "node_name", label: "Node name" }, { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip}</Mono> },
                { key: "node_type", label: "Node type" }, { key: "domain", label: "Domain" },
                { key: "live", label: "Live", render: (r: any) => <Live v={r.live} /> },
                { key: "edr_feasible", label: "EDR feasible", render: (r: any) => <YN v={r.edr_feasible} /> },
                { key: "edr_installed", label: "EDR installed", render: (r: any) => <YN v={r.edr_installed} /> },
                { key: "edr_actual", label: "EDR actual", render: (r: any) => <ActualBadge v={r.edr_actual} /> },
                { key: "verification", label: "Verification", render: (r: any) => <VerifBadge v={r.verification} /> },
                { key: "match_method", label: "Match", render: (r: any) => <Badge>{r.match_method}</Badge> },
                { key: "remarks", label: "Remarks", wrap: true },
              ]} />
            </Card>
          )}

          {tab === "activity" && (
            <Card className="px-4 py-2">
              {d.events.length ? d.events.map((e: any, i: number) => (
                <div key={i} className="grid grid-cols-[150px_150px_1fr] gap-3 border-b border-border py-2 text-[12.5px] last:border-0">
                  <span className="text-muted">{fmtDt(e.ts)}</span>
                  <span><EventBadge e={e.event} /></span>
                  <span><EventDetails e={e} /></span>
                </div>
              )) : <div className="py-6 text-center text-muted"><History className="mx-auto mb-2 size-5" />No events recorded</div>}
            </Card>
          )}

          {tab === "raw" && (
            <pre className="max-h-[70vh] overflow-auto rounded-xl border border-border bg-surface p-4 font-mono text-[11.5px] scroll-thin">{JSON.stringify(h.raw, null, 2)}</pre>
          )}
        </>
      )}
    </Sheet>
  );
}

function PeerLink({ aid, children }: { aid: string; children: React.ReactNode }) {
  const { open } = useHostDrawer();
  return <a className="cursor-pointer font-medium text-accent-fg hover:underline" onClick={() => open(aid)}>{children}</a>;
}
