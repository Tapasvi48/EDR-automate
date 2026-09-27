"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtDt, fmtRel, hoursSince } from "@/lib/format";
import { Badge, Button, Callout, Card, KV, Loading, Sheet, Tabs } from "./ui";
import { SimpleTable } from "./data-table";
import { ActualBadge, FeasibleBadge, HostFlags, HostStatus, Live, Mono, SevCounts, SeverityBadge, VerifBadge, When, YN, removalLabel } from "./badges";

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
          <Tabs value={tab} onChange={setTab} tabs={[
            { id: "overview", label: "Overview" },
            { id: "ips", label: "IP / NIC history", count: d.ip_history.length },
            { id: "related", label: "Duplicates", count: d.same_ip.length },
            { id: "inventory", label: "Inventory", count: d.inventory.length },
            { id: "vulns", label: "Vulnerabilities", count: (d.vulns || []).filter((v: any) => v.status === "open").length },
            { id: "raw", label: "Raw" },
          ]} />

          {tab === "overview" && (
            <div className="space-y-4">
              <Card className="p-4">
                <KV items={[
                  ["Connection IP", <Mono key="c">{h.connection_ip}</Mono>], ["Local IP", <Mono key="a">{h.local_ip}</Mono>],
                  ["External IP", <Mono key="b">{h.external_ip}</Mono>], ["Default gateway", h.default_gateway_ip],
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
              <Card className="p-4">
                <KV items={[
                  ["In NIAM dump", (d.niam || []).length
                    ? <span key="n" className="flex items-center gap-2"><Badge tone="good">Yes</Badge><span className="text-xs">NE ID {d.niam.map((n: any) => n.ne_id).join(", ")}</span></span>
                    : <span key="n" className="flex items-center gap-2"><Badge tone="neutral">No</Badge><span className="text-xs text-muted">{h.local_ip ? `${h.local_ip} is not in the latest NIAM dump` : "no local IP"}</span></span>],
                  ["LOB inventory", d.inventory.length
                    ? <button key="i" className="text-accent-fg hover:underline" onClick={() => setTab("inventory")}>{d.inventory.map((i: any) => `${i.lob}${i.msp ? " · " + i.msp : ""}`).join(", ")} — show all details</button>
                    : <span key="i" className="text-muted">Not in any LOB inventory</span>],
                ]} />
              </Card>
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
            <div className="space-y-3">
              <Callout>Duplicate agents: other agent IDs with the same <b>connection IP and local IP</b> as this host — the same machine with an old sensor record left behind. With two or more online at once it is a routing conflict instead.</Callout>
              <Card><SimpleTable rows={d.same_ip} columns={peerCols} empty="No other agent ID has this connection IP and local IP" /></Card>
            </div>
          )}

          {tab === "inventory" && (
            d.inventory.length ? (
              <div className="space-y-4">
                {d.inventory.map((r: any) => (
                  <Card key={`${r.lob_id}|${r.item_key}`} className="p-4">
                    <div className="mb-3 flex flex-wrap items-baseline gap-2">
                      <span className="text-[14px] font-semibold">Inventory ({r.lob})</span>
                      {r.msp && <Badge tone="outline">{r.msp}</Badge>}
                      {r.version_no && <Badge tone="info">v{r.version_no}</Badge>}
                      <span className="text-xs text-muted">{r.filename}{r.uploaded_at ? ` · uploaded ${fmtRel(r.uploaded_at)}` : ""}</span>
                      <Link className="ml-auto text-xs text-accent-fg hover:underline" href={`/lob/?id=${r.lob_id}&tab=inventory&q=${encodeURIComponent(r.ip || r.node_name)}`}>Open in LOB</Link>
                    </div>
                    <KV items={[
                      ["IP", <Mono key="ip">{r.ip}</Mono>], ["Node name", r.node_name], ["MSP", r.msp], ["Node type", r.node_type],
                      ["Domain", r.domain], ["Live / Non Live", <Live key="l" v={r.live} />], ["OS (sheet)", r.os || "–"],
                      ["EDR feasible", r.feasible ? <span key="fd" className="inline-flex items-center gap-1.5"><FeasibleBadge v={r.feasible} reason={r.feasible_reason} /><span className="text-xs text-muted">{r.feasible_reason}</span></span> : "–"],
                      ["EDR feasible (sheet)", <YN key="f" v={r.edr_feasible} />], ["EDR installed (inventory)", <YN key="i" v={r.edr_installed} />],
                      ["Remarks", r.remarks],
                      ...Object.entries(r.extra || {}).map(([k, v]) => [k, String(v)] as [string, React.ReactNode]),
                    ]} />
                    <div className="mt-3 border-t border-border pt-3">
                      <KV items={[
                        ["EDR status (matched)", <ActualBadge key="a" v={r.edr_actual} />], ["Inventory claim check", <VerifBadge key="v" v={r.verification} />],
                        ["Matched by", r.match_method], ["Change in latest version", r.change_tag || "–"],
                      ]} />
                    </div>
                  </Card>
                ))}
              </div>
            ) : <Card className="p-8 text-center text-muted">This host is not in any LOB inventory</Card>
          )}

          {tab === "vulns" && (
            <Card>
              <div className="flex flex-wrap items-center gap-3 px-4 py-3 text-[12.5px]">
                <SevCounts c={(d.vulns || []).filter((v: any) => v.status === "open" && v.sev_rank === 4).length}
                  h={(d.vulns || []).filter((v: any) => v.status === "open" && v.sev_rank === 3).length}
                  m={(d.vulns || []).filter((v: any) => v.status === "open" && v.sev_rank === 2).length}
                  l={(d.vulns || []).filter((v: any) => v.status === "open" && v.sev_rank === 1).length} />
                <span className="text-muted">Last scan: {d.scans?.length ? `${fmtDt(d.scans[0].scanned_at)} (${d.scans[0].lob})` : "never scanned"}</span>
                <Link className="ml-auto text-accent-fg hover:underline" href={`/ip-search/?q=${h.local_ip}`}>Open in Asset 360</Link>
              </div>
              <SimpleTable rows={d.vulns || []} maxHeight="55vh" empty={`No vulnerability findings for ${h.local_ip || "this host"}`} columns={[
                { key: "severity", label: "Severity", render: (r: any) => <SeverityBadge s={r.severity} /> },
                { key: "name", label: "Vulnerability", wrap: true },
                { key: "lob", label: "LOB" },
                { key: "port", label: "Port", render: (r: any) => `${r.port || ""}${r.protocol ? "/" + r.protocol : ""}` },
                { key: "cve", label: "CVE", wrap: true },
                { key: "last_observed", label: "Last observed", render: (r: any) => fmtDt(r.last_observed) },
                { key: "status", label: "Status", render: (r: any) => r.status === "fixed" ? <span className="text-good-fg">Fixed</span> : "Open" },
              ]} />
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
