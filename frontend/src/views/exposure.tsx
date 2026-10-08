"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ChevronDown, Network, Pin, Plus, ShieldOff, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Card, Kpi, KpiGrid, Loading, Modal, PageHeader, Tabs } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { EdrBadge, Mono, SeverityBadge } from "@/components/badges";
import { RegistryTable } from "@/components/registry-table";

const RULES: [string, string, string][] = [
  ["inventory", "LOB inventory", "An “Internet Facing” / “Exposure” / “Zone” column says Yes, DMZ or Internet, or a “Public IP” / “NAT IP” column gives the node a public address (also when several nodes share one NAT IP)."],
  ["scan", "VA scan", "A scan covered a public IP: the asset's own public IP, or the public / NAT IP of an inventory node (its findings are what the internet can see)."],
  ["matrix", "Communication matrix", "Three kinds of asset: (1) a public IP no rule NATs to a private IP (directly on the internet); (2) a private IP with its public / NAT IP, from an inbound destination-NAT rule or an outbound source-NAT rule (the public IP is shown on the private asset, not as an asset of its own); (3) a private IP the firewall lets in from or out to the internet with no NAT IP. Internet destinations, partner sources and VPN peers are never listed. Rows can be marked internet-facing by hand."],
  ["ip", "Public IP", "The asset's own IPv4 is globally routable and comes from an inventory, the NIAM dump or a VA scan. A global IPv6 address alone is not evidence (IPv6 needs no NAT, so most IPv6 addresses are global): IPv6 assets are exposed only through the communication matrix, an inventory Internet Facing / Public IP column, or Mark exposed."],
  ["edr", "CrowdStrike connection IP", "The agent's connection IP (the interface it reaches the CrowdStrike cloud from) is a public IPv4. CrowdStrike assets are listed under their connection IP; the local IP and the external (egress / NAT) IP are not exposure evidence."],
  ["va", "VA public inventory", "The host is on the uploaded VA public inventory sheet. The asset is its private IP; when the sheet has none, the private IP the communication matrix NATs the public IP to; else the public IP. LOB / MSP / node type come from the LOB inventory, or from the sheet when no inventory lists the host. Differences with the matrix or the LOB inventory are shown as evidence (‘VA public inventory differs’)."],
  ["passive", "Passive scan", "Shodan InternetDB (Internet DB scan page) sees open ports on the asset's public IP or the public / NAT IP it sits behind."],
  ["manual", "Marked by hand", "The IP or its subnet is on the Mark exposed list, with a note saying where you know it from."],
];
const TABS = [["exposed", "Directly exposed"], ["cgnat", "Indirectly exposed"], ["shadow", "Shadow exposure"], ["whitelisted", "Whitelisted"]] as const;

export default function Exposure() {
  const [state, set, replaceAll] = useUrlState();
  const [how, setHow] = React.useState(false);
  const [wlOpen, setWlOpen] = React.useState(false);
  const [indOpen, setIndOpen] = React.useState(false);
  const [manOpen, setManOpen] = React.useState(false);
  const tab = (state.tab as string) || "exposed";
  const { data: s, error, refetch } = useQuery({ queryKey: ["exposure-summary"], queryFn: () => api<any>("/api/exposure/summary") });
  const { data: sh } = useQuery({ queryKey: ["exposure-shadow"], queryFn: () => api<any>("/api/exposure/shadow") });
  if (!s) return <Loading error={error} retry={() => refetch()} />;
  const only = (patch: Record<string, string>) => replaceAll({ ...patch, tab: "exposed" });
  const fixed: Record<string, string> = tab === "cgnat" ? { cgnat: "1" } : tab === "whitelisted" ? { whitelisted: "1" } : { exposed: "1" };
  return (
    <div>
      <PageHeader title="Internet exposed"
        sub="Assets reachable from the internet, with the evidence for each: LOB inventory, the communication matrix, a VA scan of a public IP, or a public IP from an inventory / NIAM / scan."
        actions={<>
          <Button onClick={() => setManOpen(true)}><Pin /> Mark exposed ({fmtN(s.manual?.length || 0)})</Button>
          <Button onClick={() => setIndOpen(true)}><Network /> Indirect ranges ({fmtN(s.indirect?.length || 0)})</Button>
          <Button onClick={() => setWlOpen(true)}><ShieldOff /> Whitelist ({fmtN(s.whitelist?.length || 0)})</Button>
        </>} />
      <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(170px,1fr))]">
        <Kpi label="Exposed assets" value={s.exposed} tone="crit" active={tab === "exposed" && !Object.keys(state).some((k) => !["page", "size", "sort", "dir", "tab"].includes(k))} onClick={() => only({})} />
        <Kpi label="No EDR agent" value={s.no_edr} tone="crit" foot="exposed and unprotected" active={state.edr_status === "Not Installed"} onClick={() => only({ edr_status: "Not Installed" })} />
        <Kpi label="Crit / high vulns" value={s.crit_high} tone="serious" active={state.vulns === "crit_high"} onClick={() => only({ vulns: "crit_high" })} />
        <Kpi label="Not in any inventory" value={s.not_in_inventory} tone="violet" active={state.missing === "inventory"} onClick={() => only({ missing: "inventory" })} />
        <Kpi label="Shadow exposure" value={sh?.shadow_ips ?? "–"} tone="serious" foot="public IPs no matrix rule covers" active={tab === "shadow"} onClick={() => replaceAll({ tab: "shadow" })} />
        <Kpi label="Indirectly exposed" value={s.cgnat} foot="CGNAT + telecom ranges" active={tab === "cgnat"} onClick={() => replaceAll({ tab: "cgnat" })} />
      </KpiGrid>
      <div className="mt-3 flex flex-wrap items-center gap-1.5 text-[12.5px]">
        <span className="mr-1 text-muted">Exposed by</span>
        {([["inventory", "Inventory", s.by_inventory], ["scan", "VA scan", s.by_scan], ["matrix", "Comm. matrix", s.by_matrix], ["va", "VA public inventory", s.by_va], ["passive", "Passive scan", s.by_passive],
          ["edr", "CrowdStrike", s.by_edr], ["manual", "Marked by hand", s.by_manual]] as [string, string, number][]).map(([k, l, n]) => (
          <button key={k} onClick={() => only({ exposure_src: k })}
            className={cn("rounded-full border px-2.5 py-0.5 transition-colors", state.exposure_src === k ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-border-strong")}>
            {l} <b className="tabular">{fmtN(n || 0)}</b>
          </button>
        ))}
        <span className="ml-1 text-[11.5px] text-muted">an asset can have several</span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[12.5px]">
        <span className="mr-1 text-muted">Address type</span>
        {([["public", "Public IP only (direct, no private IP behind)", s.kind_public], ["nat", "Private + public / NAT IP", s.kind_nat],
          ["private", "Private, internet without NAT IP", s.kind_private]] as [string, string, number][]).map(([k, l, n]) => (
          <button key={k} onClick={() => only({ ip_kind: k })}
            className={cn("rounded-full border px-2.5 py-0.5 transition-colors", state.ip_kind === k ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-border-strong")}>
            {l} <b className="tabular">{fmtN(n || 0)}</b>
          </button>
        ))}
        {s.matrix_only > 0 && <button onClick={() => only({ has: "matrix" })}
          className={cn("rounded-full border px-2.5 py-0.5", state.has === "matrix" ? "border-accent bg-accent-soft text-accent-fg" : "border-border hover:border-border-strong")}
          title="Addresses only the communication matrix knows (no inventory, scan, CrowdStrike or NIAM record yet)">Only in the matrix <b className="tabular">{fmtN(s.matrix_only)}</b></button>}
      </div>

      <Card className="mt-4">
        <button className="flex w-full items-center gap-2 px-4 py-3 text-left text-[13px] font-semibold" onClick={() => setHow(!how)}>
          How an asset is marked internet-exposed <ChevronDown className={cn("size-4 transition-transform", how && "rotate-180")} />
          <span className="ml-auto font-normal text-muted">any one of these is enough</span>
        </button>
        {how && (
          <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
            {RULES.map(([k, t, d]) => (
              <div key={k} className="rounded-lg border border-border bg-surface-2/40 p-3">
                <div className="text-[12.5px] font-semibold">{t}</div>
                <div className="mt-1 text-[12px] text-fg-2">{d}</div>
              </div>
            ))}
            <div className="rounded-lg border border-dashed border-border p-3 text-[12px] text-muted md:col-span-2">
              Not counted as directly exposed: whitelisted IPs / subnets, and indirectly exposed assets — CGNAT addresses (100.64.0.0/10) and the telecom ranges you add under Indirect ranges (partner / NNI / roaming / core links). Every asset inside those ranges is listed on the Indirectly exposed tab so you still see it.
            </div>
          </div>
        )}
      </Card>

      <div className="mt-4">
        <Tabs value={tab} onChange={(v) => replaceAll({ tab: v })}
          tabs={TABS.map(([id, label]) => ({ id, label, count: id === "exposed" ? s.exposed : id === "cgnat" ? s.cgnat : id === "shadow" ? sh?.shadow : s.whitelisted }))} />
        {tab === "shadow" ? <ShadowTable data={sh} />
          : <RegistryTable key={tab} state={state} set={set} reset={() => replaceAll({ tab })} fixed={fixed} storageKey="exposure-v2" hideExposure />}
      </div>

      <ListDialog kind="whitelist" open={wlOpen} onOpenChange={setWlOpen} entries={s.whitelist || []} />
      <ListDialog kind="indirect" open={indOpen} onOpenChange={setIndOpen} entries={s.indirect || []} />
      <ListDialog kind="manual" open={manOpen} onOpenChange={setManOpen} entries={s.manual || []} />
    </div>
  );
}

const LISTS = {
  shadow: { title: "Shadow ranges", ok: "Shadow ranges saved",
    text: "IPs and subnets to watch for shadow exposure, e.g. your own public ranges. Every known IP inside them (inventory, CrowdStrike, VA scan, NIAM) that no inbound rule of the communication matrix covers is listed on the Shadow exposure tab. Whitelisted, CGNAT and indirect ranges are left out." },
  manual: { title: "Mark internet exposed", ok: "Exposed list saved",
    text: "IPs and subnets you know are reachable from the internet but no upload says so. In the note, say where it comes from (e.g. MP firewall export, pentest report); it shows in the Exposed by column." },
  whitelist: { title: "Exposure whitelist", ok: "Whitelist saved", text: "IPs and subnets here are never listed as internet exposed. They stay visible on the Whitelisted tab." },
  indirect: { title: "Indirectly exposed ranges", ok: "Indirect ranges saved",
    text: "Telecom ranges reachable from the internet only through another network (CGNAT pools, partner / NNI / roaming interconnects, core links). Every asset whose IP or NAT IP is inside them shows on the Indirectly exposed tab. CGNAT (100.64.0.0/10) is always included." },
};
/** Editable IP / subnet list: the whitelist or the indirectly exposed ranges. */
function ListDialog({ kind, open, onOpenChange, entries }: { kind: "whitelist" | "indirect" | "manual" | "shadow"; open: boolean; onOpenChange: (v: boolean) => void; entries: any[] }) {
  const L = LISTS[kind];
  const qc = useQueryClient();
  const [rows, setRows] = React.useState<any[]>(entries);
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => { if (open) setRows(entries.length ? entries : [{ value: "", note: "" }]); }, [open, entries]);
  const save = async () => {
    setBusy(true);
    try {
      const r = await api<any>(`/api/exposure/${kind === "shadow" ? "shadow-ranges" : kind}`, { method: "PUT", body: { entries: rows } });
      toast.success(`${L.ok} · ${fmtN(r.entries.length)} entr${r.entries.length === 1 ? "y" : "ies"}`);
      qc.invalidateQueries();
      onOpenChange(false);
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  const cls = "h-8 rounded-lg border border-border-strong bg-surface px-2.5 text-[13px] outline-none focus:border-accent";
  return (
    <Modal open={open} onOpenChange={onOpenChange} title={L.title}
      footer={<><Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button><Button variant="primary" onClick={save} disabled={busy}>Save</Button></>}>
      <p className="mb-3 text-[13px] text-fg-2">{L.text} IPv4 or IPv6, a single IP (<code>203.0.113.10</code>) or a subnet (<code>10.44.0.0/16</code>).</p>
      <div className="space-y-2">
        {rows.map((r, i) => (
          <div key={i} className="flex gap-2">
            <input className={cn(cls, "w-[220px] font-mono")} value={r.value} placeholder="IP or subnet" onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
            <input className={cn(cls, "min-w-0 flex-1")} value={r.note} placeholder="Why (optional)" onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, note: e.target.value } : x)))} />
            <Button size="icon" variant="ghost" aria-label="Remove" onClick={() => setRows(rows.filter((_, j) => j !== i))}><Trash2 /></Button>
          </div>
        ))}
      </div>
      <Button size="sm" className="mt-3" onClick={() => setRows([...rows, { value: "", note: "" }])}><Plus /> Add IP / subnet</Button>
    </Modal>
  );
}

const SEV = ["Info", "Low", "Medium", "High", "Critical"];
/** Ports the VA scan found open on a public IP, against the inbound Internet / ISP rules of the communication matrix. */
function ShadowTable({ data }: { data: any }) {
  const [all, setAll] = React.useState(false);
  const [rangesOpen, setRangesOpen] = React.useState(false);
  if (!data) return <Loading />;
  const rows = all ? data.rows : data.rows.filter((r: any) => r.shadow);
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 text-[12.5px] text-fg-2">
        <span className="max-w-[760px]">Public IPv4s the communication matrix does not account for: ports a VA scan found open on a public IP that no inbound rule allows,
          and public CrowdStrike connection IPs or IPs in your shadow ranges that no inbound rule covers at all. Undocumented exposure, or a matrix that is out of date.</span>
        <span className="ml-auto flex gap-1.5">
          <Button size="sm" onClick={() => setRangesOpen(true)}>Shadow ranges ({fmtN(data.ranges?.length || 0)})</Button>
          <Button size="sm" variant={all ? "soft" : "ghost"} onClick={() => setAll(!all)}>{all ? "Show shadow only" : `Show all ${fmtN(data.ports)} checked`}</Button>
        </span>
      </div>
      <SimpleTable rows={rows} maxHeight="60vh" empty="No shadow ports: every port the scanner saw on a public IP is allowed by a rule" columns={[
        { key: "ip", label: "Public IP", render: (x: any) => <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(x.internal_ip || x.ip)}`}>{x.ip}</Link> },
        { key: "asset", label: "Asset", render: (x: any) => <span>{x.asset || "–"}{x.internal_ip && <span className="ml-1 text-[11.5px] text-muted">({x.internal_ip})</span>}</span> },
        { key: "lobs", label: "LOB" },
        { key: "edr_status", label: "EDR status", render: (x: any) => <span className="flex flex-col items-start gap-0.5"><EdrBadge s={x.edr_status} />
          {(x.edr_detail || "").startsWith("matched by public IP") && <Badge tone="violet" title={x.edr_detail}>Public IP match</Badge>}
          {(x.cs_hostname || x.edr_detail) && <span className="text-[11px] text-muted">{[x.cs_hostname, x.edr_detail].filter(Boolean).join(" · ")}</span>}</span> },
        { key: "msps", label: "MSP", render: (x: any) => x.msps || <span className="text-muted">–</span> },
        { key: "port", label: "Port", render: (x: any) => x.whole_ip ? <span className="text-[12px] text-muted">whole IP{x.scanned ? "" : " · not scanned"}</span> : <b className="font-mono">{x.port}/{x.protocol}</b> },
        { key: "seen_by", label: "Seen by", render: (x: any) => <span className="text-[12px]">{x.seen_by}</span> },
        { key: "max_rank", label: "Worst open finding", render: (x: any) => x.max_rank >= 0 ? <SeverityBadge s={SEV[x.max_rank]} /> : <span className="text-muted">none open</span> },
        { key: "names", label: "Findings", wrap: true, render: (x: any) => <span className="text-[12px] text-fg-2">{x.names.join(" · ")}</span> },
        { key: "rules", label: "Allowed by", render: (x: any) => x.shadow ? <Badge tone="crit">Shadow — no rule</Badge> : <span className="text-[12px]">{x.rules}</span> },
        { key: "rules_on_ip", label: "Rules on this IP", num: true },
      ]} />
      <ListDialog kind="shadow" open={rangesOpen} onOpenChange={setRangesOpen} entries={data.ranges || []} />
    </Card>
  );
}
