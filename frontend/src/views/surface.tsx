"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Globe2, Info, Radar, Settings2 } from "lucide-react";
import { api } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtN, fmtRel } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, Callout, Card, CardHeader, FilterSelect, Input, Kpi, KpiGrid, Loading, Modal, PageHeader, SearchInput, Spinner, Tabs } from "@/components/ui";
import { DataTable, SimpleTable, type Column } from "@/components/data-table";
import { EdrBadge, Mono } from "@/components/badges";
import { CveChips, PortChips } from "./passive-scan";
import { ClassBadge, ClassifyBar, WhoisCell, WhoisFilters } from "@/components/whois";

const SOURCE_HELP: Record<string, string> = {
  inventory: "an LOB inventory row has this public IP (its own IP, or the Public / NAT IP column)",
  matrix: "the communication matrix has it: destination / source NAT, a NAT pool, the IP register, or a public destination of our rules",
  crowdstrike: "a CrowdStrike agent's connection IP is this public IP",
  "va scan": "a VA scan covered this public IP",
  passive: "an Internet DB (passive) scan looked it up — delete the scan on the Internet DB scan page to remove it",
  "your ranges": "inside a public range you listed under Your ranges & ASNs",
};

const LINK = (ip: string) => `https://www.shodan.io/search?query=${encodeURIComponent(ip)}`;

/** Internet attack surface: every public IP we know, grouped by /24 and by the BGP prefix that advertises it. */
export default function Surface() {
  const qc = useQueryClient();
  const [state, set, replaceAll] = useUrlState();
  const tab = state.tab || "ips";
  const [cfg, setCfg] = React.useState(false);
  const [how, setHow] = React.useState(false);
  const [sel, setSel] = React.useState<Set<string>>(new Set());
  const [total, setTotal] = React.useState(0);
  const bits = state.bits || "24";
  const { data, error, refetch } = useQuery({ queryKey: ["surface", bits], queryFn: () => api<any>("/api/surface", { params: { bits } }),
    refetchInterval: (q) => ((q.state.data as any)?.job?.running ? 1500 : false) });
  const pst = useQuery({ queryKey: ["passive-status"], queryFn: () => api<any>("/api/passive/status"),
    refetchInterval: (q) => ((q.state.data as any)?.job?.running ? 1200 : false) });
  const was = React.useRef(false);
  React.useEffect(() => {
    const r = !!pst.data?.job?.running || !!data?.job?.running;
    if (was.current && !r) { qc.invalidateQueries({ queryKey: ["surface"] }); qc.invalidateQueries({ queryKey: ["/api/surface/ips"] }); }
    was.current = r;
  }, [pst.data, data, qc]);
  if (!data) return <Loading error={error} retry={() => refetch()} />;
  const s = data.summary, job = data.job, pjob = pst.data?.job;
  const run = async (path: string, body: any, ok: string) => {
    try { const r = await api<any>(path, { method: "POST", body }); toast.success(`${ok}${r.targets ? ` · ${fmtN(r.targets)} IPs` : r.total ? ` · ${fmtN(r.total)}` : ""}`); refetch(); pst.refetch(); }
    catch (e: any) { toast.error(e.message); }
  };
  const ipCols: Column[] = [
    { key: "ip", label: "Public IP", render: (r) => <span className="flex items-center gap-1.5"><Link className="font-mono text-[12.5px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.asset_ip || r.ip)}`}>{r.ip}</Link>
      <a className="text-[10.5px] text-muted hover:text-accent-fg" href={LINK(r.ip)} target="_blank" rel="noopener noreferrer" title="Open in Shodan">Shodan↗</a></span> },
    { key: "name", label: "Asset", render: (r) => <span>{r.name || <span className="text-muted">unknown</span>}{r.asset_ip && <span className="block font-mono text-[11px] text-muted">behind NAT: {r.asset_ip}</span>}</span> },
    { key: "lobs", label: "LOB", render: (r) => r.lobs || <span className="text-muted">–</span> },
    { key: "sources", label: "Known from", render: (r) => <span className="flex flex-wrap gap-1">{r.sources.map((x: string) => <Badge key={x} tone="neutral" title={SOURCE_HELP[x]}>{x}</Badge>)}</span> },
    { key: "prefix", label: "Advertised prefix", render: (r) => r.prefix ? <span><Mono>{r.prefix}</Mono>{r.asn && <span className="block text-[11px] text-muted">AS{r.asn} {r.holder}</span>}</span> : <span className="text-muted">–</span> },
    { key: "ports", label: "Open ports", wrap: true, render: (r) => r.scanned ? <PortChips ports={r.ports} /> : <span className="text-muted">not scanned</span> },
    { key: "vulns", label: "CVEs", wrap: true, render: (r) => r.scanned ? <CveChips vulns={r.vulns} /> : <span className="text-muted">–</span> },
    { key: "whois", label: "WHOIS", wrap: true, render: (r) => <WhoisCell r={r} /> },
    { key: "cls", label: "Class", render: (r) => <ClassBadge c={r.cls} /> },
    { key: "gn", label: "GreyNoise", render: (r) => r.gn_noise ? <Badge tone="crit">seen scanning</Badge> : r.gn_riot ? <Badge tone="info">benign service</Badge> : <span className="text-muted">–</span> },
    { key: "edr_status", label: "EDR", hidden: true, render: (r) => <EdrBadge s={r.edr_status} /> },
  ];
  const groupCols = (label: string, onPick: (k: string) => void, withScan?: boolean): Column[] => [
    { key: "key", label, render: (g) => <button className="font-mono text-[12.5px] text-accent-fg hover:underline" onClick={() => onPick(g.key)}>{g.key}</button> },
    { key: "holder", label: "Holder", render: (g) => g.asn ? <span className="text-[12px]">AS{g.asn} {g.holder}</span> : <span className="text-muted">–</span> },
    { key: "block", label: "Registered block", wrap: true, render: (g) => g.block_name ? <span className="flex max-w-[240px] flex-col" title={[g.block_org, g.block_country, g.block_range].filter(Boolean).join(" · ")}>
      <b className="truncate text-[12px]">{g.block_name}</b><span className="line-clamp-2 text-[11.5px] text-fg-2">{g.block_descr || g.block_org}</span>
      {g.block_range && <span className="font-mono text-[10.5px] text-muted">{g.block_range}</span>}</span> : <span className="text-[11.5px] text-muted">not looked up</span> },
    { key: "whois_name", label: "WHOIS of its IPs", wrap: true, render: (g) => g.whois_name ? <span className="flex max-w-[260px] flex-col"><b className="truncate text-[12px]">{g.whois_name}</b>
      {(g.whois_descr || g.whois_org) && <span className="line-clamp-2 text-[11.5px] text-fg-2">{g.whois_descr || g.whois_org}</span>}</span> : <span className="text-[11.5px] text-muted">not looked up</span> },
    { key: "ips", label: "Known public IPs", num: true }, { key: "assets", label: "Assets", num: true },
    { key: "cls", label: "Enterprise", render: (g) => (g.enterprise || g.non_enterprise) ? <span className="text-[12px]"><b className="text-good-fg">{g.enterprise}</b> / <span className="text-muted">{g.non_enterprise} non</span></span> : <span className="text-[11.5px] text-muted">unmarked</span> },
    { key: "lobs", label: "LOB", wrap: true, render: (g) => <span className="text-[12px]">{g.lobs || "–"}</span> },
    { key: "scanned", label: "Scanned", num: true, render: (g) => <span className={g.scanned < g.ips ? "text-warn-fg" : ""}>{g.scanned} / {g.ips}</span> },
    { key: "with_ports", label: "Open ports", num: true, render: (g) => g.with_ports ? <b className="text-crit-fg">{g.with_ports}</b> : "0" },
    { key: "with_cves", label: "With CVEs", num: true, render: (g) => g.with_cves ? <b className="text-crit-fg">{g.with_cves}</b> : "0" },
    ...(withScan ? [{ key: "scan", label: "", render: (g: any) => g.key.includes("/") && <Button size="sm" variant="ghost" onClick={() => run("/api/surface/scan", { scope: "prefix", prefix: g.key }, `Scanning ${g.key}`)}><Radar /> Scan</Button> } as Column] : []),
  ];
  return (
    <div>
      <PageHeader title="Attack surface"
        sub="Every public IP the console knows (inventory, communication matrix, CrowdStrike, VA scans, passive scans and your own ranges), grouped by /24 and by the BGP prefix that advertises it, with what the internet sees on each."
        actions={<>
          <Button onClick={() => setCfg(true)}><Settings2 /> Your ranges & ASNs</Button>
          <Button onClick={() => run("/api/surface/enrich", { only_new: true }, "Looking up prefixes and GreyNoise")} disabled={job.running}><Globe2 /> Look up prefixes & WHOIS</Button>
          <Button variant="primary" onClick={() => run("/api/surface/scan", { scope: "known" }, "Internet DB scan started")} disabled={pjob?.running}><Radar /> Scan all public IPs</Button>
        </>} />
      {data.demo && <Callout tone="info" className="mb-4">Sample data mode: InternetDB, RIPEstat and GreyNoise answers are simulated.</Callout>}
      {(job.running || pjob?.running) && (
        <Card className="mb-4 flex items-center gap-3 p-3 text-[12.5px]">
          <Spinner className="size-4" />
          {pjob?.running ? <span>Internet DB scan · {fmtN(pjob.done)} of {fmtN(pjob.total)}</span> : <span>{job.kind} · {fmtN(job.done)} of {fmtN(job.total)}</span>}
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-3"><div className="h-full bg-accent transition-all" style={{ width: `${(100 * (pjob?.running ? pjob.done / Math.max(1, pjob.total) : job.done / Math.max(1, job.total)))}%` }} /></div>
        </Card>
      )}
      <KpiGrid className="mb-3 grid-cols-[repeat(auto-fill,minmax(160px,1fr))]">
        <Kpi label="Public IPs known" value={s.ips} tone="info" foot={`${fmtN(s.subnets)} /24 subnets · ${fmtN(s.prefixes)} advertised prefixes`} active={!state.show} onClick={() => replaceAll({ tab: "ips" })} />
        <Kpi label="Not scanned yet" value={s.ips - s.scanned} tone="warn" foot="no Internet DB lookup" active={state.show === "unscanned"} onClick={() => replaceAll({ tab: "ips", show: "unscanned" })} />
        <Kpi label="Open ports seen" value={s.with_ports} tone="crit" foot="by the internet (InternetDB)" active={state.show === "ports"} onClick={() => replaceAll({ tab: "ips", show: "ports" })} />
        <Kpi label="With known CVEs" value={s.with_cves} tone="serious" active={state.show === "cves"} onClick={() => replaceAll({ tab: "ips", show: "cves" })} />
        <Kpi label="Seen scanning the internet" value={s.noisy} tone="crit" foot="GreyNoise" active={state.show === "noisy"} onClick={() => replaceAll({ tab: "ips", show: "noisy" })} />
        <Kpi label="Enterprise" value={s.enterprise} tone="good" foot={`${fmtN(s.non_enterprise)} non-enterprise · ${fmtN(s.ips - s.enterprise - s.non_enterprise)} unmarked`} active={state.cls === "enterprise"} onClick={() => replaceAll({ tab: "ips", cls: "enterprise" })} />
        <Kpi label="Advertised, unknown" value={s.adv_unknown} tone="violet" foot={`of ${fmtN(s.adv_prefixes)} prefixes your ASNs announce`} active={tab === "advertised"} onClick={() => replaceAll({ tab: "advertised" })} />
      </KpiGrid>
      <Card className="mb-4">
        <button className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-[12.5px] font-medium" onClick={() => setHow(!how)}>
          <Info className="size-4 text-accent-fg" /> How the surface is built and scanned <span className="ml-auto text-muted">{how ? "hide" : "show"}</span></button>
        {how && (
          <div className="grid gap-4 border-t border-border px-4 py-3 text-[12.5px] text-fg-2 md:grid-cols-3">
            <div><b className="text-fg">Known public IPs</b> come from inventory (own IP or Public / NAT IP column), the communication matrix (NAT, pool, register, public destinations),
              CrowdStrike public connection IPs, VA scans of public IPs, earlier passive scans and the ranges you add.</div>
            <div><b className="text-fg">Advertised prefixes</b> come from RIPEstat (free, global BGP data): the prefix and origin ASN of each IP. Mark the ASNs that are yours and the page lists every
              prefix they announce; prefixes with no known IP are space nobody has inventoried. ISP-provided IPs show the ISP's ASN, so only mark your own.</div>
            <div><b className="text-fg">Scans are passive</b>: Shodan InternetDB returns ports / CVEs already recorded by internet-wide scanning, GreyNoise says if an IP is seen scanning the internet.
              Nothing is sent to your assets; only the public IP is sent to these services. A whole advertised prefix (up to /20) can be scanned to find exposed IPs you did not know.</div>
          </div>
        )}
      </Card>
      <Tabs value={tab} onChange={(v) => replaceAll({ tab: v })} tabs={[
        { id: "ips", label: "Public IPs", count: s.ips }, { id: "subnets", label: `By /${data.bits} subnet`, count: data.subnets.length },
        { id: "prefixes", label: "By advertised prefix", count: s.prefixes }, { id: "asns", label: "ASNs", count: s.asns },
        { id: "advertised", label: job.running && job.kind.includes("advertised") ? "Advertised by your ASNs · fetching…" : "Advertised by your ASNs", count: s.adv_prefixes }]} />
      {tab === "ips" && (
        <>
        <ClassifyBar universe="surface" selected={sel} onDone={() => setSel(new Set())} />
        <DataTable endpoint="/api/surface/ips" exportPath="/api/surface/ips/export" state={state} setState={set} omit={["tab"]} noun="public IPs" storageKey="surface"
          rowKey={(r: any) => r.ip} onReset={() => replaceAll({ tab })} sortable={false} columns={ipCols} selected={sel} onSelectedChange={setSel}
          onData={(d: any) => setTotal(d.total)}
          filters={<>
            <SearchInput className="w-72" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, asset, LOB, holder, CVE…" />
            <FilterSelect single label="Show" value={state.show} onChange={(v) => set({ show: v })} any="All"
              options={[["unscanned", "Not scanned"], ["ports", "Open ports"], ["cves", "Known CVEs"], ["noisy", "Seen scanning"], ["exposed", "Marked exposed"]]} />
            <WhoisFilters facetsPath="/api/surface/whois-facets" state={state} set={set} />
            {(state.subnet || state.prefix || state.asn) && <Badge tone="info">{state.subnet || state.prefix || `AS${state.asn}`}
              <button className="ml-1" onClick={() => set({ subnet: undefined, prefix: undefined, asn: undefined })}>×</button></Badge>}
          </>} />
        </>
      )}
      {tab === "subnets" && <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-2.5 text-[12.5px]">
          <FilterSelect single label="Group public IPs by" value={bits} onChange={(v) => set({ bits: !v || v === "24" ? undefined : v })}
            options={["16", "20", "22", "23", "24", "25", "26", "27", "28", "29", "30"].map((b) => [b, `/${b}`])} />
          <span className="text-muted">Registered block = the WHOIS record that holds the subnet (looked up with “Look up prefixes & WHOIS”); WHOIS of its IPs = what its known IPs are registered as.</span>
        </div>
        <SimpleTable rows={data.subnets} maxHeight="65vh" columns={groupCols(`/${data.bits} subnet`, (k) => replaceAll({ tab: "ips", subnet: k }), true)} /></Card>}
      {tab === "prefixes" && <Card>{!s.looked_up ? <div className="p-6 text-[13px] text-muted">Prefixes are not looked up yet: use <b>Look up prefixes</b>.</div>
        : <SimpleTable rows={data.prefixes} maxHeight="65vh" columns={groupCols("Advertised prefix", (k) => replaceAll({ tab: "ips", prefix: k }), true)} />}</Card>}
      {tab === "asns" && <Card><SimpleTable rows={data.asns} empty="Look up prefixes first" columns={[
        { key: "asn", label: "ASN", render: (a: any) => <button className="font-mono text-accent-fg hover:underline" onClick={() => replaceAll({ tab: "ips", asn: a.asn })}>AS{a.asn}</button> },
        { key: "holder", label: "Holder" }, { key: "ips", label: "Known public IPs", num: true },
        { key: "ours", label: "Yours?", render: (a: any) => a.ours ? <Badge tone="good">yours</Badge> : <span className="text-muted">mark under Your ranges & ASNs</span> },
      ]} /></Card>}
      {tab === "advertised" && (
        <Card>
          <CardHeader title="Prefixes your ASNs announce"
            hint={data.our_asns.length ? `ASNs: ${data.our_asns.map((a: string) => `AS${a}`).join(", ")} · fetched from RIPEstat automatically when you add an ASN, refreshed weekly` : "mark your ASNs first"}
            right={<Button size="sm" variant="ghost" disabled={!data.our_asns.length || job.running} onClick={() => run("/api/surface/advertised", {}, "Refreshing advertised prefixes")}>Refresh now</Button>} />
          <SimpleTable rows={data.advertised} maxHeight="60vh" empty={data.our_asns.length ? "Not fetched yet: Refresh from RIPEstat" : "Mark the ASNs that are yours (Your ranges & ASNs)"} columns={[
            { key: "prefix", label: "Prefix", render: (a: any) => <Mono>{a.prefix}</Mono> }, { key: "asn", label: "ASN", render: (a: any) => `AS${a.asn}` },
            { key: "whois_name", label: "WHOIS", wrap: true, render: (a: any) => a.whois_name ? <span className="flex max-w-[260px] flex-col"><b className="text-[12px]">{a.whois_name}</b>
              {(a.whois_descr || a.whois_org) && <span className="line-clamp-2 text-[11.5px] text-fg-2">{a.whois_descr || a.whois_org}</span>}</span> : <span className="text-[11.5px] text-muted">–</span> },
            { key: "size", label: "Addresses", num: true, render: (a: any) => fmtN(a.size) },
            { key: "known", label: "Known public IPs", num: true, render: (a: any) => a.known ? fmtN(a.known) : <Badge tone="violet">none — unknown space</Badge> },
            { key: "scanned", label: "Scanned", num: true }, { key: "with_ports", label: "Open ports", num: true },
            { key: "scan", label: "", render: (a: any) => a.size <= 4096 ? <Button size="sm" variant="ghost" onClick={() => run("/api/surface/scan", { scope: "prefix", prefix: a.prefix }, `Scanning ${a.prefix}`)}><Radar /> Scan prefix</Button>
              : <span className="text-[11px] text-muted">larger than /20: scan smaller parts</span> },
          ]} />
        </Card>
      )}
      {cfg && <SurfaceSettings data={data} onClose={(fetching?: boolean) => { setCfg(false); refetch(); if (fetching) replaceAll({ tab: "advertised" }); }} />}
    </div>
  );
}

function SurfaceSettings({ data, onClose }: { data: any; onClose: (fetching?: boolean) => void }) {
  const [asns, setAsns] = React.useState<string>((data.our_asns || []).map((a: string) => `AS${a}`).join(", "));
  const [ranges, setRanges] = React.useState<string>((data.ranges || []).map((r: any) => r.value + (r.note ? ` # ${r.note}` : "")).join("\n"));
  const [busy, setBusy] = React.useState(false);
  const save = async () => {
    setBusy(true);
    try {
      const r = await api<any>("/api/surface/settings", { method: "PUT", body: {
        asns: asns.split(/[\s,;]+/).filter(Boolean),
        ranges: ranges.split("\n").map((l: string) => l.trim()).filter(Boolean).map((l: string) => { const [v, ...n] = l.split("#"); return { value: v.trim(), note: n.join("#").trim() }; }) } });
      toast.success(r.fetching?.length ? `Saved · fetching the prefixes ${r.fetching.map((a: string) => `AS${a}`).join(", ")} announce from RIPEstat${r.queued ? " (after the current lookup)" : ""}` : "Saved");
      onClose(!!r.fetching?.length);
    } catch (e: any) { toast.error(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title="Your public ranges and ASNs"
      footer={<><Button onClick={() => onClose()}>Cancel</Button><Button variant="primary" loading={busy} onClick={save}>Save</Button></>}>
      <div className="space-y-4 text-[13px]">
        <label className="block">
          <div className="mb-1 font-medium">ASNs that are yours</div>
          <Input className="w-full" value={asns} onChange={(e) => setAsns(e.target.value)} placeholder="e.g. AS9498, AS24560" />
          <div className="mt-1 text-[11.5px] text-muted">On save, the prefixes they announce are fetched from RIPEstat automatically and listed under “Advertised by your ASNs”. Do not add your ISP's ASN if your IPs are ISP-provided. Known ASNs: {data.asns.map((a: any) => `AS${a.asn} (${a.holder})`).join(", ") || "look up prefixes first"}</div>
        </label>
        <label className="block">
          <div className="mb-1 font-medium">Your public ranges (one per line, optional “# note”)</div>
          <textarea className="h-36 w-full rounded-lg border border-border-strong bg-surface p-2 font-mono text-[12.5px]" value={ranges} onChange={(e) => setRanges(e.target.value)}
            placeholder={"203.0.113.0/26 # DC-1 internet edge\n198.51.100.10-20"} />
          <div className="mt-1 text-[11.5px] text-muted">Each address in a range of up to 256 IPs becomes a known public IP (bigger ranges: scan them as a prefix).</div>
        </label>
      </div>
    </Modal>
  );
}
