"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as Popover from "@radix-ui/react-popover";
import { ArchiveRestore, Radar, SlidersHorizontal, Trash2, X } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge, Button, FilterSelect, Modal, SearchInput, useConfirm } from "./ui";
import { SimpleTable } from "./data-table";
import { DataTable, type Column } from "./data-table";
import { EdrBadge, FeasibleBadge, Mono, OsCell, SevCounts } from "./badges";

export const SRC: [string, string][] = [["inventory", "Inventory"], ["edr", "CrowdStrike"], ["scan", "VA scan"], ["niam", "NIAM"]];
const SRC_SHORT: Record<string, string> = { inventory: "INV", edr: "EDR", scan: "VA", niam: "NIAM" };

/** Four small tags: which sources know this IP. */
export function SourceTags({ sources }: { sources: string }) {
  const have = new Set((sources || "").split(","));
  return (
    <span className="inline-flex gap-1">
      {SRC.map(([k, l]) => (
        <span key={k} title={`${l}: ${have.has(k) ? "yes" : "no"}`}
          className={cn("rounded px-1.5 py-0.5 text-[10.5px] font-semibold tracking-wide",
            have.has(k) ? "bg-accent-soft text-accent-fg" : "bg-surface-3 text-muted line-through decoration-muted/60")}>{SRC_SHORT[k]}</span>
      ))}
    </span>
  );
}

export function ExposureBadge({ r }: { r: any }) {
  if (!r.exposed) return <span className="text-muted">No</span>;
  return <Badge tone="crit" title={(r.exposure || []).map((e: any) => "• " + e.text).join("\n")}>Exposed</Badge>;
}

/** labels for filters that arrive from links on other pages (coverage gaps, Overview, LOB pages) */
const LINK_KEYS: Record<string, (v: string) => string> = {
  gap: (v) => ({ edr: "EDR not installed", niam: "Not integrated", scan: "Never scanned" } as any)[v] || v,
  pending: () => "EDR not installed", coverage_status: (v) => `EDR ${v.toLowerCase()} (inventory)`, applicable: () => "EDR applicable",
  installed: () => "EDR installed", niam: (v) => (v === "1" ? "NIAM integrated" : "Not integrated"), scanned: (v) => (v === "1" ? "Scanned" : "Never scanned"),
  offline_kind: (v) => ({ console: "Offline in the console", removed: "Removed from console", import: "Old EDR import" } as any)[v] || v,
  exposure_src: (v) => `Exposed via ${v}`, edr_applicable: () => "EDR applicable (incl. EDR-only assets)",
  os_source: (v) => (v === "none" ? "OS unknown" : `OS from ${({ edr: "CrowdStrike", inventory: "inventory", scan: "VA scan" } as any)[v] || v}`),
};
const MAIN_KEYS = ["q", "has", "missing", "lob", "msp", "node_type", "edr_status", "exposed", "vulns", "feasibility"];

export function RegistryTable({ state, set, reset, fixed, storageKey = "registry", hideExposure, allowDelete }: {
  state: Record<string, string>; set: any; reset: () => void; fixed?: Record<string, string>; storageKey?: string; hideExposure?: boolean;
  allowDelete?: boolean;
}) {
  const router = useRouter();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [showDeleted, setShowDeleted] = React.useState(false);
  React.useEffect(() => setSelected(new Set()), [state.q, state.lob, state.has, state.missing]);
  const scanSelected = async () => {
    try {
      const r = await api<any>("/api/passive/scan", { method: "POST", body: { items: [...selected], source: "All inventory" } });
      toast.success(`Passive scan started · ${fmtN(r.targets)} public IP(s)${r.skipped?.length ? ` · ${fmtN(r.skipped.length)} skipped (private, no public / NAT IP)` : ""}`,
        { action: { label: "Open", onClick: () => router.push("/passive-scan/") } });
    } catch (e: any) { toast.error(e.message); }
  };
  const deleteSelected = async () => {
    const n = selected.size;
    if (!(await confirm({ title: `Delete ${fmtN(n)} row${n > 1 ? "s" : ""}?`, danger: true, ok: "Delete",
      body: <>Rows that come from a LOB inventory are <b>removed from that inventory</b> (current version; logged in the item history as removed by hand).
        Every selected row leaves All inventory and every count. Rows CrowdStrike, a VA scan or NIAM still report stay hidden until you restore them from
        <b> Deleted rows</b>. The next inventory upload adds a removed node back if it is in the file.</> }))) return;
    try {
      const r = await api<any>("/api/registry/delete", { method: "POST", body: { keys: [...selected] } });
      toast.success(r.message);
      setSelected(new Set());
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); }
  };
  const { data: meta } = useMeta();
  const { data: sum } = useQuery({ queryKey: ["registry-summary"], queryFn: () => api<any>("/api/registry/summary") });
  const count = (k: string) => (sum ? ` (${fmtN(sum[k] || 0)})` : "");
  const msps = (meta?.msps || []).filter((m) => !state.lob || String(m.lob_id) === state.lob);
  const lobName = (id: number) => meta?.lobs.find((l) => l.id === id)?.name || "";
  const linkPills = Object.keys(LINK_KEYS).filter((k) => state[k]);
  const anyActive = linkPills.length + MAIN_KEYS.filter((k) => state[k]).length > 0;
  const moreCount = ["missing", "msp", "node_type", "feasibility", "edr_status", "vulns"].filter((k) => state[k]).length;
  const cols: Column[] = [
    { key: "ip", label: "IP", render: (r) => r.ip ? <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/ip-search/?q=${encodeURIComponent(r.ip)}`}>{r.ip}</Link> : <span className="text-muted">no IP</span> },
    { key: "name", label: "Name", render: (r) => <b>{r.name || <span className="font-normal text-muted">–</span>}</b> },
    ...(hideExposure ? [] : [{ key: "sources", label: "Sources", render: (r: any) => <SourceTags sources={r.sources} /> }]),
    { key: "lobs", label: "LOB", render: (r) => r.lobs || <span className="text-muted">Not in inventory</span> },
    { key: "msps", label: "MSP", render: (r) => r.msps || "" },
    { key: "node_type", label: "Node type", sort: false },
    { key: "os", label: "OS", render: (r) => <OsCell os={r.os} src={r.os_source} /> },
    { key: "feasibility", label: "EDR feasible", render: (r) => <FeasibleBadge v={r.feasibility} reason={r.feasibility_reason} /> },
    { key: "edr_status", label: "CrowdStrike", render: (r) => (
      <span className="inline-flex items-center gap-1.5"><EdrBadge s={r.edr_status} />{r.edr_detail && r.edr_detail !== "in console" && <span className="text-[11px] text-muted">{r.edr_detail}</span>}</span>) },
    { key: "last_scan", label: "VA scan", render: (r) => r.in_scan ? <span>{fmtDt(r.last_scan).slice(0, 10)}</span> : <span className="text-muted">Not scanned</span> },
    { key: "crit", label: "Crit / High / Med / Low", render: (r) => r.in_scan ? <SevCounts c={r.crit} h={r.high} m={r.med} l={r.low} /> : null },
    { key: "ne_ids", label: "NIAM", sort: false, render: (r) => r.in_niam ? <span className="text-xs">{r.ne_ids || "Yes"}</span> : <span className="text-muted">No</span> },
    ...(hideExposure ? [] : [{ key: "exposed", label: "Internet", render: (r: any) => <ExposureBadge r={r} /> }]),
    { key: "exposed_by", label: "Exposed by", sort: false, hidden: !hideExposure, render: (r) => {
      const by = Array.from(new Set((r.exposure || []).filter((e: any) => e.src !== "indirect").map((e: any) => e.where || e.src))) as string[];
      const tone = (w: string) => w.startsWith("Inventory") ? "info" : w.startsWith("Matrix") ? "violet" : w.startsWith("Manual") || w.startsWith("Marked") ? "warn" : w === "VA scan" ? "serious" : "neutral";
      const all = (r.exposure || []).map((e: any) => "• " + e.text).join("\n");
      return <span className="flex items-center gap-1 whitespace-nowrap" title={all}>{by.slice(0, 2).map((w) => <Badge key={w} tone={tone(w) as any}>{w}</Badge>)}
        {by.length > 2 && <span className="text-[11px] text-muted">+{by.length - 2}</span>}</span>;
    } },
    { key: "public_ips", label: "Public / NAT IP", sort: false, hidden: !hideExposure, render: (r) => <Mono>{r.public_ips || r.nat_of ? r.public_ips || `NAT of ${r.nat_of}` : ""}</Mono> },
    { key: "exposure", label: "Exposure evidence", sort: false, wrap: true, hidden: true, render: (r) => (
      <ul className="space-y-0.5 text-[12px]">{(r.exposure || []).map((e: any) => <li key={e.text}><Badge tone="outline" className="mr-1 text-[10px]">{e.src}</Badge>{e.text}</li>)}</ul>) },
    { key: "cs_hostname", label: "CrowdStrike hostname", sort: false, hidden: true },
    { key: "live", label: "Live / Non Live", sort: false, hidden: true },
  ];
  return (
    <>
    <DataTable endpoint="/api/registry" exportPath="/api/registry/export" columns={cols} state={state} setState={set} fixed={fixed}
      selected={allowDelete ? selected : undefined} onSelectedChange={allowDelete ? setSelected : undefined}
      toolbar={allowDelete ? <>
        {selected.size > 0 && <>
          <span className="text-[12.5px] text-fg-2"><b>{fmtN(selected.size)}</b> selected</span>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
          <Button size="sm" variant="soft" onClick={scanSelected}><Radar /> Passive scan</Button>
          <Button size="sm" variant="danger" onClick={deleteSelected}><Trash2 /> Delete selected</Button>
        </>}
        <Button size="sm" variant="ghost" onClick={() => setShowDeleted(true)}><ArchiveRestore /> Deleted rows</Button>
      </> : undefined}
      storageKey={storageKey} noun="assets" rowKey={(r: any) => r.asset_key} onReset={reset}
      onRowClick={(r: any) => r.ip && router.push(`/ip-search/?q=${encodeURIComponent(r.ip)}`)}
      filters={
        <div className="flex w-full flex-wrap items-center gap-2">
          <SearchInput className="w-[300px] max-w-full" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP, CIDR, name, NE ID… (paste many)" />
          <FilterSelect label="Found in" value={state.has} onChange={(v) => set({ has: v })} any="Any source"
            options={[["inventory", `LOB inventory${count("inventory")}`], ["edr", `CrowdStrike${count("edr")}`], ["scan", `VA scan${count("scan")}`], ["niam", `NIAM${count("niam")}`]]} />
          <FilterSelect label="LOB" value={state.lob} onChange={(v) => set({ lob: v, msp: undefined })} any="All" options={(meta?.lobs || []).map((l) => ({ value: l.id, label: l.name }))} />
          {!hideExposure && <FilterSelect label="Internet" value={state.exposed} onChange={(v) => set({ exposed: v })} any="Any" options={[["1", `Exposed${count("exposed")}`], ["0", "Not exposed"]]} />}
          <Popover.Root>
            <Popover.Trigger asChild>
              <Button size="sm" variant={moreCount ? "soft" : "default"}><SlidersHorizontal /> More filters{moreCount > 0 && <Badge tone="info" className="ml-0.5">{moreCount}</Badge>}</Button>
            </Popover.Trigger>
            <Popover.Portal>
              <Popover.Content align="start" sideOffset={6} className="z-50 w-[520px] max-w-[95vw] rounded-xl border border-border bg-surface p-3 shadow-xl">
                <div className="grid grid-cols-2 gap-2 [&_button]:w-full [&_button]:justify-between">
                  <FilterSelect label="Missing from" value={state.missing} onChange={(v) => set({ missing: v })} any="Nothing"
                    options={[["inventory", `Inventory${count("not_in_inventory")}`], ["edr", "CrowdStrike"], ["scan", "VA scan"], ["niam", `NIAM${count("not_in_niam")}`], ["inventory|niam", "Inventory and NIAM"]]} />
                  <FilterSelect label="MSP" value={state.msp} onChange={(v) => set({ msp: v })} any="All"
                    options={msps.map((x) => ({ value: x.id, label: state.lob ? x.name : `${x.name} · ${lobName(x.lob_id)}` }))} />
                  <FilterSelect label="Node type" value={state.node_type} onChange={(v) => set({ node_type: v })} any="All" options={meta?.node_types || []} />
                  <FilterSelect label="EDR feasible" value={state.feasibility} onChange={(v) => set({ feasibility: v })} any="Any"
                    options={[["Yes", "Feasible"], ["No", `Not feasible${count("not_feasible")}`], ["To be decided", `To be decided${count("to_be_decided")}`], ["Unidentified", `Unidentified${count("unidentified")}`]]} />
                  <FilterSelect label="CrowdStrike" value={state.edr_status} onChange={(v) => set({ edr_status: v })} any="Any" options={[["Online", "Online"], ["Offline", "Offline (incl. EDR history)"], ["Not Installed", "No agent"]]} />
                  <FilterSelect label="Vulnerabilities" value={state.vulns} onChange={(v) => set({ vulns: v })} any="Any"
                    options={[["crit_high", "Critical / high open"], ["any", "Any open finding"], ["none", "Scanned, nothing open"]]} />
                </div>
              </Popover.Content>
            </Popover.Portal>
          </Popover.Root>
          {linkPills.map((k) => (
            <Badge key={k} tone="info" className="gap-1">{LINK_KEYS[k](state[k])}
              <button onClick={() => set({ [k]: undefined })}><X className="size-3" /></button></Badge>
          ))}
          {anyActive && <Button size="sm" variant="ghost" onClick={() => set(Object.fromEntries([...MAIN_KEYS, ...Object.keys(LINK_KEYS)].map((k) => [k, undefined])))}><X /> Clear all</Button>}
        </div>
      } />
    {showDeleted && <DeletedRows onClose={() => setShowDeleted(false)} />}
    </>
  );
}

/** Rows deleted from All inventory, with restore. */
function DeletedRows({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { data, refetch } = useQuery({ queryKey: ["registry-deleted"], queryFn: () => api<any>("/api/registry/deleted") });
  const [sel, setSel] = React.useState<Set<string>>(new Set());
  const restore = async (keys: string[]) => {
    try {
      await api("/api/registry/restore", { method: "POST", body: { keys } });
      toast.success(`${fmtN(keys.length)} row(s) restored · they come back as their sources still report them`);
      setSel(new Set());
      refetch();
      qc.invalidateQueries();
    } catch (e: any) { toast.error(e.message); }
  };
  const rows = data?.rows || [];
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} wide title={`Deleted rows (${fmtN(rows.length)})`}
      footer={<><Button onClick={onClose}>Close</Button><Button variant="primary" disabled={!sel.size} onClick={() => restore([...sel])}><ArchiveRestore /> Restore {sel.size ? fmtN(sel.size) : ""}</Button></>}>
      <div className="mb-2 text-[12.5px] text-muted">Restoring shows a row again where CrowdStrike, a VA scan or NIAM still report it. Inventory rows that were removed are not re-created:
        re-upload the inventory or restore a version on the LOB page.</div>
      <SimpleTable rows={rows} maxHeight="55vh" empty="Nothing deleted" columns={[
        { key: "sel", label: "", render: (r: any) => <input type="checkbox" checked={sel.has(r.asset_key)} onChange={(e) => { const n = new Set(sel); e.target.checked ? n.add(r.asset_key) : n.delete(r.asset_key); setSel(n); }} /> },
        { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip || r.asset_key}</Mono> }, { key: "name", label: "Name" },
        { key: "hidden_at", label: "Deleted", render: (r: any) => fmtDt(r.hidden_at) }, { key: "hidden_by", label: "By" },
      ]} />
    </Modal>
  );
}
