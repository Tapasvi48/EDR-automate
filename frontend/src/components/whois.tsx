"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import * as Pop from "@radix-ui/react-popover";
import { Building2 } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { Badge, Button, FilterSelect, SearchInput, useConfirm } from "@/components/ui";

const DETAIL: [string, string][] = [["whois_name", "Name"], ["whois_descr", "Description"], ["whois_org", "Organisation"], ["whois_range", "Range"],
  ["whois_country", "Country"], ["whois_rir", "Registry"], ["whois_net_type", "Type"], ["whois_status", "Status"], ["whois_emails", "Emails"],
  ["whois_abuse", "Abuse contact"], ["whois_phones", "Phones"], ["whois_address", "Address"], ["whois_contacts", "Contacts"],
  ["whois_registered", "Registered"], ["whois_changed", "Last changed"], ["whois_parent", "Parent block"], ["whois_remarks", "Remarks"]];

/** WHOIS of a public IP: registered name, description, organisation; click for the full record (emails, contacts, address…). */
export function WhoisCell({ r }: { r: any }) {
  if (!r.whois_name && !r.whois_org) return <span className="text-[11.5px] text-muted" title={r.whois_error || ""}>{r.whois_error ? "no WHOIS answer" : "not looked up"}</span>;
  return (
    <Pop.Root>
      <Pop.Trigger asChild>
        <button type="button" onClick={(e) => e.stopPropagation()} className="flex max-w-[280px] flex-col text-left hover:opacity-80">
          <span className="truncate text-[12px] font-semibold">{r.whois_name}</span>
          {r.whois_descr && <span className="line-clamp-2 text-[11.5px] text-fg-2">{r.whois_descr}</span>}
          {r.whois_org && r.whois_org !== r.whois_descr && <span className="truncate text-[11px] text-muted">{r.whois_org}{r.whois_country ? ` · ${r.whois_country}` : ""}</span>}
        </button>
      </Pop.Trigger>
      <Pop.Portal>
        <Pop.Content align="start" sideOffset={6} collisionPadding={10} onClick={(e) => e.stopPropagation()}
          className="z-50 max-h-[70vh] w-[420px] max-w-[92vw] overflow-auto rounded-xl border border-border bg-surface p-3 shadow-xl">
          <div className="mb-2 text-[12px] font-semibold">WHOIS · {r.ip}</div>
          <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]">
            {DETAIL.filter(([k]) => r[k]).map(([k, l]) => <React.Fragment key={k}><dt className="text-muted">{l}</dt><dd className="break-words">{String(r[k])}</dd></React.Fragment>)}
          </dl>
          <div className="mt-2 text-[11px] text-muted">From RDAP (rdap.org → the regional registry).</div>
        </Pop.Content>
      </Pop.Portal>
    </Pop.Root>
  );
}

export function ClassBadge({ c }: { c?: string | null }) {
  if (c === "enterprise") return <Badge tone="good">enterprise</Badge>;
  if (c === "non-enterprise") return <Badge tone="neutral">non-enterprise</Badge>;
  return <span className="text-[11.5px] text-muted">unmarked</span>;
}

/** WHOIS name / WHOIS text / enterprise filters for a DataTable. */
export function WhoisFilters({ facetsPath, state, set }: { facetsPath: string; state: Record<string, string>; set: (p: Record<string, string | undefined>) => void }) {
  const { data } = useQuery({ queryKey: [facetsPath], queryFn: () => api<any>(facetsPath) });
  const opts = (data?.rows || []).map((f: any) => [f.name, `${f.name} (${fmtN(f.n)})${f.descr ? ` — ${f.descr}` : f.org ? ` — ${f.org}` : ""}`.slice(0, 90)] as [string, string]);
  return <>
    <FilterSelect label="WHOIS" value={state.whois} onChange={(v) => set({ whois: v })} any="All" options={opts} />
    <SearchInput className="w-56" value={state.wq || ""} onChange={(v) => set({ wq: v })} placeholder="WHOIS description / org…" />
    <FilterSelect label="Class" value={state.cls} onChange={(v) => set({ cls: v })} any="All"
      options={[["enterprise", "Enterprise"], ["non-enterprise", "Non-enterprise"], ["none", "Unmarked"]]} />
  </>;
}

/** Mark the selected IPs (tick rows, or "Select all N matching" above the table after filtering) as enterprise /
 *  non-enterprise, and optionally every other IP that has no mark yet as non-enterprise. */
export function ClassifyBar({ universe, selected, onDone }: { universe: "surface" | "passive"; selected: Set<string>; onDone: () => void }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [busy, setBusy] = React.useState("");
  const ips = [...selected];
  const go = async (key: string, body: any) => {
    if (body.others && !(await confirm({ title: "Mark every other unmarked IP as non-enterprise?", body: `The ${fmtN(ips.length)} selected IPs and IPs that already have a mark are left as they are.`, ok: "Mark" }))) return;
    setBusy(key);
    try {
      const r = await api<any>("/api/whois/class", { method: "POST", body });
      toast.success(`${fmtN(r.marked)} IPs ${body.class ? `marked ${body.class}` : "cleared"}`);
      qc.invalidateQueries(); if (!body.others) onDone();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  return (
    <div className="mb-2 flex flex-wrap items-center gap-1.5 rounded-xl border border-border bg-surface px-3 py-2 text-[12.5px]">
      <Building2 className="size-4 text-muted" /><span className="mr-1 font-medium">Mark</span>
      {ips.length === 0 ? <span className="text-muted">tick IPs in the table (filter, then “Select all … matching”) to mark them enterprise or non-enterprise</span> : <>
        <span className="text-fg-2">{fmtN(ips.length)} selected as</span>
        <Button size="sm" loading={busy === "e"} onClick={() => go("e", { ips, class: "enterprise" })}>Enterprise</Button>
        <Button size="sm" loading={busy === "n"} onClick={() => go("n", { ips, class: "non-enterprise" })}>Non-enterprise</Button>
        <Button size="sm" variant="ghost" loading={busy === "c"} onClick={() => go("c", { ips, class: null })}>Clear mark</Button>
        <span className="mx-1 h-4 w-px bg-border" />
        <Button size="sm" variant="soft" loading={busy === "o"} title="every IP that is not selected and has no mark yet"
          onClick={() => go("o", { ips, class: "non-enterprise", others: universe })}>All other unmarked → non-enterprise</Button>
      </>}
    </div>
  );
}
