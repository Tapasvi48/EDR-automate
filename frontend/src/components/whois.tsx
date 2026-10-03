"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Building2 } from "lucide-react";
import { api } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { Badge, Button, FilterSelect, SearchInput, useConfirm } from "@/components/ui";

/** WHOIS of a public IP: registered name, description, organisation (country · range in the tooltip). */
export function WhoisCell({ r }: { r: any }) {
  if (!r.whois_name && !r.whois_org) return <span className="text-[11.5px] text-muted" title={r.whois_error || ""}>{r.whois_error ? "no WHOIS answer" : "not looked up"}</span>;
  return (
    <span className="flex max-w-[280px] flex-col" title={[r.whois_org, r.whois_country, r.whois_range].filter(Boolean).join(" · ")}>
      <span className="truncate text-[12px] font-semibold">{r.whois_name}</span>
      {r.whois_descr && <span className="line-clamp-2 text-[11.5px] text-fg-2">{r.whois_descr}</span>}
      {r.whois_org && r.whois_org !== r.whois_descr && <span className="truncate text-[11px] text-muted">{r.whois_org}{r.whois_country ? ` · ${r.whois_country}` : ""}</span>}
    </span>
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

/** Mark the selected IPs, every IP the current filter matches, or every other unmarked IP as enterprise / non-enterprise. */
export function ClassifyBar({ path, filter, selected, total, onDone }: {
  path: string; filter: Record<string, string>; selected: Set<string>; total: number; onDone: () => void;
}) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [busy, setBusy] = React.useState("");
  const f = Object.fromEntries(Object.entries(filter).filter(([k, v]) => v && !["page", "size", "tab"].includes(k)));
  const filtered = Object.keys(f).length > 0;
  const go = async (key: string, body: any, what: string) => {
    if (!body.ips && !(await confirm({ title: what, body: "Marks are kept per IP and can be changed or cleared at any time.", ok: "Mark" }))) return;
    setBusy(key);
    try {
      const r = await api<any>(body.ips ? "/api/whois/class" : path, { method: "POST", body });
      toast.success(`${fmtN(r.marked)} IPs ${body.class ? `marked ${body.class}` : "cleared"}`);
      qc.invalidateQueries(); onDone();
    } catch (e: any) { toast.error(e.message); } finally { setBusy(""); }
  };
  const ips = [...selected];
  return (
    <div className="mb-2 flex flex-wrap items-center gap-1.5 rounded-xl border border-border bg-surface px-3 py-2 text-[12.5px]">
      <Building2 className="size-4 text-muted" /><span className="mr-1 font-medium">Mark</span>
      {ips.length > 0 ? <>
        <span className="text-muted">{fmtN(ips.length)} selected:</span>
        <Button size="sm" loading={busy === "se"} onClick={() => go("se", { ips, class: "enterprise" }, "")}>Enterprise</Button>
        <Button size="sm" loading={busy === "sn"} onClick={() => go("sn", { ips, class: "non-enterprise" }, "")}>Non-enterprise</Button>
        <Button size="sm" variant="ghost" loading={busy === "sc"} onClick={() => go("sc", { ips, class: null }, "")}>Clear</Button>
      </> : <span className="text-muted">select rows, or use the filter:</span>}
      <span className="mx-1 h-4 w-px bg-border" />
      <span className="text-muted">{filtered ? `all ${fmtN(total)} matching the filter:` : `all ${fmtN(total)}:`}</span>
      <Button size="sm" loading={busy === "fe"} onClick={() => go("fe", { filter: f, class: "enterprise" }, `Mark ${fmtN(total)} IPs as enterprise?`)}>Enterprise</Button>
      <Button size="sm" loading={busy === "fn"} onClick={() => go("fn", { filter: f, class: "non-enterprise" }, `Mark ${fmtN(total)} IPs as non-enterprise?`)}>Non-enterprise</Button>
      {filtered && <>
        <span className="mx-1 h-4 w-px bg-border" />
        <Button size="sm" variant="soft" loading={busy === "on"} title="every IP outside this filter that has no mark yet"
          onClick={() => go("on", { filter: f, class: "non-enterprise", scope: "others" }, "Mark every other unmarked IP as non-enterprise?")}>All others → non-enterprise</Button>
      </>}
    </div>
  );
}
