"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, GitCompare, History, Layers, List, Pencil, Plus, RotateCcw, Tags, Trash2, Upload } from "lucide-react";
import { toast } from "sonner";
import { api, downloadExcel } from "@/lib/api";
import { useUrlState } from "@/lib/hooks";
import { fmtDt, fmtN, fmtRel } from "@/lib/format";
import { Badge, Button, Callout, Card, CardHeader, Chip, Field, Input, Kpi, KpiGrid, Loading, Modal, PageHeader, SearchInput, Select, Tabs, useConfirm } from "@/components/ui";
import { COLORS, HBars, Legend } from "@/components/charts";
import { DataTable, SimpleTable } from "@/components/data-table";
import { InventoryTable } from "@/components/inventory-table";
import { CoverageTable } from "@/components/coverage-table";
import { HostTable } from "@/components/host-table";
import { HostLink, HostStatus, Mono, When } from "@/components/badges";
import { Preview, UploadWizard } from "@/components/upload-wizard";
import { TagWizard } from "@/components/tag-wizard";
import { LobForm } from "./lobs";

export default function Lob() {
  const [state, set, replaceAll] = useUrlState();
  const id = +(state.id || 0);
  const tab = state.tab || "overview";
  const router = useRouter();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [upload, setUpload] = React.useState<{ msp?: number | null; type?: number | null } | null>(null);
  const [typeForm, setTypeForm] = React.useState<any>(null);
  const [tagging, setTagging] = React.useState<{ msp?: number | null } | null>(null);
  const [edit, setEdit] = React.useState(false);
  const [mspForm, setMspForm] = React.useState<any>(null);
  const { data } = useQuery({ queryKey: ["lob", id], queryFn: () => api<any>(`/api/lobs/${id}`), enabled: !!id });
  const { data: versions } = useQuery({ queryKey: ["lob-versions", id], queryFn: () => api<any>(`/api/lobs/${id}/versions`), enabled: !!id });
  if (!id) return <Callout tone="crit">No LOB selected. <Link href="/lobs/" className="underline">Back to LOBs</Link></Callout>;
  if (!data) return <Loading />;
  const { lob, summary: s, current_version: cv, msps, types = [] } = data;
  const goTab = (t: string, extra: Record<string, string> = {}) => replaceAll({ id: String(id), tab: t, ...extra });
  const del = async () => {
    if (!(await confirm({ title: `Delete ${lob.name}?`, body: "This permanently deletes the LOB, its MSPs, all inventory versions, change history and agent tags. Falcon host data is not affected.", ok: "Delete LOB", danger: true }))) return;
    await api(`/api/lobs/${id}`, { method: "DELETE" });
    toast.success("LOB deleted");
    qc.invalidateQueries();
    router.push("/lobs/");
  };
  const delMsp = async (m: any) => {
    if (!(await confirm({ title: `Delete MSP ${m.msp}?`, body: "The MSP and its agent tags are removed. MSPs that still own inventory nodes cannot be deleted.", ok: "Delete", danger: true }))) return;
    try { await api(`/api/msps/${m.msp_id}`, { method: "DELETE" }); toast.success("MSP deleted"); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };
  const delType = async (t: any) => {
    if (!(await confirm({ title: `Delete type ${t.name}?`, body: `Deletes the ${t.name} inventory with all ${t.versions} of its versions and change history, and removes its ${t.nodes} nodes from the LOB inventory. The main inventory and other types are not affected.`, ok: "Delete type", danger: true }))) return;
    try { await api(`/api/types/${t.id}`, { method: "DELETE" }); toast.success("Type deleted"); qc.invalidateQueries(); }
    catch (e: any) { toast.error(e.message); }
  };

  return (
    <div>
      <Link href="/lobs/" className="mb-2 inline-flex items-center gap-1 text-xs text-fg-2 hover:text-fg"><ArrowLeft className="size-3.5" /> All LOBs</Link>
      <PageHeader
        title={<span className="flex items-center gap-2">{lob.name}{cv && <Badge tone="info">v{cv.version_no}</Badge>}{types.length > 0 && <Badge tone="violet">{types.length} type{types.length > 1 ? "s" : ""}</Badge>}</span>}
        sub={<>{lob.description}{lob.owner ? ` · ${lob.owner}` : ""}{cv ? ` · last upload ${fmtRel(cv.uploaded_at)} by ${cv.uploaded_by || "unknown"}${cv.scope_msp ? ` (MSP ${cv.scope_msp} only)` : ""}` : " · no inventory uploaded yet"}</>}
        actions={<>
          <Button variant="ghost" size="icon" title="Edit LOB" onClick={() => setEdit(true)}><Pencil /></Button>
          <Button variant="ghost" size="icon" title="Delete LOB" onClick={del}><Trash2 /></Button>
          <Button onClick={() => setMspForm({})}><Plus /> MSP</Button>
          <Button onClick={() => setTypeForm({})}><Plus /> Type</Button>
          <Button onClick={() => setTagging({})}><Tags /> Tag agents</Button>
          <Button onClick={() => downloadExcel(`/api/lobs/${id}/inventory/export`)}><Download /> Inventory</Button>
          <Button variant="primary" onClick={() => setUpload({})}><Upload /> Upload inventory</Button>
        </>}
      />
      <Tabs value={tab} onChange={(t) => goTab(t)} tabs={[
        { id: "overview", label: "Overview" },
        { id: "inventory", label: "Inventory", count: s.nodes },
        { id: "unlisted", label: "Not in inventory", count: s.unlisted },
        { id: "tags", label: "Agent tags" },
        { id: "changes", label: "Change log" },
        { id: "versions", label: "Versions", count: versions?.rows.length },
      ]} />

      {tab === "overview" && (
        <>
          {!s.nodes && (
            <Callout className="mb-4">No inventory yet. Add the LOB&apos;s MSPs, then upload the inventory (one file for the whole LOB with an MSP column, or one file per MSP).</Callout>
          )}
          <KpiGrid className="grid-cols-[repeat(auto-fill,minmax(140px,1fr))]">
            <Kpi label="Nodes" value={s.nodes} tone="info" onClick={() => goTab("inventory")} foot={`${fmtN(s.not_feasible)} not feasible · ${fmtN(s.non_live)} non live`} />
            <Kpi label="Applicable" value={s.applicable} onClick={() => goTab("inventory", { applicable: "1" })} foot="Live & EDR feasible" />
            <Kpi label="Installed" value={s.installed} tone="good" foot={s.coverage === null ? undefined : `${s.coverage}% coverage`} onClick={() => goTab("inventory", { installed: "1" })} />
            <Kpi label="Online" value={s.online} tone="good" onClick={() => goTab("inventory", { coverage_status: "Online" })} />
            <Kpi label="Offline" value={s.offline} tone="warn" onClick={() => goTab("inventory", { coverage_status: "Offline" })} />
            <Kpi label="Not installed" value={s.not_installed} tone="crit" onClick={() => goTab("inventory", { coverage_status: "Not Installed" })} />
            <Kpi label="Hidden" value={s.hidden} tone="violet" onClick={() => goTab("inventory", { coverage_status: "Hidden" })} />
            <Kpi label="Not in inventory" value={s.unlisted} tone="violet" foot="agents on EDR, missing from inventory" onClick={() => goTab("unlisted")} />
            <Kpi label="Duplicate IPs" value={s.dup_ips} tone="serious" foot="IP on several rows in this LOB" onClick={() => goTab("inventory", { dup: "ip" })} />
            <Kpi label="IPs in other LOBs" value={s.cross_lob_ips} tone="serious" foot="same IP also listed by another LOB" onClick={() => goTab("inventory", { dup: "cross_lob" })} />
          </KpiGrid>

          <Card className="mt-4">
            <CardHeader title={<span className="flex items-center gap-2"><Layers className="size-4" /> Inventories</span>}
              hint="the main inventory plus one per type — each has its own upload and version history"
              right={<Button size="sm" onClick={() => setTypeForm({})}><Plus /> Add type</Button>} />
            <SimpleTable rows={[{ id: null, name: "Main inventory", main: true, nodes: s.nodes - types.reduce((a: number, t: any) => a + t.nodes, 0),
              current_version: cv?.version_no, uploaded_at: cv?.uploaded_at, uploaded_by: cv?.uploaded_by, versions: undefined }, ...types]}
              columns={[
                { key: "name", label: "Inventory", render: (t: any) => <span className="flex items-center gap-1.5"><b>{t.name}</b>{t.main ? <Badge tone="outline">whole LOB</Badge> : <Badge tone="violet">type</Badge>}</span> },
                { key: "nodes", label: "Nodes", num: true, render: (t: any) => fmtN(t.nodes) },
                { key: "current_version", label: "Current version", render: (t: any) => t.current_version ? <Badge tone="info">v{t.current_version}</Badge> : <span className="text-muted">nothing uploaded</span> },
                { key: "uploaded_at", label: "Last upload", render: (t: any) => t.uploaded_at ? <span>{fmtRel(t.uploaded_at)} <span className="text-xs text-muted">{t.uploaded_by}</span></span> : "–" },
                { key: "act", label: "", render: (t: any) => (
                  <div className="flex justify-end gap-1">
                    <Button size="sm" variant="ghost" title={`Upload ${t.name}`} onClick={() => setUpload({ type: t.id })}><Upload /></Button>
                    <Button size="sm" variant="ghost" title="Show nodes" onClick={() => goTab("inventory", { type: t.main ? "main" : String(t.id) })}><List /></Button>
                    {!t.main && <Button size="sm" variant="ghost" title="Rename type" onClick={() => setTypeForm(t)}><Pencil /></Button>}
                    {!t.main && <Button size="sm" variant="ghost" title="Delete type" onClick={() => delType(t)}><Trash2 /></Button>}
                  </div>
                ) },
              ]} />
          </Card>

          <Card className="mt-4">
            <CardHeader title="MSP-wise coverage" hint="click any number to open the matching nodes"
              right={<Button size="sm" onClick={() => setMspForm({})}><Plus /> Add MSP</Button>} />
            {msps.length ? (
              <CoverageTable rows={msps} mode="msp" showLob={false} actions={(m) => (
                <div className="flex justify-end gap-1">
                  {m.msp_id && <Button size="sm" variant="ghost" title="Upload inventory for this MSP" onClick={() => setUpload({ msp: m.msp_id })}><Upload /></Button>}
                  {m.msp_id && <Button size="sm" variant="ghost" title="Tag agents to this MSP" onClick={() => setTagging({ msp: m.msp_id })}><Tags /></Button>}
                  {m.msp_id && <Button size="sm" variant="ghost" title="Edit MSP" onClick={() => setMspForm(m)}><Pencil /></Button>}
                  {m.msp_id && <Button size="sm" variant="ghost" title="Delete MSP" onClick={() => delMsp(m)}><Trash2 /></Button>}
                </div>
              )} />
            ) : (
              <div className="px-4 pb-6 pt-2 text-center text-muted">No MSPs yet — <button className="text-accent-fg hover:underline" onClick={() => setMspForm({})}>add one</button>, or upload an inventory with an MSP column and they are created automatically.</div>
            )}
          </Card>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Card>
              <CardHeader title="Node type coverage" hint="applicable nodes" />
              <div className="px-4 pb-4">
                <Legend series={[{ key: "i", label: "Installed", color: COLORS.good }, { key: "o", label: "of which offline", color: COLORS.warn }, { key: "p", label: "Pending", color: COLORS.crit }]} />
                <HBars items={data.node_types.filter((r: any) => r.applicable > 0).map((r: any) => ({
                  label: r.label, n: r.applicable, href: `/lob/?id=${id}&tab=inventory&node_type=${encodeURIComponent(r.label)}&applicable=1`,
                  title: `${r.label}: ${r.installed}/${r.applicable} installed (${r.offline} offline), ${r.pending} pending`,
                  parts: [{ n: r.installed - r.offline, color: COLORS.good }, { n: r.offline, color: COLORS.warn }, { n: r.pending, color: COLORS.crit }],
                }))} />
              </div>
            </Card>
            <Card>
              <CardHeader title="Inventory accuracy" hint="inventory claim vs Falcon" />
              <div className="space-y-1 px-2 pb-3">
                {[
                  ["Inventory says “Yes”, no agent found", s.claimed_missing, "crit", { claimed_missing: "1" }],
                  ["Inventory says “No”, agent is running", s.marked_no, "serious", { marked_no: "1" }],
                  ["Marked not applicable, agent is running", s.installed_not_applicable, "warn", { installed_na: "1" }],
                  ["Same IP listed under more than one MSP", s.cross_msp_dup_ips, "serious", { cross_msp_dup: "1" }],
                  ["Installed nodes with duplicate agents", s.edr_dup_ips, "serious", {}],
                ].map(([l, n, tone, f]: any) => (
                  <button key={l} onClick={() => goTab("inventory", f)} className="flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left hover:bg-surface-2">
                    <Badge tone={n ? tone : "neutral"} className="min-w-[40px] justify-center tabular">{fmtN(n)}</Badge>
                    <span className="text-[13px] text-fg-2">{l}</span>
                  </button>
                ))}
              </div>
            </Card>
            <CrossMspDups id={id} />
          </div>
        </>
      )}

      {tab === "inventory" && (
        <InventoryTable lobId={id} state={state} set={set} reset={() => goTab("inventory")} versions={versions?.rows} types={types} />
      )}
      {tab === "unlisted" && (
        <>
          <Callout className="mb-3">
            Agents tagged to {lob.name} (via an AID + MSP sheet) that report to Falcon but are <b>not in the LOB inventory</b>. Add them to the inventory, or remove the tag if they belong elsewhere.
          </Callout>
          <HostTable state={state} set={set} reset={() => goTab("unlisted")} fixed={{ state: "active", unlisted: "1", lob: String(id) }} omit={["tab", "id"]} storageKey="unlisted"
            extraFilters={<Button size="sm" onClick={() => setTagging({})}><Tags /> Tag agents</Button>} />
        </>
      )}
      {tab === "tags" && <AgentTags id={id} state={state} set={set} reset={() => goTab("tags")} onTag={() => setTagging({})} msps={msps} />}
      {tab === "changes" && <Changes id={id} state={state} set={set} reset={() => goTab("changes")} versions={versions?.rows || []} />}
      {tab === "versions" && <Versions id={id} versions={versions?.rows} goTab={goTab} />}

      {upload && <UploadWizard lob={lob} mspId={upload.msp} typeId={upload.type} open onOpenChange={(o) => !o && setUpload(null)} />}
      {tagging && <TagWizard lob={lob} mspId={tagging.msp} open onOpenChange={(o) => !o && setTagging(null)} />}
      <LobForm open={edit} onOpenChange={setEdit} lob={lob} />
      {mspForm && <MspForm lobId={id} msp={mspForm.msp_id ? mspForm : null} onClose={() => setMspForm(null)} />}
      {typeForm && <TypeForm lobId={id} type={typeForm.id ? typeForm : null} onClose={() => setTypeForm(null)} />}
    </div>
  );
}

function MspForm({ lobId, msp, onClose }: { lobId: number; msp: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = React.useState({ name: msp?.msp || "", description: msp?.description || "", contact: msp?.contact || "" });
  const save = async () => {
    try {
      if (msp) await api(`/api/msps/${msp.msp_id}`, { method: "PUT", body: f });
      else await api(`/api/lobs/${lobId}/msps`, { method: "POST", body: f });
      toast.success(msp ? "MSP updated" : "MSP added");
      qc.invalidateQueries();
      onClose();
    } catch (e: any) { toast.error(e.message); }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={msp ? `Edit MSP · ${msp.msp}` : "Add MSP"}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!f.name.trim()} onClick={save}>{msp ? "Save" : "Add MSP"}</Button></>}>
      <div className="grid gap-3">
        <Field label="MSP name" hint="Must match the value in the inventory's MSP column (case-insensitive)."><Input autoFocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Wipro" /></Field>
        <Field label="Description"><Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <Field label="Contact"><Input value={f.contact} onChange={(e) => setF({ ...f, contact: e.target.value })} placeholder="msp-team@partner.com" /></Field>
      </div>
    </Modal>
  );
}

function TypeForm({ lobId, type, onClose }: { lobId: number; type: any; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = React.useState({ name: type?.name || "", description: type?.description || "" });
  const save = async () => {
    try {
      if (type) await api(`/api/types/${type.id}`, { method: "PUT", body: f });
      else await api(`/api/lobs/${lobId}/types`, { method: "POST", body: f });
      toast.success(type ? "Type updated" : "Type added");
      qc.invalidateQueries();
      onClose();
    } catch (e: any) { toast.error(e.message); }
  };
  return (
    <Modal open onOpenChange={(o) => !o && onClose()} title={type ? `Edit type · ${type.name}` : "Add inventory type"}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!f.name.trim()} onClick={save}>{type ? "Save" : "Add type"}</Button></>}>
      <div className="grid gap-3">
        <Field label="Type name" hint="e.g. Servers, Network devices, Databases. Every node uploaded into this type gets it as its node type.">
          <Input autoFocus value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="e.g. Network devices" />
        </Field>
        <Field label="Description"><Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        {!type && <Callout>Each type has its own inventory file and its own version history (v1, v2 …). Uploading a type replaces only that type&apos;s nodes; the main inventory and other types stay unchanged.</Callout>}
      </div>
    </Modal>
  );
}

const verLabel = (v: any) => `${v.type_name || "Main"} v${v.version_no}`;

function CrossMspDups({ id }: { id: number }) {
  const { data } = useQuery({ queryKey: ["xdup", id], queryFn: () => api<any>(`/api/lobs/${id}/cross-msp-duplicates`) });
  const rows = data?.rows || [];
  return (
    <Card>
      <CardHeader title="IPs listed by more than one MSP" hint={`${rows.length} IPs`}
        right={rows.length ? <Link className="text-xs text-accent-fg hover:underline" href={`/lob/?id=${id}&tab=inventory&cross_msp_dup=1`}>Show nodes</Link> : undefined} />
      <SimpleTable rows={rows} maxHeight="300px" empty="No IP is claimed by two MSPs" columns={[
        { key: "ip", label: "IP", render: (r: any) => <Link className="font-mono text-[12px] text-accent-fg hover:underline" href={`/lob/?id=${id}&tab=inventory&q=${r.ip}`}>{r.ip}</Link> },
        { key: "msps", label: "MSPs", wrap: true, render: (r: any) => <span className="flex flex-wrap gap-1">{r.msps.split(",").map((m: string) => <Badge key={m} tone="outline">{m}</Badge>)}</span> },
        { key: "node_names", label: "Node names", wrap: true },
      ]} />
    </Card>
  );
}

function AgentTags({ id, state, set, reset, onTag, msps }: { id: number; state: Record<string, string>; set: any; reset: () => void; onTag: () => void; msps: any[] }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const remove = async (body: any, what: string) => {
    if (!(await confirm({ title: "Remove tags?", body: `Remove ${what}? The agents stay in Falcon; they just stop counting toward this LOB/MSP.`, ok: "Remove", danger: true }))) return;
    await api(`/api/lobs/${id}/tags/remove`, { method: "POST", body });
    toast.success("Tags removed");
    qc.invalidateQueries();
  };
  return (
    <DataTable
      endpoint={`/api/lobs/${id}/tags`} state={state} setState={set} omit={["tab", "id"]} sortable={false} noun="tagged agents" rowKey={(r: any) => r.aid}
      onReset={reset}
      toolbar={<>
        <Button size="sm" onClick={onTag}><Tags /> Tag agents</Button>
        <Button size="sm" variant="danger" onClick={() => remove({ all: true, msp_id: state.msp && state.msp !== "none" ? +state.msp : null }, state.msp ? "all tags of this MSP" : "all tags of this LOB")}><Trash2 /> Remove all</Button>
      </>}
      filters={<>
        <SearchInput className="w-64" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="Hostname, IP or AID" />
        <Select value={state.msp} onChange={(v) => set({ msp: v })} placeholder="All MSPs" options={[...msps.filter((m) => m.msp_id).map((m) => ({ value: m.msp_id, label: m.msp })), { value: "none", label: "Unassigned" }]} />
      </>}
      columns={[
        { key: "hostname", label: "Hostname", render: (r: any) => r.hostname ? <HostLink aid={r.aid}><b>{r.hostname}</b></HostLink> : <Mono>{r.aid}</Mono> },
        { key: "local_ip", label: "IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
        { key: "msp", label: "MSP" },
        { key: "st", label: "Status", render: (r: any) => <HostStatus r={r} /> },
        { key: "in_inventory", label: "In inventory", render: (r: any) => r.in_inventory ? <Badge tone="good">Yes</Badge> : <Badge tone="violet">Not in inventory</Badge> },
        { key: "last_seen", label: "Last seen", render: (r: any) => <When ts={r.last_seen} /> },
        { key: "source", label: "Source file" },
        { key: "tagged_at", label: "Tagged", render: (r: any) => fmtDt(r.tagged_at) },
        { key: "x", label: "", render: (r: any) => <Button size="sm" variant="ghost" onClick={() => remove({ aids: [r.aid] }, `the tag on ${r.hostname || r.aid}`)}><Trash2 /></Button> },
      ]}
    />
  );
}

function Changes({ id, state, set, reset, versions }: { id: number; state: Record<string, string>; set: any; reset: () => void; versions: any[] }) {
  const [fields, setFields] = React.useState<string[]>([]);
  const ct = state.change_type || "";
  return (
    <DataTable
      endpoint={`/api/lobs/${id}/changes`} exportPath={`/api/lobs/${id}/changes/export`}
      state={state} setState={set} omit={["tab", "id"]} sortable={false} noun="changes" defaultSize={100}
      rowKey={(r: any) => String(r.id)} onReset={reset}
      onData={(d) => setFields(d.fields || [])}
      columns={[
        { key: "version_no", label: "Version", render: (r: any) => <Badge tone="info">{verLabel(r)}</Badge> },
        { key: "uploaded_at", label: "Uploaded", render: (r: any) => fmtDt(r.uploaded_at) },
        { key: "change_type", label: "Change", render: (r: any) => <Badge tone={r.change_type === "added" ? "info" : r.change_type === "removed" ? "crit" : "warn"}>{r.change_type === "added" ? "NEW" : r.change_type.toUpperCase()}</Badge> },
        { key: "ip", label: "IP", render: (r: any) => <Mono>{r.ip || r.item_key}</Mono> },
        { key: "node_name", label: "Node name", render: (r: any) => <b>{r.node_name}</b> },
        { key: "field_label", label: "Field" },
        { key: "diff", label: "Old → New", wrap: true, render: (r: any) => r.change_type === "modified" ? <span><span className="text-crit-fg line-through">{r.old_value || "∅"}</span> → <b className="text-good-fg">{r.new_value || "∅"}</b></span> : <span className="text-muted">{r.change_type === "added" ? "Added in this version" : "Not present in this version"}</span> },
      ]}
      filters={<>
        <SearchInput className="w-64" value={state.q || ""} onChange={(v) => set({ q: v })} placeholder="IP / key" />
        <Select value={state.version_id} onChange={(v) => set({ version_id: v })} placeholder="All versions" options={versions.map((v) => ({ value: v.id, label: `${verLabel(v)} · ${fmtDt(v.uploaded_at)}` }))} />
        <Select value={state.field} onChange={(v) => set({ field: v })} placeholder="Any field" options={fields} />
        {[["", "All"], ["added", "New"], ["removed", "Removed"], ["modified", "Modified"]].map(([k, l]) => (
          <Chip key={k} on={ct === k} onClick={() => set({ change_type: k || undefined })}>{l}</Chip>
        ))}
      </>}
    />
  );
}

function Versions({ id, versions, goTab }: { id: number; versions?: any[]; goTab: (t: string, e?: Record<string, string>) => void }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [from, setFrom] = React.useState("");
  const [to, setTo] = React.useState("");
  React.useEffect(() => {
    if (versions && versions.length > 1 && !from) {
      // default: the latest version against the previous one of the same inventory
      const prev = versions.find((v, i) => i > 0 && v.type_id === versions[0].type_id) || versions[1];
      setTo(String(versions[0].id)); setFrom(String(prev.id));
    }
  }, [versions, from]);
  const cmp = useQuery({ queryKey: ["compare", id, from, to], queryFn: () => api<any>(`/api/lobs/${id}/compare`, { params: { v_from: from, v_to: to } }), enabled: !!from && !!to && from !== to });
  if (!versions) return <Loading />;
  const restore = async (v: any) => {
    if (!(await confirm({ title: `Restore ${verLabel(v)}?`, body: `A new ${v.type_name || "main inventory"} version will be created with the exact contents of ${verLabel(v)}. Nothing is deleted — the current version stays in history.`, ok: "Restore as new version" }))) return;
    const r = await api<any>(`/api/lobs/${id}/versions/${v.id}/restore`, { method: "POST", body: {} });
    toast.success(`Restored as ${v.type_name || "Main"} v${r.version_no}`);
    qc.invalidateQueries();
  };
  const opts = versions.map((v) => ({ value: v.id, label: `${verLabel(v)} · ${fmtDt(v.uploaded_at)}` }));
  return (
    <div className="space-y-4">
      <Card>
        <SimpleTable rows={versions} empty="No versions yet" columns={[
          { key: "version_no", label: "Version", render: (v: any) => <span className="flex items-center gap-1.5"><Badge tone="info">{verLabel(v)}</Badge>{v.is_current ? <Badge tone="good">current</Badge> : null}{v.restored_from && <Badge tone="violet">restore</Badge>}</span> },
          { key: "uploaded_at", label: "Uploaded", render: (v: any) => <span>{fmtDt(v.uploaded_at)} <span className="text-xs text-muted">{v.uploaded_by}</span></span> },
          { key: "filename", label: "File", render: (v: any) => <span className="text-fg-2">{v.filename}</span> },
          { key: "note", label: "Note", wrap: true },
          { key: "template_name", label: "Template", render: (v: any) => v.template_name || <span className="text-muted">auto</span> },
          { key: "key_field", label: "Key" },
          { key: "row_count", label: "Rows", num: true, render: (v: any) => fmtN(v.row_count) },
          { key: "delta", label: "Changes vs previous", render: (v: any) => <span className="tabular"><span className="text-accent-fg">+{fmtN(v.added)}</span> · <span className="text-crit-fg">−{fmtN(v.removed)}</span> · <span className="text-warn-fg">~{fmtN(v.modified)}</span></span> },
          { key: "warnings", label: "", render: (v: any) => v.warnings?.length ? <Badge tone="warn" title={v.warnings.join("\n")}>{v.warnings.length} warnings</Badge> : null },
          { key: "act", label: "", render: (v: any) => (
            <div className="flex gap-1">
              <Button size="sm" onClick={() => goTab("inventory", v.is_current ? { type: v.type_id ? String(v.type_id) : "main" } : { version_id: String(v.id) })}>View</Button>
              <Button size="sm" onClick={() => goTab("changes", { version_id: String(v.id) })}><History /> Changes</Button>
              {!v.is_current && <Button size="sm" onClick={() => restore(v)}><RotateCcw /> Restore</Button>}
            </div>
          ) },
        ]} />
      </Card>
      {versions.length > 1 && (
        <Card>
          <CardHeader title={<span className="flex items-center gap-2"><GitCompare className="size-4" /> Compare any two versions</span>}
            right={<>
              <Select value={from} onChange={setFrom} options={opts} />
              <span className="text-muted">→</span>
              <Select value={to} onChange={setTo} options={opts} />
            </>} />
          <div className="px-4 pb-4">
            {from === to ? <div className="py-6 text-center text-muted">Pick two different versions</div> : cmp.data ? <Preview p={cmp.data} /> : <Loading />}
          </div>
        </Card>
      )}
    </div>
  );
}
