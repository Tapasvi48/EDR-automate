"use client";
import * as React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, Building2, FileClock, Radio, ShieldAlert, Tags, Waypoints, Activity } from "lucide-react";
import { api } from "@/lib/api";
import { useMeta } from "@/lib/hooks";
import { fmtDt, fmtN } from "@/lib/format";
import { Badge, Button, Card, CardHeader, Field, PageHeader, Select } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { UploadWizard } from "@/components/upload-wizard";
import { TagWizard } from "@/components/tag-wizard";
import { MappedUpload } from "@/components/mapped-upload";
import { MatrixUpload } from "@/components/matrix-upload";
import { EdrLookup } from "@/components/edr-lookup";

type Kind = "inventory" | "tags" | "vulns" | "edr" | "niam" | "sod" | "comm" | "ndr" | "vapub" | "edrlookup";
type Open = null | { kind: Kind; lob?: { id: number; name: string } };

export default function UploadCenter() {
  const { data: meta } = useMeta();
  const [lob, setLob] = React.useState<Record<string, string>>({});
  const [open, setOpen] = React.useState<Open>(null);
  const lobs = meta?.lobs || [];
  const pick = (k: string) => lobs.find((l) => String(l.id) === lob[k]);
  const recent = useQuery({
    queryKey: ["upload-history"],
    queryFn: async () => {
      const [vs, imp, nm, sd, cm, ...inv] = await Promise.all([
        api<any>("/api/vulns/summary"), api<any>("/api/edr-import/history"), api<any>("/api/niam/uploads"),
        api<any>("/api/sod/uploads"), api<any>("/api/comm/uploads"),
        ...lobs.map((l) => api<any>(`/api/lobs/${l.id}/versions`).then((r) => r.rows.map((v: any) => ({ ...v, lob: l.name })))),
      ]);
      const rows = [
        ...inv.flat().map((v: any) => ({ when: v.uploaded_at, type: "Inventory", lob: v.lob, file: v.filename, by: v.uploaded_by,
          detail: `v${v.version_no} · ${fmtN(v.row_count)} rows · +${fmtN(v.added)} / −${fmtN(v.removed)} / ~${fmtN(v.modified)}` })),
        ...vs.scans.map((s: any) => ({ when: s.uploaded_at, type: "Vulnerability scan", lob: s.lob, file: s.filename, by: s.uploaded_by,
          detail: `${fmtN(s.hosts)} hosts · ${fmtN(s.rows)} findings · +${fmtN(s.new_findings)} new · ${fmtN(s.fixed_findings)} fixed` })),
        ...imp.rows.map((i: any) => ({ when: i.uploaded_at, type: "Old EDR inventory", lob: "–", file: i.filename, by: i.uploaded_by,
          detail: `${fmtN(i.added)} imported · ${fmtN(i.live_now)} live now · ${fmtN(i.already_known)} known` })),
        ...nm.rows.map((i: any) => ({ when: i.uploaded_at, type: "NIAM dump", lob: "–", file: i.filename, by: i.uploaded_by,
          detail: `${fmtN(i.rows)} nodes · +${fmtN(i.added)} / −${fmtN(i.removed)} / ~${fmtN(i.changed)}` })),
        ...sd.rows.map((i: any) => ({ when: i.uploaded_at, type: "SOD exceptions", lob: "–", file: i.filename, by: i.uploaded_by,
          detail: `${fmtN(i.rows)} exceptions · +${fmtN(i.added)} new · −${fmtN(i.removed)} removed` })),
        ...cm.rows.map((i: any) => ({ when: i.uploaded_at, type: "Communication matrix", lob: "–", file: i.filename, by: i.uploaded_by,
          detail: `${fmtN(i.rows)} rules (replaced ${fmtN(i.replaced)})` })),
      ];
      return rows.sort((a, b) => (b.when || "").localeCompare(a.when || ""));
    },
    enabled: !!meta,
  });

  const LobPicker = ({ k }: { k: string }) => (
    <Field label="LOB">
      <Select className="max-w-none" value={lob[k]} onChange={(v) => setLob({ ...lob, [k]: v })} placeholder="Choose a LOB…" options={lobs.map((l) => ({ value: l.id, label: l.name }))} />
    </Field>
  );
  const cards: { k: Kind; icon: React.ReactNode; title: string; desc: string; needsLob: boolean }[] = [
    { k: "inventory", icon: <Building2 className="size-5" />, title: "LOB inventory", needsLob: true,
      desc: "Standard template (IP, Node Name, MSP, Node Type, Domain, Live/Non Live, OS, EDR Feasible, EDR Installed, Remarks). Versioned per LOB; can be one MSP or one inventory type." },
    { k: "vulns", icon: <ShieldAlert className="size-5" />, title: "Vulnerability scan", needsLob: true,
      desc: "Nessus-format export (IP Address, Vulnerability Name, Severity, Port, Plugin ID, CVE, dates…). Tracks new / fixed findings and each host's last scan." },
    { k: "vapub", icon: <ShieldAlert className="size-5" />, title: "VA public inventory", needsLob: false,
      desc: "Publicly reachable hosts for the VA team (Public IP, Private IP, LOB, MS Partner, DMZ…). Checked against the LOB inventory and the communication matrix; every host is listed as internet exposed." },
    { k: "edrlookup", icon: <FileClock className="size-5" />, title: "EDR lookup (match a list)", needsLob: false,
      desc: "Any Excel with an IP and / or hostname column: matched to every CrowdStrike asset (console, removed, old EDR import) and returned with EDR status, OS and last seen appended. Nothing is saved." },
    { k: "edr", icon: <FileClock className="size-5" />, title: "Old EDR inventory", needsLob: false,
      desc: "An older CrowdStrike host export. Agents no longer in the live console are kept as “Old EDR import” in EDR history and used for matching." },
    { k: "tags", icon: <Tags className="size-5" />, title: "Agent tags (AID + MSP)", needsLob: true,
      desc: "Assign agents that report to EDR but are missing from the inventory to a LOB / MSP — they show as “EDR only”." },
    { k: "niam", icon: <Radio className="size-5" />, title: "NIAM dump", needsLob: false,
      desc: "Host (IP) → NE ID. Every network element is matched to inventory, EDR and vulnerabilities; NE ID shows up in Asset 360. Full snapshot per upload." },
    { k: "sod", icon: <BadgeCheck className="size-5" />, title: "Vulnerability exceptions (SOD)", needsLob: false,
      desc: "The approved exception register. Matching findings become Accepted and leave open counts and risk; they reopen when the exception expires." },
    { k: "comm", icon: <Waypoints className="size-5" />, title: "Communication matrix", needsLob: false,
      desc: "Firewall / NAT flows. Inbound Internet / ISP rules mark destinations internet-exposed on those ports; flows appear in Asset 360." },
    { k: "ndr", icon: <Activity className="size-5" />, title: "Seceon NDR alerts", needsLob: false,
      desc: "Alert export from Seceon aiXDR / OTM. Network detections per IP show under Recent detections in Asset 360 (live alerts can come through the webhook instead)." },
  ];

  return (
    <div>
      <PageHeader title="Upload center" sub="Every file that feeds the console, in one place. Each upload is checked and previewed before anything is saved." />
      {!lobs.length && (
        <Card className="mb-4 p-4 text-[13px]">No LOBs yet — <Link href="/lobs/" className="text-accent-fg hover:underline">create a LOB</Link> first to upload inventories, scans or tags.</Card>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        {cards.map((c) => (
          <Card key={c.k} className="flex flex-col p-5">
            <div className="flex items-start gap-3">
              <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent-fg">{c.icon}</div>
              <div className="min-w-0">
                <div className="text-[15px] font-semibold">{c.title}</div>
                <div className="mt-1 text-[12.5px] text-muted">{c.desc}</div>
              </div>
            </div>
            <div className="mt-4 flex items-end gap-3">
              {c.needsLob && <div className="flex-1"><LobPicker k={c.k} /></div>}
              <Button variant="primary" className={c.needsLob ? "" : "ml-auto"} disabled={c.needsLob && !pick(c.k)}
                onClick={() => setOpen({ kind: c.k, lob: c.needsLob ? pick(c.k) : undefined })}>Upload…</Button>
            </div>
          </Card>
        ))}
      </div>
      <Card className="mt-5">
        <CardHeader title="Upload history" hint="latest first" />
        <SimpleTable rows={recent.data || []} maxHeight="480px" empty="Nothing uploaded yet" columns={[
          { key: "when", label: "When", render: (r: any) => fmtDt(r.when) },
          { key: "type", label: "Type", render: (r: any) => <Badge tone={r.type === "Inventory" ? "info" : r.type === "Vulnerability scan" ? "crit" : r.type === "NIAM dump" ? "violet" : "outline"}>{r.type}</Badge> },
          { key: "lob", label: "LOB" }, { key: "file", label: "File" }, { key: "by", label: "By" },
          { key: "detail", label: "Result", wrap: true },
        ]} />
      </Card>
      {open?.kind === "inventory" && open.lob && <UploadWizard lob={open.lob} open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "tags" && open.lob && <TagWizard lob={open.lob} open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "vulns" && <MappedUpload kind="vulns" lobId={open.lob?.id} open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "edr" && <MappedUpload kind="edr" open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "niam" && <MappedUpload kind="niam" open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "sod" && <MappedUpload kind="sod" open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "comm" && <MatrixUpload open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "ndr" && <MappedUpload kind="ndr" open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "vapub" && <MappedUpload kind="vapub" open onOpenChange={(o) => !o && setOpen(null)} />}
      {open?.kind === "edrlookup" && <EdrLookup open onOpenChange={(o) => !o && setOpen(null)} />}
    </div>
  );
}
