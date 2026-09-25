"use client";
import * as React from "react";
import { Download, ListChecks, Play } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { Badge, Button, Card, CardHeader, Chip, PageHeader, type Tone } from "@/components/ui";
import { SimpleTable } from "@/components/data-table";
import { HostLink, Mono, When } from "@/components/badges";

const TONE: Record<string, Tone> = { Online: "good", "Online (stale)": "warn", Offline: "serious", Removed: "crit", Hidden: "crit", "Not Found": "crit", "IP seen in history only": "violet", Unknown: "neutral" };

export default function Lookup() {
  const [text, setText] = React.useState("");
  const [res, setRes] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(false);
  const [filter, setFilter] = React.useState("");
  const count = text.split(/[\s,;]+/).filter(Boolean).length;
  const run = async () => {
    setLoading(true);
    try { setRes(await api("/api/lookup", { method: "POST", body: { text } })); setFilter(""); }
    catch (e: any) { toast.error(e.message); } finally { setLoading(false); }
  };
  const exportXlsx = async () => {
    const r = await fetch("/api/lookup/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "bulk_lookup.xlsx";
    a.click();
  };
  const rows = (res?.rows || []).filter((r: any) => !filter || r.status === filter);
  return (
    <div>
      <PageHeader title="Bulk lookup" sub="Paste a list of IPs and/or hostnames (from a ticket, audit or scan). Each entry is checked against Falcon — current agents, removed agents, NIC history — and LOB inventories." />
      <div className="grid gap-4 xl:grid-cols-[380px_minmax(0,1fr)]">
        <Card className="flex flex-col p-4">
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={16}
            placeholder={"10.20.34.17\nCORP-WS-0369\n10.30.12.4, PAY-SRV-0012\n…"}
            className="w-full flex-1 resize-y rounded-lg border border-border-strong bg-surface p-3 font-mono text-[12.5px] outline-none focus:outline-2 focus:outline-accent" />
          <div className="mt-3 flex items-center gap-2">
            <span className="text-xs text-muted">{fmtN(count)} entries</span>
            <div className="flex-1" />
            <Button onClick={() => { setText(""); setRes(null); }}>Clear</Button>
            <Button variant="primary" loading={loading} disabled={!count} onClick={run}><Play /> Check</Button>
          </div>
        </Card>
        <Card>
          <CardHeader title="Results" hint={res ? `${fmtN(res.total)} entries` : undefined} right={res && <Button size="sm" onClick={exportXlsx}><Download /> Excel</Button>} />
          {!res ? (
            <div className="py-16 text-center text-muted"><ListChecks className="mx-auto mb-2 size-8 opacity-60" />Results appear here</div>
          ) : (
            <>
              <div className="flex flex-wrap gap-1.5 px-4 pb-3">
                <Chip on={!filter} onClick={() => setFilter("")} count={res.total}>All</Chip>
                {Object.entries(res.summary).map(([s, n]) => <Chip key={s} on={filter === s} onClick={() => setFilter(filter === s ? "" : s)} count={n as number}>{s}</Chip>)}
              </div>
              <SimpleTable rows={rows} maxHeight="calc(100vh - 300px)" columns={[
                { key: "term", label: "Input", render: (r: any) => <Mono>{r.term}</Mono> },
                { key: "status", label: "EDR status", render: (r: any) => <Badge tone={TONE[r.status] || "neutral"}>{r.status}</Badge> },
                { key: "hostname", label: "Falcon host", render: (r: any) => r.aid ? <HostLink aid={r.aid}>{r.hostname || r.aid}</HostLink> : "–" },
                { key: "local_ip", label: "Current IP", render: (r: any) => <Mono>{r.local_ip}</Mono> },
                { key: "last_seen", label: "Last seen", render: (r: any) => r.last_seen ? <When ts={r.last_seen} /> : "–" },
                { key: "agents", label: "Agents", num: true, render: (r: any) => r.total_agents > 1 ? <Badge tone="serious">{r.active_agents} active / {r.total_agents}</Badge> : r.total_agents || "" },
                { key: "os_version", label: "OS" },
                { key: "lobs", label: "LOB" },
                { key: "inv_edr_installed", label: "Inv. EDR installed" },
                { key: "inv_verification", label: "Inv. verification" },
              ]} />
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
