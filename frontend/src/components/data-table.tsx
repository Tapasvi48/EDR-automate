"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Columns3, Download, Filter, GripVertical, RotateCcw, X } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button, Card, Empty, Input } from "./ui";

export type Column<T = any> = {
  key: string;
  label: string;
  render?: (r: T) => React.ReactNode;
  sort?: string | false;
  num?: boolean;
  hidden?: boolean;
  wrap?: boolean;
  className?: string;
};

type Props<T> = {
  endpoint: string;
  exportPath?: string;
  columns: Column<T>[];
  state: Record<string, string>;
  setState: (patch: Record<string, string | number | undefined>, opts?: { resetPage?: boolean }) => void;
  /** params always sent to the API but not stored in the URL */
  fixed?: Record<string, string>;
  /** URL keys that are UI-only and must not be sent to the API */
  omit?: string[];
  storageKey?: string;
  noun?: string;
  title?: React.ReactNode;
  toolbar?: React.ReactNode;
  filters?: React.ReactNode;
  onRowClick?: (r: T) => void;
  renderExpanded?: (r: T) => React.ReactNode;
  rowKey?: (r: T) => string;
  onReset?: () => void;
  defaultSize?: number;
  maxHeight?: string;
  sortable?: boolean;
  emptyText?: React.ReactNode;
  onData?: (d: any) => void;
  /** row checkboxes: the parent keeps the selected row keys (e.g. for a bulk delete) */
  selected?: Set<string>;
  onSelectedChange?: (s: Set<string>) => void;
};

export function DataTable<T extends Record<string, any>>(p: Props<T>) {
  const size = +(p.state.size || p.defaultSize || 50);
  const page = +(p.state.page || 1);
  const apiParams = React.useMemo(() => {
    const o: Record<string, string> = { ...p.state, ...(p.fixed || {}), size: String(size), page: String(page) };
    (p.omit || []).forEach((k) => delete o[k]);
    return o;
  }, [p.state, p.fixed, p.omit, size, page]);

  const q = useQuery({
    queryKey: [p.endpoint, apiParams],
    queryFn: () => api<{ rows: T[]; total: number }>(p.endpoint, { params: apiParams }),
    placeholderData: keepPreviousData,
  });
  // the next page is fetched in the background, so paging forward is instant
  const qc = useQueryClient();
  React.useEffect(() => {
    if (!q.data || page * size >= (q.data.total ?? 0)) return;
    const next = { ...apiParams, page: String(page + 1) };
    qc.prefetchQuery({ queryKey: [p.endpoint, next], queryFn: () => api(p.endpoint, { params: next }), staleTime: 60_000 });
  }, [q.data, page, size, apiParams, p.endpoint, qc]);
  React.useEffect(() => {
    if (q.data && p.onData) p.onData(q.data);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data]);

  const [hidden, setHidden] = React.useState<Set<string>>(() => new Set(p.columns.filter((c) => c.hidden).map((c) => c.key)));
  React.useEffect(() => {
    if (!p.storageKey) return;
    try {
      const s = localStorage.getItem("cols:" + p.storageKey);
      if (s) setHidden(new Set(JSON.parse(s)));
    } catch {}
  }, [p.storageKey]);
  const saveHidden = (h: Set<string>) => {
    setHidden(new Set(h));
    try {
      if (p.storageKey) localStorage.setItem("cols:" + p.storageKey, JSON.stringify([...h]));
    } catch {}
  };
  // user-chosen column order (drag in the Columns menu), saved per table
  const [order, setOrder] = React.useState<string[]>([]);
  React.useEffect(() => {
    if (!p.storageKey) return;
    try {
      const s = localStorage.getItem("colorder:" + p.storageKey);
      if (s) setOrder(JSON.parse(s));
    } catch {}
  }, [p.storageKey]);
  const saveOrder = (o: string[]) => {
    setOrder(o);
    try {
      if (p.storageKey) localStorage.setItem("colorder:" + p.storageKey, JSON.stringify(o));
    } catch {}
  };
  const ordered = React.useMemo(() => {
    if (!order.length) return p.columns;
    const pos = new Map(order.map((k, i) => [k, i]));
    // columns missing from the saved order keep their default neighbours
    return [...p.columns].map((c, i) => ({ c, i })).sort((a, b) => (pos.get(a.c.key) ?? a.i - 0.5) - (pos.get(b.c.key) ?? b.i - 0.5)).map((x) => x.c);
  }, [order, p.columns]);
  const move = (key: string, to: number) => {
    const keys = ordered.map((c) => c.key).filter((k) => k !== key);
    keys.splice(Math.max(0, Math.min(keys.length, to)), 0, key);
    saveOrder(keys);
  };
  const [dragKey, setDragKey] = React.useState<string | null>(null);
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const cols = ordered.filter((c) => !hidden.has(c.key));
  const rows = q.data?.rows || [];
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  const from = total ? (page - 1) * size + 1 : 0;
  const to = Math.min(total, page * size);
  const rk = p.rowKey || ((r: T) => String(r.aid ?? r.item_key ?? r.id ?? r.value ?? JSON.stringify(r)));

  const fields = React.useMemo(() => fieldList(p.columns, rows), [p.columns, rows]);
  const ffs = Object.entries(p.state).filter(([k, v]) => k.startsWith("ff_") && v);
  const selectAllMatching = async () => {
    const all = await api<{ rows: T[] }>(p.endpoint, { params: { ...apiParams, page: "1", __all: "1" } });
    p.onSelectedChange?.(new Set(all.rows.map(rk)));
  };

  const toggleSort = (s: string) => {
    if (p.state.sort === s) p.setState({ dir: p.state.dir === "asc" ? "desc" : "asc" });
    else p.setState({ sort: s, dir: "desc" });
  };

  return (
    <Card className="relative overflow-hidden">
      {p.filters && <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-3">{p.filters}</div>}
      {ffs.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 border-b border-border bg-accent-soft/30 px-3.5 py-2 text-[12px]">
          <Filter className="size-3.5 text-accent-fg" />
          {ffs.map(([k, v]) => {
            const [op, val] = v.includes(":") ? [v.split(":")[0], v.slice(v.indexOf(":") + 1)] : ["has", v];
            return (
              <span key={k} className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-surface px-2 py-0.5">
                <b>{fields.find((f) => f.key === k.slice(3))?.label || k.slice(3)}</b> <span className="text-muted">{OPS.find((o) => o[0] === op)?.[1] || op}</span> {val.split("|").join(" or ")}
                <button className="text-muted hover:text-fg" onClick={() => p.setState({ [k]: undefined })}><X className="size-3" /></button>
              </span>
            );
          })}
          <button className="ml-1 text-accent-fg hover:underline" onClick={() => p.setState(Object.fromEntries(ffs.map(([k]) => [k, undefined])))}>Clear field filters</button>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-2.5">
        {p.title && <span className="font-semibold">{p.title}</span>}
        <span className="text-fg-2">
          <b className="tabular text-fg">{q.data ? fmtN(total) : "–"}</b> {p.noun || "rows"}
        </span>
        {p.onSelectedChange && total > 0 && (p.selected?.size ?? 0) < total && (
          <Button size="sm" variant="soft" onClick={selectAllMatching} title="Select every row that matches the current filters, on all pages">
            Select all {fmtN(total)}{total > rows.length ? " matching" : ""}
          </Button>
        )}
        {p.onSelectedChange && (p.selected?.size ?? 0) > 0 && (
          <span className="text-[12px] text-fg-2">{fmtN(p.selected!.size)} selected · <button className="text-accent-fg hover:underline" onClick={() => p.onSelectedChange?.(new Set())}>clear</button></span>
        )}
        <div className="flex-1" />
        {p.toolbar}
        <FieldFilter fields={fields} rows={rows} onAdd={(k, v) => p.setState({ ["ff_" + k]: v })} />
        {p.onReset && (
          <Button size="sm" variant="ghost" onClick={p.onReset}>
            <RotateCcw /> Reset
          </Button>
        )}
        <Popover.Root>
          <Popover.Trigger asChild>
            <Button size="sm"><Columns3 /> Columns</Button>
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content align="end" side="bottom" sideOffset={6} collisionPadding={10} style={{ maxHeight: "min(460px, var(--radix-popover-content-available-height))" }} className="z-50 w-64 overflow-y-auto rounded-xl border border-border bg-surface p-2 shadow-xl scroll-thin">
              <div className="flex items-center gap-2 px-1.5 pb-1 text-xs">
                <b>Columns</b>
                <span className="flex-1" />
                <button className="text-accent-fg hover:underline" onClick={() => saveHidden(new Set())}>All</button>
                <button className="text-accent-fg hover:underline" onClick={() => { saveHidden(new Set(p.columns.filter((c) => c.hidden).map((c) => c.key))); saveOrder([]); }}>Default</button>
              </div>
              <div className="px-1.5 pb-2 text-[11px] text-muted">Drag ⋮⋮ to reorder</div>
              {ordered.map((c, i) => (
                <label key={c.key} draggable
                  onDragStart={(e) => { setDragKey(c.key); e.dataTransfer.effectAllowed = "move"; }}
                  onDragOver={(e) => { e.preventDefault(); if (dragKey && dragKey !== c.key) move(dragKey, i); }}
                  onDragEnd={() => setDragKey(null)}
                  className={cn("group/col flex cursor-pointer items-center gap-2 rounded-md px-1.5 py-1 text-[12.5px] hover:bg-surface-2", dragKey === c.key && "bg-accent-soft")}>
                  <GripVertical className="size-3.5 shrink-0 cursor-grab text-muted" />
                  <input
                    type="checkbox"
                    className="accent-[var(--accent)]"
                    checked={!hidden.has(c.key)}
                    onChange={(e) => {
                      const h = new Set(hidden);
                      e.target.checked ? h.delete(c.key) : h.add(c.key);
                      saveHidden(h);
                    }}
                  />
                  <span className="flex-1 truncate">{c.label || c.key}</span>
                  <span className="hidden gap-0.5 group-hover/col:flex">
                    <button type="button" title="Move up" disabled={i === 0} onClick={(e) => { e.preventDefault(); move(c.key, i - 1); }} className="rounded p-0.5 hover:bg-surface-3 disabled:opacity-30"><ArrowUp className="size-3" /></button>
                    <button type="button" title="Move down" disabled={i === ordered.length - 1} onClick={(e) => { e.preventDefault(); move(c.key, i + 1); }} className="rounded p-0.5 hover:bg-surface-3 disabled:opacity-30"><ArrowDown className="size-3" /></button>
                  </span>
                </label>
              ))}
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>
        {p.exportPath && (
          <Button size="sm" onClick={() => {
            const e = { ...apiParams };
            delete e.page;
            delete e.size;
            downloadExcel(p.exportPath!, e);
          }}>
            <Download /> Excel
          </Button>
        )}
      </div>
      <div className="relative overflow-auto scroll-thin" style={{ maxHeight: p.maxHeight || "calc(100vh - 260px)" }}>
        {q.isFetching && <div className="loadbar absolute inset-x-0 top-0 z-20 h-0.5 overflow-hidden" />}
        <table className="w-full border-separate border-spacing-0 text-[12.8px]">
          <thead>
            <tr>
              {p.renderExpanded && <th className="sticky top-0 z-10 w-8 border-b border-border bg-surface-2" />}
              {p.onSelectedChange && (
                <th className="sticky top-0 z-10 w-9 border-b border-border bg-surface-2 px-3">
                  <input type="checkbox" className="accent-[var(--accent)]" title="Select the rows on this page (use “Select all” above for every matching row)"
                    checked={rows.length > 0 && rows.every((r) => p.selected?.has(rk(r)))}
                    onChange={(e) => {
                      const n = new Set(p.selected);
                      rows.forEach((r) => (e.target.checked ? n.add(rk(r)) : n.delete(rk(r))));
                      p.onSelectedChange!(n);
                    }} />
                </th>
              )}
              {cols.map((c) => {
                const s = c.sort === false || p.sortable === false ? null : c.sort || c.key;
                const on = s && p.state.sort === s;
                return (
                  <th
                    key={c.key}
                    onClick={s ? () => toggleSort(s) : undefined}
                    className={cn(
                      "sticky top-0 z-10 whitespace-nowrap border-b border-border bg-surface-2 px-3 py-2 text-left text-xs font-semibold text-fg-2",
                      s && "cursor-pointer select-none hover:text-fg",
                      c.num && "text-right"
                    )}
                  >
                    <span className="inline-flex items-center gap-1">
                      {c.label}
                      {on && (p.state.dir === "asc" ? <ArrowUp className="size-3 text-accent" /> : <ArrowDown className="size-3 text-accent" />)}
                    </span>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {q.isError && (
              <tr>
                <td colSpan={99} className="p-4 text-crit-fg">{String((q.error as Error).message)}</td>
              </tr>
            )}
            {!q.isLoading && !rows.length && !q.isError && (
              <tr>
                <td colSpan={99}><Empty>{p.emptyText}</Empty></td>
              </tr>
            )}
            {q.isLoading && (
              <tr>
                <td colSpan={99}><Empty>Loading…</Empty></td>
              </tr>
            )}
            {rows.map((r) => {
              const key = rk(r);
              const isOpen = expanded.has(key);
              const clickable = p.onRowClick || p.renderExpanded;
              return (
                <React.Fragment key={key}>
                  <tr
                    className={cn("group", clickable && "cursor-pointer", isOpen && "[&>td]:bg-accent-soft")}
                    onClick={(e) => {
                      if ((e.target as HTMLElement).closest("a,button,input,select")) return;
                      if (p.renderExpanded) {
                        const n = new Set(expanded);
                        isOpen ? n.delete(key) : n.add(key);
                        setExpanded(n);
                      } else p.onRowClick?.(r);
                    }}
                  >
                    {p.renderExpanded && (
                      <td className="border-b border-border px-2 text-muted group-hover:bg-surface-2">
                        <ChevronRight className={cn("size-4 transition-transform", isOpen && "rotate-90")} />
                      </td>
                    )}
                    {p.onSelectedChange && (
                      <td className={cn("border-b border-border px-3 group-hover:bg-surface-2", p.selected?.has(key) && "bg-accent-soft/60")}>
                        <input type="checkbox" className="accent-[var(--accent)]" checked={!!p.selected?.has(key)}
                          onChange={(e) => {
                            const n = new Set(p.selected);
                            e.target.checked ? n.add(key) : n.delete(key);
                            p.onSelectedChange!(n);
                          }} />
                      </td>
                    )}
                    {cols.map((c) => (
                      <td
                        key={c.key}
                        className={cn(
                          "max-w-[340px] border-b border-border px-3 py-[7px] align-middle group-hover:bg-surface-2",
                          c.wrap ? "whitespace-normal" : "overflow-hidden text-ellipsis whitespace-nowrap",
                          c.num && "text-right tabular",
                          c.className
                        )}
                      >
                        {c.render ? c.render(r) : (r[c.key] ?? "")}
                      </td>
                    ))}
                  </tr>
                  {isOpen && p.renderExpanded && (
                    <tr>
                      <td colSpan={99} className="border-b border-border bg-surface-2 p-0">
                        {p.renderExpanded(r)}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center gap-2 border-t border-border px-3.5 py-2.5 text-[12.5px] text-fg-2">
        <span className="tabular">
          {fmtN(from)}–{fmtN(to)} of {fmtN(total)}
        </span>
        <div className="flex-1" />
        <label className="flex items-center gap-1.5">
          Rows
          <select
            className="h-7 rounded-md border border-border-strong bg-surface px-1.5"
            value={size}
            onChange={(e) => p.setState({ size: e.target.value })}
          >
            {[25, 50, 100, 250, 500].map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
        <Button size="sm" disabled={page <= 1} onClick={() => p.setState({ page: 1 })}><ChevronsLeft /></Button>
        <Button size="sm" disabled={page <= 1} onClick={() => p.setState({ page: page - 1 })}><ChevronLeft /> Prev</Button>
        <span className="tabular">
          Page {page} / {fmtN(pages)}
        </span>
        <Button size="sm" disabled={page >= pages} onClick={() => p.setState({ page: page + 1 })}>Next <ChevronRight /></Button>
        <Button size="sm" disabled={page >= pages} onClick={() => p.setState({ page: pages })}><ChevronsRight /></Button>
      </div>
    </Card>
  );
}

/* Client-side table for small arrays */
export function SimpleTable<T extends Record<string, any>>({ rows, columns, empty = "None", maxHeight, onRowClick }: {
  rows: T[]; columns: Column<T>[]; empty?: React.ReactNode; maxHeight?: string; onRowClick?: (r: T) => void;
}) {
  if (!rows?.length) return <Empty>{empty}</Empty>;
  return (
    <div className="overflow-auto scroll-thin" style={{ maxHeight }}>
      <table className="w-full border-separate border-spacing-0 text-[12.8px]">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={cn("sticky top-0 z-10 whitespace-nowrap border-b border-border bg-surface-2 px-3 py-2 text-left text-xs font-semibold text-fg-2", c.num && "text-right")}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className={cn("group", onRowClick && "cursor-pointer")} onClick={(e) => {
              if ((e.target as HTMLElement).closest("a,button")) return;
              onRowClick?.(r);
            }}>
              {columns.map((c) => (
                <td key={c.key} className={cn("border-b border-border px-3 py-[7px] group-hover:bg-surface-2", c.wrap ? "whitespace-normal" : "whitespace-nowrap", c.num && "text-right tabular")}>
                  {c.render ? c.render(r) : (r[c.key] ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


/* ---------------- filter on any field ---------------- */
const OPS: [string, string][] = [["has", "contains"], ["is", "is"], ["not", "does not contain"], ["empty", "is empty"], ["set", "is not empty"]];
const human = (k: string) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

function fieldList(columns: Column[], rows: any[]) {
  const out: { key: string; label: string }[] = [];
  const seen = new Set<string>();
  const sample = rows[0] || {};
  for (const c of columns) {
    if (c.key in sample && !seen.has(c.key)) { out.push({ key: c.key, label: c.label || human(c.key) }); seen.add(c.key); }
  }
  for (const k of Object.keys(sample)) {
    if (!seen.has(k) && !k.startsWith("_")) { out.push({ key: k, label: human(k) }); seen.add(k); }
  }
  return out;
}

/** "Filter" button: pick any field the table's API returns, an operator and values (several with |). */
function FieldFilter({ fields, rows, onAdd }: { fields: { key: string; label: string }[]; rows: any[]; onAdd: (key: string, value: string) => void }) {
  const [open, setOpen] = React.useState(false);
  const [key, setKey] = React.useState("");
  const [op, setOp] = React.useState("has");
  const [val, setVal] = React.useState("");
  const [fq, setFq] = React.useState("");
  const suggestions = React.useMemo(() => {
    if (!key) return [];
    const c = new Map<string, number>();
    for (const r of rows) {
      const v = r[key];
      const t = v == null ? "" : Array.isArray(v) ? v.join(", ") : typeof v === "object" ? "" : String(v);
      if (t && t.length < 80) c.set(t, (c.get(t) || 0) + 1);
    }
    return [...c.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([t]) => t);
  }, [key, rows]);
  const add = () => {
    if (!key || (!val.trim() && op !== "empty" && op !== "set")) return;
    onAdd(key, `${op}:${val.trim()}`);
    setOpen(false); setVal(""); setKey(""); setOp("has"); setFq("");
  };
  const shown = fields.filter((f) => !fq || f.label.toLowerCase().includes(fq.toLowerCase()) || f.key.includes(fq.toLowerCase()));
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild><Button size="sm" title="Filter on any field"><Filter /> Filter</Button></Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="end" sideOffset={6} collisionPadding={10} className="z-50 w-[360px] rounded-xl border border-border bg-surface p-3 shadow-xl">
          <div className="mb-2 text-[12px] font-semibold">Filter on any field</div>
          {!key ? (
            <>
              <Input autoFocus className="mb-2 w-full" placeholder="Search fields…" value={fq} onChange={(e) => setFq(e.target.value)} />
              <div className="max-h-64 overflow-auto scroll-thin">
                {shown.map((f) => (
                  <button key={f.key} className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-[12.5px] hover:bg-surface-2" onClick={() => setKey(f.key)}>
                    <span>{f.label}</span><span className="font-mono text-[10.5px] text-muted">{f.key}</span>
                  </button>
                ))}
                {!shown.length && <div className="px-2 py-2 text-[12px] text-muted">{fields.length ? "No field matches" : "Load some rows first"}</div>}
              </div>
            </>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-[12.5px]"><b>{fields.find((f) => f.key === key)?.label}</b>
                <button className="text-[11.5px] text-accent-fg hover:underline" onClick={() => setKey("")}>change field</button></div>
              <div className="flex flex-wrap gap-1">
                {OPS.map(([o, l]) => (
                  <button key={o} onClick={() => setOp(o)} className={cn("rounded-md border px-2 py-0.5 text-[12px]", op === o ? "border-accent bg-accent-soft text-accent-fg" : "border-border text-fg-2")}>{l}</button>
                ))}
              </div>
              {op !== "empty" && op !== "set" && (
                <>
                  <Input autoFocus className="w-full" placeholder="value (several: a | b)" value={val} onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
                  {suggestions.length > 0 && <div className="flex max-h-28 flex-wrap gap-1 overflow-auto">
                    {suggestions.map((t) => <button key={t} className="max-w-full truncate rounded-md bg-surface-2 px-1.5 py-0.5 text-[11.5px] hover:bg-surface-3"
                      onClick={() => setVal(val ? `${val} | ${t}` : t)}>{t}</button>)}
                  </div>}
                </>
              )}
              <div className="flex justify-end gap-2 pt-1"><Button size="sm" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button size="sm" variant="primary" onClick={add}>Apply</Button></div>
            </div>
          )}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
