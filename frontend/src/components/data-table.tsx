"use client";
import * as React from "react";
import * as Popover from "@radix-ui/react-popover";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Columns3, Download, RotateCcw } from "lucide-react";
import { api, downloadExcel } from "@/lib/api";
import { fmtN } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button, Card, Empty } from "./ui";

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
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const cols = p.columns.filter((c) => !hidden.has(c.key));
  const rows = q.data?.rows || [];
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / size));
  const from = total ? (page - 1) * size + 1 : 0;
  const to = Math.min(total, page * size);
  const rk = p.rowKey || ((r: T) => String(r.aid ?? r.item_key ?? r.id ?? r.value ?? JSON.stringify(r)));

  const toggleSort = (s: string) => {
    if (p.state.sort === s) p.setState({ dir: p.state.dir === "asc" ? "desc" : "asc" });
    else p.setState({ sort: s, dir: "desc" });
  };

  return (
    <Card className="relative overflow-hidden">
      {p.filters && <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-3">{p.filters}</div>}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3.5 py-2.5">
        {p.title && <span className="font-semibold">{p.title}</span>}
        <span className="text-fg-2">
          <b className="tabular text-fg">{q.data ? fmtN(total) : "–"}</b> {p.noun || "rows"}
        </span>
        <div className="flex-1" />
        {p.toolbar}
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
            <Popover.Content align="end" sideOffset={6} className="z-50 max-h-[420px] w-60 overflow-y-auto rounded-xl border border-border bg-surface p-2 shadow-xl scroll-thin">
              <div className="flex items-center gap-2 px-1.5 pb-2 text-xs">
                <b>Columns</b>
                <span className="flex-1" />
                <button className="text-accent-fg hover:underline" onClick={() => saveHidden(new Set())}>All</button>
                <button className="text-accent-fg hover:underline" onClick={() => saveHidden(new Set(p.columns.filter((c) => c.hidden).map((c) => c.key)))}>Default</button>
              </div>
              {p.columns.map((c) => (
                <label key={c.key} className="flex cursor-pointer items-center gap-2 rounded-md px-1.5 py-1 text-[12.5px] hover:bg-surface-2">
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
                  {c.label || c.key}
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
