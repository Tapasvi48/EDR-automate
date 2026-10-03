"use client";
import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import * as DM from "@radix-ui/react-dropdown-menu";
import * as Pop from "@radix-ui/react-popover";
import { Check, ChevronDown, Loader2, Search, X } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { fmtBytes, fmtN, fmtSecs } from "@/lib/format";

/* ---------------- Button ---------------- */
type BtnProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "ghost" | "danger" | "soft";
  size?: "sm" | "md" | "icon";
  loading?: boolean;
};
export const Button = React.forwardRef<HTMLButtonElement, BtnProps>(function Button(
  { className, variant = "default", size = "md", loading, children, disabled, ...p },
  ref
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg font-medium transition-colors",
        "focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50 disabled:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
        size === "sm" && "h-7 px-2.5 text-xs",
        size === "md" && "h-8.5 px-3 text-[13px]",
        size === "icon" && "size-8",
        variant === "default" && "border border-border-strong bg-surface text-fg hover:bg-surface-3 shadow-card",
        variant === "primary" && "bg-accent text-white hover:brightness-110 shadow-card",
        variant === "ghost" && "text-fg-2 hover:bg-surface-3 hover:text-fg",
        variant === "soft" && "bg-accent-soft text-accent-fg hover:brightness-95",
        variant === "danger" && "border border-border-strong bg-surface text-crit-fg hover:bg-crit-soft",
        className
      )}
      {...p}
    >
      {loading && <Loader2 className="animate-spin" />}
      {children}
    </button>
  );
});

/* ---------------- Card ---------------- */
export function Card({ className, children, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("rounded-xl border border-border bg-surface shadow-card min-w-0", className)} {...p}>
      {children}
    </div>
  );
}
export function CardHeader({ title, hint, right, className }: { title: React.ReactNode; hint?: React.ReactNode; right?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 px-4 pt-3.5 pb-2 flex-wrap", className)}>
      <h2 className="text-[14px] font-semibold">{title}</h2>
      {hint && <span className="text-xs text-muted">{hint}</span>}
      {right && <div className="ml-auto flex items-center gap-2">{right}</div>}
    </div>
  );
}

/* ---------------- Badge ---------------- */
export type Tone = "neutral" | "good" | "warn" | "serious" | "crit" | "info" | "violet" | "outline";
const TONES: Record<Tone, string> = {
  neutral: "bg-surface-3 text-fg-2",
  good: "bg-good-soft text-good-fg",
  warn: "bg-warn-soft text-warn-fg",
  serious: "bg-serious-soft text-serious-fg",
  crit: "bg-crit-soft text-crit-fg",
  info: "bg-accent-soft text-accent-fg",
  violet: "bg-violet-soft text-violet-fg",
  outline: "border border-border-strong text-fg-2",
};
export function Badge({ tone = "neutral", className, children, title }: { tone?: Tone; className?: string; children: React.ReactNode; title?: string }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1 rounded-full px-2 py-px text-[11px] font-semibold leading-[18px] whitespace-nowrap", TONES[tone], className)}>
      {children}
    </span>
  );
}

/* ---------------- Inputs ---------------- */
export const inputCls =
  "h-8.5 rounded-lg border border-border-strong bg-surface px-2.5 text-[13px] text-fg placeholder:text-muted focus:outline-2 focus:outline-accent focus:-outline-offset-1 min-w-0";
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...p }, ref) {
  return <input ref={ref} className={cn(inputCls, className)} {...p} />;
});
export function Select({ className, value, onChange, options, placeholder, ...p }: Omit<React.SelectHTMLAttributes<HTMLSelectElement>, "onChange"> & {
  value?: string;
  onChange: (v: string) => void;
  options: (string | [string, string] | { value: string | number; label: string })[];
  placeholder?: string;
}) {
  return (
    <select className={cn(inputCls, "pr-7 max-w-[210px]", className)} value={value ?? ""} onChange={(e) => onChange(e.target.value)} {...p}>
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => {
        const [v, l] = Array.isArray(o) ? o : typeof o === "object" ? [String(o.value), o.label] : [o, o];
        return (
          <option key={v} value={v}>
            {l}
          </option>
        );
      })}
    </select>
  );
}
export function SearchInput({ value, onChange, placeholder, className, autoFocus, big }: { value: string; onChange: (v: string) => void; placeholder?: string; className?: string; autoFocus?: boolean; big?: boolean }) {
  const [v, setV] = React.useState(value);
  React.useEffect(() => setV(value), [value]);
  React.useEffect(() => {
    if (v === value) return;
    const t = setTimeout(() => onChange(v), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [v]);
  return (
    <div className={cn("relative min-w-0", className)}>
      <Search className={cn("absolute left-2.5 top-1/2 -translate-y-1/2 text-muted", big ? "size-5 left-3" : "size-4")} />
      <input
        autoFocus={autoFocus}
        className={cn(inputCls, "w-full pl-8", big && "h-11 pl-10 text-[15px] rounded-xl")}
        value={v}
        placeholder={placeholder}
        onChange={(e) => setV(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && onChange(v)}
      />
      {v && (
        <button className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-fg" onClick={() => { setV(""); onChange(""); }}>
          <X className="size-4" />
        </button>
      )}
    </div>
  );
}
export function Field({ label, children, hint, className }: { label: string; children: React.ReactNode; hint?: React.ReactNode; className?: string }) {
  return (
    <label className={cn("flex min-w-0 flex-col gap-1 [&>input]:w-full [&>select]:w-full [&>textarea]:w-full", className)}>
      <span className="text-xs font-medium text-fg-2">{label}</span>
      {children}
      {hint && <span className="text-[11.5px] text-muted">{hint}</span>}
    </label>
  );
}
export function Checkbox({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: React.ReactNode }) {
  return (
    <label className="inline-flex items-center gap-2 text-[12.5px] text-fg-2 cursor-pointer select-none">
      <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

/* ---------------- Chip / Segmented / Tabs ---------------- */
export function Chip({ on, onClick, children, count }: { on?: boolean; onClick: () => void; children: React.ReactNode; count?: number }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 h-7 rounded-full border px-3 text-xs font-medium transition-colors",
        on ? "border-accent bg-accent-soft text-accent-fg" : "border-border-strong bg-surface text-fg-2 hover:border-accent"
      )}
    >
      {children}
      {count !== undefined && <span className="tabular opacity-70">{fmtN(count)}</span>}
    </button>
  );
}
export function Segmented<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: [T, React.ReactNode][] }) {
  return (
    <div className="inline-flex rounded-lg border border-border-strong bg-surface p-0.5 shadow-card">
      {options.map(([v, l]) => (
        <button
          key={v}
          onClick={() => onChange(v)}
          className={cn("h-7 rounded-md px-2.5 text-xs font-medium transition-colors", value === v ? "bg-accent-soft text-accent-fg" : "text-fg-2 hover:text-fg")}
        >
          {l}
        </button>
      ))}
    </div>
  );
}
export function Tabs({ value, onChange, tabs }: { value: string; onChange: (v: string) => void; tabs: { id: string; label: React.ReactNode; count?: number }[] }) {
  return (
    <div className="flex gap-1 border-b border-border mb-4 overflow-x-auto">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            "px-3.5 py-2.5 text-[13px] font-medium border-b-2 -mb-px whitespace-nowrap transition-colors",
            value === t.id ? "border-accent text-accent-fg" : "border-transparent text-fg-2 hover:text-fg"
          )}
        >
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 rounded-full bg-surface-3 px-1.5 text-[11px] tabular">{fmtN(t.count)}</span>}
        </button>
      ))}
    </div>
  );
}

/* ---------------- KPI ---------------- */
const KPI_TONE: Record<string, string> = {
  good: "before:bg-good", warn: "before:bg-warn", serious: "before:bg-serious", crit: "before:bg-crit", info: "before:bg-accent", violet: "before:bg-violet", neutral: "before:bg-transparent",
};
export function Kpi({ label, value, foot, tone = "neutral", href, onClick, icon, title, active }: {
  label: React.ReactNode; value: React.ReactNode; foot?: React.ReactNode; tone?: string; href?: string; onClick?: () => void; icon?: React.ReactNode; title?: string; active?: boolean;
}) {
  const inner = (
    <div
      title={title}
      onClick={onClick}
      className={cn(
        "relative overflow-hidden rounded-xl border bg-surface px-4 py-3 shadow-card transition-all h-full",
        "before:absolute before:left-0 before:top-0 before:bottom-0 before:w-[3px]",
        KPI_TONE[tone] || "",
        active ? "border-accent ring-2 ring-accent/20" : "border-border",
        (href || onClick) && "cursor-pointer hover:border-accent hover:-translate-y-px"
      )}
    >
      <div className="flex items-center gap-1.5 text-xs font-medium text-fg-2">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-[26px] font-semibold tracking-tight leading-tight">{typeof value === "number" ? fmtN(value) : value}</div>
      {foot && <div className="mt-0.5 text-[11.5px] text-muted">{foot}</div>}
    </div>
  );
  return href ? <Link href={href} className="block">{inner}</Link> : inner;
}
export function KpiGrid({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("grid gap-3 grid-cols-[repeat(auto-fill,minmax(180px,1fr))]", className)}>{children}</div>;
}

/* ---------------- misc ---------------- */
export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("size-5 animate-spin text-muted", className)} />;
}
export function Empty({ children = "No matching records", className }: { children?: React.ReactNode; className?: string }) {
  return <div className={cn("py-10 text-center text-muted text-[13px]", className)}>{children}</div>;
}
/** Spinner while a query loads; a clear message + retry once it fails (instead of spinning forever). */
export function Loading({ error, retry }: { error?: unknown; retry?: () => void }) {
  if (error) {
    const msg = error instanceof Error ? error.message : String(error);
    const missing = /^404\b/.test(msg) || /Not Found/i.test(msg);
    return (
      <div className="mx-auto my-10 max-w-lg rounded-xl border border-border bg-surface p-5 text-center">
        <div className="text-[14px] font-semibold text-crit-fg">{missing ? "This feature isn't available on the running server" : "Couldn't load this data"}</div>
        <div className="mt-1.5 text-[12.5px] text-fg-2">
          {missing ? <>The page was updated but the backend is an older build. Restart it (<code className="font-mono">./run.sh</code> or restart the container) and reload.</> : msg}
        </div>
        {retry && <button onClick={retry} className="mt-3 rounded-lg border border-border px-3 py-1.5 text-[12.5px] hover:bg-surface-2">Try again</button>}
      </div>
    );
  }
  return (
    <div className="flex items-center justify-center py-16">
      <Spinner />
    </div>
  );
}
export function Meter({ value, tone }: { value: number; tone?: string }) {
  const color = tone || (value >= 95 ? "var(--good)" : value >= 80 ? "var(--warn)" : "var(--crit)");
  return (
    <div title={`${value}%`} className="h-2 w-full rounded-full bg-surface-3 overflow-hidden">
      <div className="h-full rounded-full" style={{ width: `${Math.min(100, value)}%`, background: color }} />
    </div>
  );
}
export function Callout({ tone = "info", children, className }: { tone?: "info" | "warn" | "crit" | "good"; children: React.ReactNode; className?: string }) {
  const cls = { info: "bg-accent-soft text-accent-fg", warn: "bg-warn-soft text-warn-fg", crit: "bg-crit-soft text-crit-fg", good: "bg-good-soft text-good-fg" }[tone];
  return <div className={cn("rounded-lg px-3 py-2.5 text-[12.5px]", cls, className)}>{children}</div>;
}
export function PageHeader({ title, sub, actions }: { title: React.ReactNode; sub?: React.ReactNode; actions?: React.ReactNode }) {
  // long descriptions stay to one line; "more" shows the rest
  const [more, setMore] = React.useState(false);
  const long = typeof sub === "string" && sub.length > 150;
  return (
    <div className="mb-5 flex flex-wrap items-end gap-3">
      <div className="min-w-0 max-w-4xl">
        <h1 className="text-[21px] font-semibold tracking-tight">{title}</h1>
        {sub && (long ? (
          <div className="mt-1 flex items-start gap-1.5 text-[12.5px] text-muted">
            <span className={more ? "" : "line-clamp-1"}>{sub}</span>
            <button className="shrink-0 text-accent-fg hover:underline" onClick={() => setMore(!more)}>{more ? "less" : "more"}</button>
          </div>
        ) : <div className="mt-1 text-[12.5px] text-muted">{sub}</div>)}
      </div>
      {actions && <div className="ml-auto flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
export function SectionTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h3 className={cn("mb-2.5 mt-6 text-[11.5px] font-semibold uppercase tracking-wider text-muted", className)}>{children}</h3>;
}
export function KV({ items }: { items: [string, React.ReactNode][] }) {
  return (
    <div className="grid gap-x-5 gap-y-3 grid-cols-[repeat(auto-fill,minmax(200px,1fr))]">
      {items.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <div className="text-[11.5px] text-muted">{k}</div>
          <div className="font-medium break-words">{v === "" || v === null || v === undefined ? <span className="text-muted">–</span> : v}</div>
        </div>
      ))}
    </div>
  );
}

/* ---------------- Progress ---------------- */
/** Long-running task: determinate bar with bytes / speed / ETA when `loaded`+`total` are known, otherwise an
 *  indeterminate bar. Elapsed time always ticks so the user can see work is still going. */
export function ProgressPanel({ label, detail, loaded, total, startedAt, className }: {
  label: React.ReactNode; detail?: React.ReactNode; loaded?: number; total?: number; startedAt: number; className?: string;
}) {
  const [now, setNow] = React.useState(Date.now());
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, []);
  const elapsed = (now - startedAt) / 1000;
  const known = !!total && loaded !== undefined;
  const frac = known ? Math.min(1, loaded! / total!) : 0;
  const speed = known && elapsed > 0.3 ? loaded! / elapsed : 0;
  const eta = speed ? (total! - loaded!) / speed : null;
  return (
    <div className={cn("rounded-xl border border-border bg-surface-2 px-4 py-3", className)} role="status" aria-live="polite">
      <div className="flex items-center gap-2 text-[13px] font-medium">
        <Loader2 className="size-4 animate-spin text-accent" />
        <span className="min-w-0 flex-1 truncate">{label}</span>
        {known && <span className="tabular text-accent-fg">{Math.round(frac * 100)}%</span>}
      </div>
      <div className={cn("relative mt-2 h-2 overflow-hidden rounded-full bg-surface-3", !known && "loadbar")}>
        {known && <div className="h-full rounded-full bg-accent transition-[width] duration-200" style={{ width: `${frac * 100}%` }} />}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 text-[11.5px] text-muted tabular">
        {known && <span>{fmtBytes(loaded!)} of {fmtBytes(total!)}</span>}
        {speed > 0 && frac < 1 && <span>{fmtBytes(speed)}/s</span>}
        {eta !== null && frac < 1 && <span>~{fmtSecs(eta)} left</span>}
        {detail && <span>{detail}</span>}
        <span className="ml-auto">{fmtSecs(elapsed)} elapsed</span>
      </div>
    </div>
  );
}

/* ---------------- Sheet (drawer) & Modal ---------------- */
export function Sheet({ open, onOpenChange, title, sub, actions, children, width = 960 }: {
  open: boolean; onOpenChange: (v: boolean) => void; title: React.ReactNode; sub?: React.ReactNode; actions?: React.ReactNode; children: React.ReactNode; width?: number;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 anim-fade" />
        <Dialog.Content
          aria-describedby={undefined}
          className="fixed right-0 top-0 bottom-0 z-50 flex flex-col bg-bg shadow-2xl anim-slide outline-none"
          style={{ width: `min(${width}px, 97vw)` }}
        >
          <div className="flex items-start gap-3 border-b border-border bg-surface px-5 py-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-[17px] font-semibold">{title}</Dialog.Title>
              {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
            </div>
            {actions}
            <Dialog.Close asChild>
              <Button variant="ghost" size="icon"><X /></Button>
            </Dialog.Close>
          </div>
          <div className="flex-1 overflow-y-auto px-5 py-4 pb-12 scroll-thin">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export function Modal({ open, onOpenChange, title, children, footer, wide }: {
  open: boolean; onOpenChange: (v: boolean) => void; title: React.ReactNode; children: React.ReactNode; footer?: React.ReactNode; wide?: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/40 anim-fade" />
        <Dialog.Content
          aria-describedby={undefined}
          className="fixed left-1/2 top-1/2 z-50 flex max-h-[92vh] flex-col rounded-2xl bg-surface shadow-2xl anim-pop outline-none"
          style={{ width: wide ? "min(1200px, 96vw)" : "min(640px, 94vw)", transform: "translate(-50%, -50%)" }}
        >
          <div className="flex items-center gap-3 border-b border-border px-5 py-3.5">
            <Dialog.Title className="text-[16px] font-semibold">{title}</Dialog.Title>
            <Dialog.Close asChild>
              <Button variant="ghost" size="icon" className="ml-auto"><X /></Button>
            </Dialog.Close>
          </div>
          <div className="flex-1 overflow-y-auto px-5 py-4 scroll-thin">{children}</div>
          {footer && <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{footer}</div>}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/* ---------------- Confirm (promise based) ---------------- */
type ConfirmOpts = { title: string; body: React.ReactNode; ok?: string; danger?: boolean };
const ConfirmCtx = React.createContext<(o: ConfirmOpts) => Promise<boolean>>(async () => false);
export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = React.useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null);
  const confirm = React.useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => setState({ ...o, resolve })), []);
  const close = (v: boolean) => {
    state?.resolve(v);
    setState(null);
  };
  return (
    <ConfirmCtx.Provider value={confirm}>
      {children}
      <Modal
        open={!!state}
        onOpenChange={(o) => !o && close(false)}
        title={state?.title}
        footer={
          <>
            <Button onClick={() => close(false)}>Cancel</Button>
            <Button variant={state?.danger ? "danger" : "primary"} onClick={() => close(true)}>{state?.ok || "Confirm"}</Button>
          </>
        }
      >
        <div className="text-[13.5px]">{state?.body}</div>
      </Modal>
    </ConfirmCtx.Provider>
  );
}
export const useConfirm = () => React.useContext(ConfirmCtx);

/* ---------------- Menu (dropdown of actions) ---------------- */
export type MenuItem = { label: React.ReactNode; icon?: React.ReactNode; onSelect: () => void; danger?: boolean; hint?: React.ReactNode } | "sep";
export function Menu({ trigger, items, align = "end", width = 240 }: { trigger: React.ReactNode; items: MenuItem[]; align?: "start" | "end"; width?: number }) {
  return (
    <DM.Root modal={false}>
      <DM.Trigger asChild>{trigger}</DM.Trigger>
      <DM.Portal>
        <DM.Content align={align} sideOffset={6} style={{ width }} className="z-50 rounded-xl border border-border bg-surface p-1.5 shadow-xl">
          {items.map((it, i) => it === "sep" ? <DM.Separator key={i} className="my-1 h-px bg-border" /> : (
            <DM.Item key={i} onSelect={it.onSelect}
              className={cn("flex cursor-pointer select-none items-start gap-2.5 rounded-lg px-2.5 py-2 text-[13px] outline-none data-[highlighted]:bg-surface-2 [&_svg]:mt-0.5 [&_svg]:size-4 [&_svg]:shrink-0",
                it.danger ? "text-crit-fg" : "text-fg")}>
              {it.icon && <span className={it.danger ? "" : "text-fg-2"}>{it.icon}</span>}
              <span className="min-w-0">
                <span className="block font-medium">{it.label}</span>
                {it.hint && <span className="block text-[11.5px] leading-snug text-muted">{it.hint}</span>}
              </span>
            </DM.Item>
          ))}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

/* ---------------- Labelled filter select ---------------- */
type Opt = string | [string, string] | { value: string | number; label: string };
const optPair = (o: Opt): [string, string] => (Array.isArray(o) ? o : typeof o === "object" ? [String(o.value), o.label] : [o, o]);
/** A filter that always says what it filters: "Status: Any ▾". Multi-select by default (values joined with "|", which
 *  every list API reads as "any of"); `single` for sort / view pickers and yes-no switches. Searchable when long. */
export function FilterSelect({ label, value, onChange, options, any = "Any", className, single }: {
  label: string; value?: string; onChange: (v: string) => void; options: Opt[]; any?: string; className?: string; single?: boolean;
}) {
  const [open, setOpen] = React.useState(false);
  const [q, setQ] = React.useState("");
  const pairs = options.map(optPair);
  const picked = (value ?? "").split("|").filter(Boolean);
  const labelOf = (v: string) => pairs.find(([x]) => x === v)?.[1] ?? v;
  const on = picked.length > 0;
  const shown = pairs.filter(([, l]) => !q || l.toLowerCase().includes(q.toLowerCase()));
  const toggle = (v: string) => {
    if (single) { onChange(v); setOpen(false); return; }
    const next = picked.includes(v) ? picked.filter((x) => x !== v) : [...picked, v];
    onChange(next.join("|"));
  };
  const text = !on ? any : picked.length === 1 ? labelOf(picked[0]) : `${labelOf(picked[0])} +${picked.length - 1}`;
  return (
    <Pop.Root open={open} onOpenChange={(o) => { setOpen(o); if (!o) setQ(""); }}>
      <Pop.Trigger asChild>
        <button type="button" title={on ? picked.map(labelOf).join(", ") : undefined}
          className={cn("inline-flex h-8.5 min-w-0 max-w-[280px] items-center gap-1 rounded-lg border pl-2.5 pr-2 text-[13px] shadow-card transition-colors",
            on ? "border-accent bg-accent-soft" : "border-border-strong bg-surface hover:border-fg-2/40", className)}>
          <span className="shrink-0 whitespace-nowrap text-muted">{label}:</span>
          <span className={cn("min-w-0 truncate", on ? "font-semibold text-accent-fg" : "font-medium text-fg")}>{text}</span>
          {on && !single ? <span role="button" aria-label={`Clear ${label}`} className="ml-0.5 rounded p-0.5 text-muted hover:bg-surface-3 hover:text-fg"
            onClick={(e) => { e.stopPropagation(); onChange(""); }}><X className="size-3" /></span>
            : <ChevronDown className="size-3.5 shrink-0 text-muted" />}
        </button>
      </Pop.Trigger>
      <Pop.Portal>
        <Pop.Content align="start" sideOffset={6} className="z-50 w-[min(340px,90vw)] rounded-xl border border-border bg-surface p-1.5 shadow-xl">
          {pairs.length > 8 && (
            <div className="mb-1 flex items-center gap-1.5 rounded-lg border border-border px-2">
              <Search className="size-3.5 text-muted" />
              <input autoFocus className="h-8 w-full bg-transparent text-[13px] outline-none" placeholder={`Search ${label.toLowerCase()}…`} value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
          )}
          <div className="max-h-72 overflow-auto">
            <button type="button" onClick={() => { onChange(""); if (single) setOpen(false); }}
              className={cn("flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-[13px] hover:bg-surface-2", !on && "font-semibold text-accent-fg")}>
              <span className="w-4">{!on && <Check className="size-3.5" />}</span>{any}
            </button>
            {shown.map(([v, l]) => {
              const sel = picked.includes(v);
              return (
                <button type="button" key={v} onClick={() => toggle(v)}
                  className={cn("flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-[13px] hover:bg-surface-2", sel && "font-semibold text-accent-fg")}>
                  {single ? <span className="w-4 shrink-0">{sel && <Check className="size-3.5" />}</span>
                    : <span className={cn("flex size-4 shrink-0 items-center justify-center rounded border", sel ? "border-accent bg-accent text-white" : "border-border-strong")}>{sel && <Check className="size-3" />}</span>}
                  <span className="min-w-0 break-words">{l}</span>
                </button>
              );
            })}
            {!shown.length && <div className="px-2.5 py-2 text-[12.5px] text-muted">No match</div>}
          </div>
          {!single && on && <div className="mt-1 flex items-center justify-between border-t border-border px-2 pt-1.5 text-[12px] text-muted">
            <span>{picked.length} selected</span>
            <button type="button" className="text-accent-fg hover:underline" onClick={() => setOpen(false)}>Done</button></div>}
        </Pop.Content>
      </Pop.Portal>
    </Pop.Root>
  );
}
