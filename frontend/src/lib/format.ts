export const fmtN = (n: any) => (n === null || n === undefined || n === "" ? "–" : Number(n).toLocaleString());

export function parseTs(ts?: string | null) {
  if (!ts) return null;
  const d = new Date(ts);
  return isNaN(+d) ? null : d;
}
const p2 = (n: number) => String(n).padStart(2, "0");
export function fmtDt(ts?: string | null) {
  const d = parseTs(ts);
  if (!d) return "–";
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}
export function fmtDate(ts?: string | null) {
  const s = fmtDt(ts);
  return s === "–" ? s : s.slice(0, 10);
}
export function hoursSince(ts?: string | null) {
  const d = parseTs(ts);
  return d ? (Date.now() - d.getTime()) / 3600000 : null;
}
export function fmtRel(ts?: string | null) {
  const h = hoursSince(ts);
  if (h === null) return "–";
  const m = h * 60;
  if (m < 1) return "just now";
  if (m < 60) return `${Math.round(m)}m ago`;
  if (h < 48) return `${h < 10 ? h.toFixed(1).replace(/\.0$/, "") : Math.round(h)}h ago`;
  const d = h / 24;
  if (d < 60) return `${Math.round(d)}d ago`;
  if (d < 730) return `${Math.round(d / 30)}mo ago`;
  return `${(d / 365).toFixed(1)}y ago`;
}
export function isoDate(d: Date) {
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())}`;
}
export function daysAgo(n: number) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return isoDate(d);
}
export const today = () => isoDate(new Date());
export const pct = (a: number, b: number) => (b ? Math.round((1000 * a) / b) / 10 : 0);

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export const shortDay = (d: string) => {
  const [, m, dd] = d.split("-");
  return `${+dd} ${MONTHS[+m - 1]}`;
};

export function fillDays<T extends Record<string, any>>(rows: T[], start: string, end: string, keys: string[]) {
  const map = Object.fromEntries(rows.map((r) => [r.day, r]));
  const out: Record<string, any>[] = [];
  const d = new Date(start + "T00:00:00");
  const e = new Date(end + "T00:00:00");
  while (d <= e) {
    const k = isoDate(d);
    const r = map[k] || {};
    const o: Record<string, any> = { day: k };
    keys.forEach((key) => (o[key] = r[key] || 0));
    out.push(o);
    d.setDate(d.getDate() + 1);
  }
  return out;
}
export function fmtBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}
export function fmtSecs(s: number) {
  s = Math.max(0, Math.round(s));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}
