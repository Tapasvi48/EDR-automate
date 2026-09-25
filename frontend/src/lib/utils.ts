import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export type Params = Record<string, string | number | boolean | undefined | null>;

export function qs(params?: Params) {
  const u = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "" && v !== false) u.set(k, v === true ? "1" : String(v));
  });
  const s = u.toString();
  return s ? "?" + s : "";
}
