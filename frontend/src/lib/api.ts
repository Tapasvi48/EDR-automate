import { toast } from "sonner";
import { qs, type Params } from "./utils";

export class ApiError extends Error {}

export async function api<T = any>(path: string, opts: { method?: string; body?: any; params?: Params } = {}): Promise<T> {
  const init: RequestInit = { method: opts.method || "GET", headers: {} };
  if (opts.body instanceof FormData) init.body = opts.body;
  else if (opts.body !== undefined) {
    init.body = JSON.stringify(opts.body);
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
  }
  const r = await fetch(path + qs(opts.params), init);
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail ?? j);
    } catch {}
    throw new ApiError(msg);
  }
  return r.json();
}

export function downloadExcel(path: string, params?: Params) {
  toast.message("Preparing Excel export…");
  const a = document.createElement("a");
  a.href = path + qs(params);
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
