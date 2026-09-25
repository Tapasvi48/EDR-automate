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

export type UploadProgress = { loaded: number; total: number; startedAt: number };

/** POST a FormData with upload progress events (fetch has none). */
export function apiUpload<T = any>(path: string, body: FormData, onProgress: (p: UploadProgress) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const startedAt = Date.now();
    xhr.open("POST", path);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress({ loaded: e.loaded, total: e.total, startedAt });
    xhr.onload = () => {
      let j: any = null;
      try { j = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(j);
      else reject(new ApiError(j && typeof j.detail === "string" ? j.detail : `${xhr.status} ${xhr.statusText}`));
    };
    xhr.onerror = () => reject(new ApiError("Network error during upload"));
    xhr.send(body);
  });
}
