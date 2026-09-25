"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";

/** Page filter state mirrored into the URL query string (shareable, back-button friendly). */
export function useUrlState(defaults: Record<string, string> = {}) {
  const sp = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const state = useMemo(() => {
    const o: Record<string, string> = { ...defaults };
    sp.forEach((v, k) => (o[k] = v));
    return o;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sp]);
  const set = useCallback(
    (patch: Record<string, string | number | undefined | null>, opts: { resetPage?: boolean } = { resetPage: true }) => {
      const next = new URLSearchParams(sp.toString());
      Object.entries(patch).forEach(([k, v]) => {
        if (v === undefined || v === null || v === "") next.delete(k);
        else next.set(k, String(v));
      });
      if (opts.resetPage !== false && !("page" in patch)) next.delete("page");
      Object.entries(defaults).forEach(([k, v]) => {
        if (next.get(k) === v) next.delete(k);
      });
      const s = next.toString();
      router.replace(pathname + (s ? "?" + s : ""), { scroll: false });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sp, pathname, router]
  );
  const replaceAll = useCallback(
    (o: Record<string, string>) => {
      const s = new URLSearchParams(Object.entries(o).filter(([, v]) => v !== "" && v !== undefined)).toString();
      router.replace(pathname + (s ? "?" + s : ""), { scroll: false });
    },
    [pathname, router]
  );
  return [state, set, replaceAll] as const;
}

export function useDebounced<T>(value: T, ms = 300) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function useMeta() {
  return useQuery({ queryKey: ["meta"], queryFn: () => api<Meta>("/api/meta"), staleTime: 60_000 });
}

export function usePrevious<T>(v: T) {
  const r = useRef<T>(v);
  useEffect(() => {
    r.current = v;
  }, [v]);
  return r.current;
}

export type Meta = {
  connected: boolean;
  inventory_fields: [string, string][];
  key_fields: Record<string, string>;
  platforms: string[];
  os: string[];
  product_types: string[];
  domains: string[];
  sites: string[];
  agent_versions: string[];
  chassis: string[];
  lobs: { id: number; name: string }[];
  msps: { id: number; name: string; lob_id: number }[];
  node_types: string[];
  templates: { id: number; name: string; key_field: string }[];
  settings: Record<string, string>;
};
