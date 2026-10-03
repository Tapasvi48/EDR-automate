"use client";
import * as React from "react";
import { useRouter } from "next/navigation";

/** EDR history now lives on the Offline page (removed from console / old EDR import views). */
export default function EdrHistory() {
  const router = useRouter();
  React.useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const v = q.get("view") === "import" ? "import" : q.get("view") === "console" ? "removed" : "all";
    router.replace(v === "all" ? "/health/" : `/health/?view=${v}`);
  }, [router]);
  return null;
}
