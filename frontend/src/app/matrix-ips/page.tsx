"use client";
import { Suspense } from "react";
import View from "@/views/matrix-ips";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
