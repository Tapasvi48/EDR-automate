"use client";
import { Suspense } from "react";
import View from "@/views/falcon-mcp";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
