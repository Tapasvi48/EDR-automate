"use client";
import { Suspense } from "react";
import View from "@/views/scan-gaps";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
