"use client";
import { Suspense } from "react";
import View from "@/views/coverage";

export default function CoveragePage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
