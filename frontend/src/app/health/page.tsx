"use client";
import { Suspense } from "react";
import View from "@/views/health";

export default function HealthPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
