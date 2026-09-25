"use client";
import { Suspense } from "react";
import View from "@/views/reports";

export default function ReportsPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
