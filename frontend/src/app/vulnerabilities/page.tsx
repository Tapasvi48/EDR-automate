"use client";
import { Suspense } from "react";
import View from "@/views/vulnerabilities";

export default function VulnerabilitiesPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
