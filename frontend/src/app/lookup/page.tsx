"use client";
import { Suspense } from "react";
import View from "@/views/lookup";

export default function LookupPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
