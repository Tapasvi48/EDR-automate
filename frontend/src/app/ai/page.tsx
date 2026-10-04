"use client";
import { Suspense } from "react";
import View from "@/views/ai-full";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
