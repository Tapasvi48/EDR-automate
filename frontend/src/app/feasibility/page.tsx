"use client";
import { Suspense } from "react";
import View from "@/views/feasibility";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
