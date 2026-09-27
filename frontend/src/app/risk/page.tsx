"use client";
import { Suspense } from "react";
import View from "@/views/risk";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
