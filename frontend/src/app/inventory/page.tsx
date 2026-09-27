"use client";
import { Suspense } from "react";
import View from "@/views/inventory";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
