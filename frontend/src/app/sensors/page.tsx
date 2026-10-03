"use client";
import { Suspense } from "react";
import View from "@/views/sensors";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
