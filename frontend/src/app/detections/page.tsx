"use client";
import { Suspense } from "react";
import View from "@/views/detections";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
