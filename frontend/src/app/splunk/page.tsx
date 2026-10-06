"use client";
import { Suspense } from "react";
import View from "@/views/splunk";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
