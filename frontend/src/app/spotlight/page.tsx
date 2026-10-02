"use client";
import { Suspense } from "react";
import View from "@/views/spotlight";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
