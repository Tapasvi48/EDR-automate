"use client";
import { Suspense } from "react";
import View from "@/views/exposure";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
