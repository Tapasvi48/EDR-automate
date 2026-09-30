"use client";
import { Suspense } from "react";
import View from "@/views/analysts";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
