"use client";
import { Suspense } from "react";
import View from "@/views/patches";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
