"use client";
import { Suspense } from "react";
import View from "@/views/surface";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
