"use client";
import { Suspense } from "react";
import View from "@/views/possible-matches";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
