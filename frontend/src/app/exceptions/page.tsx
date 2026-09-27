"use client";
import { Suspense } from "react";
import View from "@/views/exceptions";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
