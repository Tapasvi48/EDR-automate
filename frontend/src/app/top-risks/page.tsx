"use client";
import { Suspense } from "react";
import View from "@/views/top-risks";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
