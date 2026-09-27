"use client";
import { Suspense } from "react";
import View from "@/views/matrix";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
