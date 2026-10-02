"use client";
import { Suspense } from "react";
import View from "@/views/alerts";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
