"use client";
import { Suspense } from "react";
import View from "@/views/attack-paths";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
