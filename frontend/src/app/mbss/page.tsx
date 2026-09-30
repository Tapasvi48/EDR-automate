"use client";
import { Suspense } from "react";
import View from "@/views/mbss";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
