"use client";
import { Suspense } from "react";
import View from "@/views/dashboard";

export default function HomePage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
