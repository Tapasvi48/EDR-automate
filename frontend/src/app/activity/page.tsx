"use client";
import { Suspense } from "react";
import View from "@/views/activity";

export default function ActivityPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
