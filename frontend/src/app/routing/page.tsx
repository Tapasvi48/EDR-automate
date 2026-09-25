"use client";
import { Suspense } from "react";
import { PairGroups } from "@/views/duplicates";

export default function RoutingPage() {
  return (
    <Suspense>
      <PairGroups kind="routing" />
    </Suspense>
  );
}
