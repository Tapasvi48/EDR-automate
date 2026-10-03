"use client";
import { Suspense } from "react";
import View from "@/views/subnets";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
