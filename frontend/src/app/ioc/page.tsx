"use client";
import { Suspense } from "react";
import View from "@/views/ioc";

export default function Page() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
