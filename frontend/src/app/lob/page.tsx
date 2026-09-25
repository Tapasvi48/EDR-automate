"use client";
import { Suspense } from "react";
import View from "@/views/lob";

export default function LobPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
