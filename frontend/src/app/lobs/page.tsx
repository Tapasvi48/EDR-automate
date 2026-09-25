"use client";
import { Suspense } from "react";
import View from "@/views/lobs";

export default function LobsPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
