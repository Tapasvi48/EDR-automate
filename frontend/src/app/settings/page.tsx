"use client";
import { Suspense } from "react";
import View from "@/views/settings";

export default function SettingsPage() {
  return (
    <Suspense>
      <View />
    </Suspense>
  );
}
