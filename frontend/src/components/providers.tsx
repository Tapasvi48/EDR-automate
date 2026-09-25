"use client";
import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { ConfirmProvider } from "./ui";
import { HostDrawerProvider } from "./host-drawer";

export function Providers({ children }: { children: React.ReactNode }) {
  const [qc] = React.useState(
    () => new QueryClient({ defaultOptions: { queries: { staleTime: 20_000, refetchOnWindowFocus: false, retry: 1 } } })
  );
  return (
    <QueryClientProvider client={qc}>
      <ConfirmProvider>
        <HostDrawerProvider>{children}</HostDrawerProvider>
      </ConfirmProvider>
      <Toaster position="bottom-right" richColors closeButton />
    </QueryClientProvider>
  );
}
