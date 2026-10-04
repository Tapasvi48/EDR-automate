"use client";
import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { LayoutGrid, MessagesSquare, PanelLeft } from "lucide-react";
import { ChatPanel, Orb } from "@/components/ai/chat";
import FalconMcp from "@/views/falcon-mcp";

/** AI SOC in its own window (no console navigation): ?focus=chat shows only the assistant, full screen. */
export default function AiFull() {
  const sp = useSearchParams();
  const chatOnly = sp.get("focus") === "chat";
  React.useEffect(() => { document.title = chatOnly ? "AI SOC · Assistant" : "AI SOC"; }, [chatOnly]);
  return (
    <div className="flex h-screen flex-col bg-bg">
      <div className="flex h-12 shrink-0 items-center gap-2.5 border-b border-border bg-surface/85 px-4 backdrop-blur">
        <Orb size={26} />
        <b className="text-[14px]">AI SOC</b>
        <span className="text-[12px] text-muted">{chatOnly ? "Assistant · full screen" : "full window"}</span>
        <div className="flex-1" />
        {chatOnly ? (
          <Link href="/ai/" className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12.5px] text-fg-2 hover:bg-surface-2 hover:text-fg"><LayoutGrid className="size-4" /> All AI SOC tools</Link>
        ) : (
          <Link href="/ai/?focus=chat" className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12.5px] text-fg-2 hover:bg-surface-2 hover:text-fg"><MessagesSquare className="size-4" /> Chat only</Link>
        )}
        <Link href="/falcon-mcp/" className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12.5px] text-fg-2 hover:bg-surface-2 hover:text-fg"><PanelLeft className="size-4" /> Back to the console</Link>
      </div>
      {chatOnly ? (
        <div className="flex min-h-0 flex-1 p-3"><ChatPanel fill /></div>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto"><div className="mx-auto w-full max-w-[1800px] px-4 pb-10 pt-4"><FalconMcp full /></div></div>
      )}
    </div>
  );
}
