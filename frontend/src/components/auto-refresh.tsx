"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/** While something is queued or running, re-render the page from the server
 *  every few seconds (ordinary server rendering; no WebSockets). */
export function AutoRefresh({ active, seconds = 3 }: { active: boolean; seconds?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => router.refresh(), seconds * 1000);
    return () => clearInterval(timer);
  }, [active, seconds, router]);
  if (!active) return null;
  return (
    <span className="muted small" role="status" aria-live="polite">
      Updating every {seconds}s…
    </span>
  );
}
