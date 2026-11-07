"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/** Always visible while provider staff are inside a client's workspace. */
export function SupportBanner({ orgName, sessionId }: { orgName: string; sessionId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  return (
    <div role="status" className="flex flex-wrap items-center justify-between gap-3 bg-info px-4 py-2 text-sm text-night lg:px-8">
      <span>
        Support mode: you&apos;re viewing <strong>{orgName}</strong>, read-only. This visit is in their activity log.
      </span>
      <button
        type="button"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          await fetch(`/api/v1/provider/support-sessions/${sessionId}/end`, { method: "POST" }).catch(() => undefined);
          router.push("/provider");
          router.refresh();
        }}
        className="rounded-md bg-night/15 px-3 py-1 font-medium hover:bg-night/25"
      >
        {busy ? "Leaving…" : "Leave workspace"}
      </button>
    </div>
  );
}
