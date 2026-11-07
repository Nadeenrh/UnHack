"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/**
 * Opening a client's workspace starts a 30-minute, read-only support session that the
 * client sees in their activity log, so a reason is required.
 */
export function OpenWorkspace({ orgId, orgName }: { orgId: string; orgName: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const res = await fetch(`/api/v1/provider/orgs/${orgId}/support-sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason }),
    }).catch(() => null);
    if (res?.ok) {
      router.push(`/app/${orgId}`);
      return;
    }
    const body = await res?.json().catch(() => ({}));
    setError(body?.message ?? "Couldn't open the workspace.");
    setBusy(false);
  }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className="rounded-md bg-ink px-4 py-2 text-sm font-semibold text-night hover:bg-ink-soft">
        Open workspace
      </button>
    );
  }

  return (
    <form onSubmit={start} className="w-full space-y-2 sm:max-w-md">
      <label className="block text-sm">
        <span className="font-medium">Why are you opening {orgName}&apos;s workspace?</span>
        <span className="block text-xs text-muted">They&apos;ll see this reason in their activity log.</span>
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
          minLength={5}
          maxLength={300}
          autoFocus
          className="mt-1 block w-full rounded-md border border-line bg-panel px-3 py-2"
          placeholder="Client asked for help with INC-0001"
        />
      </label>
      {error && <p className="text-sm text-bad">{error}</p>}
      <div className="flex gap-2">
        <button type="submit" disabled={busy} className="rounded-md bg-ink px-4 py-2 text-sm font-semibold text-night disabled:opacity-60">
          {busy ? "Opening…" : "Open for 30 minutes"}
        </button>
        <button type="button" onClick={() => setOpen(false)} className="rounded-md px-4 py-2 text-sm font-medium ring-1 ring-line">
          Cancel
        </button>
      </div>
    </form>
  );
}
