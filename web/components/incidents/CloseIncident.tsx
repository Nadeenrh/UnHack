"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { IncidentStatus } from "@/contracts/types";

/**
 * A person closes the incident (resolved or false positive) or reopens it. The AI never does this.
 * Closing is refused while a response is still waiting or running.
 */
export function CloseIncident({
  orgId,
  incidentId,
  status,
  blocked,
  canDecide,
}: {
  orgId: string;
  incidentId: string;
  status: IncidentStatus;
  blocked: boolean;
  canDecide: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const closed = status === "resolved" || status === "false_positive";

  async function send(next: "resolved" | "false_positive" | "reopen") {
    setBusy(next);
    setError(null);
    try {
      const res = await fetch(`/api/v1/orgs/${orgId}/incidents/${incidentId}/status`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status: next, ...(note.trim() ? { note: note.trim() } : {}) }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.message ?? "That didn't go through. Refresh and try again.");
      } else {
        setNote("");
      }
      router.refresh();
    } catch {
      setError("Couldn't reach NightWatch. Check your connection and try again.");
    } finally {
      setBusy(null);
    }
  }

  if (closed) {
    return (
      <div className="space-y-3 px-5 py-4 text-sm">
        <p className="flex items-center gap-2 font-medium text-ok">
          <svg aria-hidden viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="m5 12 5 5L20 7" />
          </svg>
          {status === "resolved" ? "Closed as resolved" : "Closed as a false positive"}
        </p>
        {canDecide && (
          <button type="button" disabled={!!busy} onClick={() => send("reopen")} className="rounded-md px-3 py-1.5 font-medium ring-1 ring-line hover:bg-canvas disabled:opacity-60">
            {busy ? "Reopening…" : "Reopen"}
          </button>
        )}
        {error && <p role="alert" className="text-bad">{error}</p>}
      </div>
    );
  }

  if (!canDecide) return <p className="px-5 py-4 text-sm text-muted">Only approvers and owners can close incidents.</p>;

  return (
    <div className="space-y-3 px-5 py-4 text-sm">
      {blocked ? (
        <p className="text-muted">Decide the waiting response first, then close the incident here.</p>
      ) : (
        <>
          <p className="text-muted">Once you&apos;ve checked it, close it. This is saved in the activity log.</p>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={500}
            placeholder="Note (optional)"
            className="block w-full rounded-md border border-line bg-panel px-3 py-2"
          />
          <div className="grid gap-2">
            <button type="button" disabled={!!busy} onClick={() => send("resolved")} className="rounded-md bg-ok px-3 py-2 font-semibold text-night hover:brightness-105 disabled:opacity-60">
              {busy === "resolved" ? "Closing…" : "Mark resolved"}
            </button>
            <button type="button" disabled={!!busy} onClick={() => send("false_positive")} className="rounded-md px-3 py-2 font-medium ring-1 ring-line hover:bg-canvas disabled:opacity-60">
              {busy === "false_positive" ? "Closing…" : "It was a false positive"}
            </button>
          </div>
        </>
      )}
      {error && <p role="alert" className="text-bad">{error}</p>}
    </div>
  );
}
