"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { Action, IncidentStatus } from "@/contracts/types";
import { ACTION_LABEL, ACTION_VERB, formatDateTime } from "@/components/format";
import { ActionStatusBadge } from "@/components/ui/Badges";

const RISK_TEXT: Record<Action["risk"], string> = {
  low: "Low risk",
  high: "High risk: affects a machine people use",
  critical: "Critical: affects someone's account",
};

/**
 * Proposed responses for one incident. Waiting approvals get the big card; everything else
 * is a compact record. While anything is approved or running, the page refreshes every 2s
 * so people watch it go from "Approved" to "Running now" to "Done".
 */
export function ActionPanel({
  orgId,
  actions,
  incidentStatus,
  canApprove,
  readOnlyReason,
}: {
  orgId: string;
  actions: Action[];
  incidentStatus?: IncidentStatus;
  canApprove: boolean;
  readOnlyReason?: string;
}) {
  const router = useRouter();
  const inFlight = actions.some((a) => a.status === "approved" || a.status === "executing");

  useEffect(() => {
    if (!inFlight) return;
    const t = setInterval(() => router.refresh(), 2000);
    return () => clearInterval(t);
  }, [inFlight, router]);

  const waiting = actions.filter((a) => a.status === "awaiting_approval");
  const rest = actions.filter((a) => a.status !== "awaiting_approval");

  if (!actions.length) {
    // Open incidents are still being worked on, so say that rather than "nothing proposed".
    if (incidentStatus === "open" || incidentStatus === "investigating") {
      return (
        <div className="flex items-start gap-3 px-5 py-6 text-sm">
          <span aria-hidden className="relative mt-1.5 flex size-2.5 shrink-0">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-info opacity-60" />
            <span className="relative inline-flex size-2.5 rounded-full bg-info" />
          </span>
          <div>
            <p className="font-medium">Still investigating</p>
            <p className="mt-0.5 text-muted">
              Any recommended response will show up here as soon as the investigation finishes. Nothing runs without your approval.
            </p>
          </div>
        </div>
      );
    }
    const closed = incidentStatus === "resolved" || incidentStatus === "false_positive";
    return (
      <p className="px-5 py-6 text-sm text-muted">{closed ? "No response was needed for this incident." : "No responses proposed for this incident."}</p>
    );
  }

  return (
    <div>
      {waiting.map((a) => (
        <DecisionCard key={a.id} orgId={orgId} action={a} canApprove={canApprove} readOnlyReason={readOnlyReason} />
      ))}
      {rest.length > 0 && (
        <ul>
          {rest.map((a) => (
            <li key={a.id} className="border-t border-line px-5 py-4 first:border-t-0">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="font-medium">
                  {ACTION_LABEL[a.type]} <span className="font-mono text-sm">{a.target}</span>
                </div>
                <ActionStatusBadge status={a.status} />
              </div>
              <p className="mt-1 text-sm text-muted">{a.rationale}</p>
              <ActionOutcome action={a} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ActionOutcome({ action: a }: { action: Action }) {
  const lines: React.ReactNode[] = [];
  if (a.status === "proposed") {
    lines.push("Your policy says a person does this one themselves. Nightwatch won't do it automatically.");
  }
  if (a.decided_by) {
    const verb = a.status === "denied" ? "Denied" : a.decided_by.kind === "policy" ? "Approved automatically by your policy" : "Approved";
    lines.push(`${verb}${a.decided_by.kind === "human" ? ` by ${a.decided_by.name}` : ""}, ${formatDateTime(a.decided_at)}`);
  }
  if (a.status === "expired") lines.push("Nobody decided in time, so nothing was done.");
  if (a.result) {
    lines.push(
      <span key="r">
        {a.result.detail}{" "}
        <strong className={a.result.verified ? "text-ok" : "text-muted"}>
          {a.result.verified ? "Checked: the change is in place." : "Not independently checked."}
        </strong>
      </span>
    );
  }
  if (!lines.length) return null;
  return (
    <div className="mt-2 space-y-1 text-sm">
      {lines.map((l, i) => (
        <p key={i}>{l}</p>
      ))}
    </div>
  );
}

function DecisionCard({
  orgId,
  action,
  canApprove,
  readOnlyReason,
}: {
  orgId: string;
  action: Action;
  canApprove: boolean;
  readOnlyReason?: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<null | "approve" | "deny">(null);
  const [denying, setDenying] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function decide(decision: "approve" | "deny") {
    setBusy(decision);
    setError(null);
    try {
      const res = await fetch(`/api/v1/orgs/${orgId}/actions/${action.id}/${decision}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        // Send back exactly what the person saw. If it changed, the server refuses.
        body: JSON.stringify({ target: action.target, ...(decision === "deny" && reason.trim() ? { reason: reason.trim() } : {}) }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.message ?? "That didn't go through. Refresh and try again.");
      }
      router.refresh();
    } catch {
      setError("Couldn't reach Nightwatch. Check your connection and try again.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="border-l-4 border-lantern bg-lantern-soft/60 px-5 py-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-semibold text-lantern-deep">{ACTION_LABEL[action.type]}</span>
        <span className="text-xs text-lantern-deep">{RISK_TEXT[action.risk]}</span>
      </div>
      <div className="mt-2 font-mono text-2xl font-medium break-all sm:text-3xl">{action.target}</div>
      <p className="mt-3 max-w-prose">{action.rationale}</p>

      {error && (
        <p role="alert" className="mt-3 rounded-md bg-bad-soft px-3 py-2 text-sm text-bad">
          {error}
        </p>
      )}

      {canApprove ? (
        denying ? (
          <div className="mt-4 space-y-3">
            <label className="block text-sm">
              <span className="font-medium">Why are you denying it? (optional, saved in the activity log)</span>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={500}
                className="mt-1 block w-full rounded-md border border-line bg-panel px-3 py-2"
                placeholder="For example: that address is our IT vendor"
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <button type="button" disabled={!!busy} onClick={() => decide("deny")} className="rounded-md bg-bad px-4 py-2.5 font-semibold text-night disabled:opacity-60">
                {busy === "deny" ? "Denying…" : "Deny"}
              </button>
              <button type="button" disabled={!!busy} onClick={() => setDenying(false)} className="rounded-md px-4 py-2.5 font-medium ring-1 ring-line hover:bg-panel">
                Back
              </button>
            </div>
          </div>
        ) : (
          <div className="mt-5 grid gap-2 sm:flex">
            <button
              type="button"
              disabled={!!busy}
              onClick={() => decide("approve")}
              className="rounded-md bg-lantern px-6 py-3 text-lg font-semibold text-night hover:brightness-105 disabled:opacity-60"
            >
              {busy === "approve" ? "Approving…" : ACTION_VERB[action.type]}
            </button>
            <button
              type="button"
              disabled={!!busy}
              onClick={() => setDenying(true)}
              className="rounded-md bg-panel px-6 py-3 text-lg font-semibold ring-1 ring-line hover:bg-canvas disabled:opacity-60"
            >
              Deny
            </button>
          </div>
        )
      ) : (
        <p className="mt-4 text-sm text-lantern-deep">{readOnlyReason ?? "Only approvers and owners can decide this."}</p>
      )}
      <p className="mt-3 text-xs text-muted">Requested {formatDateTime(action.requested_at)} If nobody decides within 30 minutes, nothing is done.</p>
    </div>
  );
}
