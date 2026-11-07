// A person's decision on a proposed response.
//
// The approval is bound to exactly what they reviewed: this action, in this org, for this
// target, while it's still waiting. It's one conditional UPDATE, so a stale screen, a changed
// target, a second click or a replayed request all fail safely with 409.

import type { Incident } from "@/contracts/types";
import { audit } from "./audit";
import { runLater } from "./background";
import { exec, one } from "./db";
import { executeAction } from "./executor";
import { conflict, notFound } from "./http";
import { expireStaleActions, loadIncident, refreshIncidentStatus, type ActionRow } from "./incidents";

export async function decideAction(input: {
  orgId: string;
  actionId: string;
  reviewedTarget: string;
  decision: "approve" | "deny";
  userId: string;
  reason?: string | null;
}): Promise<Incident> {
  const { orgId, actionId, reviewedTarget, decision, userId } = input;
  await expireStaleActions(orgId);

  const action = await one<ActionRow>(`SELECT * FROM actions WHERE action_id = ? AND org_id = ?`, [actionId, orgId]);
  if (!action) throw notFound("Action not found.");
  if (action.status !== "awaiting_approval") {
    throw conflict(`This action is already ${action.status.replace("_", " ")}. Refresh to see the latest.`);
  }
  if (action.target !== reviewedTarget) {
    throw conflict("The target changed since you reviewed it. Refresh and review again.");
  }

  const next = decision === "approve" ? "approved" : "denied";
  const res = await exec(
    `UPDATE actions SET status = ?, decided_by = ?, decided_at = NOW(3)
     WHERE action_id = ? AND org_id = ? AND target = ? AND status = 'awaiting_approval'`,
    [next, userId, actionId, orgId, reviewedTarget]
  );
  if (res.affectedRows !== 1) {
    throw conflict("Someone else just decided this action. Refresh to see the latest.");
  }

  await audit({
    orgId,
    actorType: "user",
    actorId: userId,
    event: decision === "approve" ? "action_approved" : "action_denied",
    incidentId: action.incident_id,
    actionId,
    details: { type: action.type, target: action.target, reason: input.reason ?? null },
  });
  await refreshIncidentStatus(orgId, action.incident_id);

  if (decision === "approve") {
    runLater(`execute ${actionId}`, () => executeAction(orgId, actionId));
  }
  return (await loadIncident(orgId, action.incident_id))!;
}
