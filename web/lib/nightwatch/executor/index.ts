// The only code that changes anything on a client's machines.
//
// Agents never call this. It runs an action only after it reached status "approved"
// (by a person, or by policy for low-risk "auto" actions), and it claims the action with
// a conditional UPDATE first, so the same action can never run twice.
//
// EXECUTOR_MODE=simulate (default)  records the decision, changes nothing, says so
// EXECUTOR_MODE=wazuh               sends the response through Wazuh active response

import { audit } from "../audit";
import { exec, one, rows } from "../db";
import type { ActionRow } from "../incidents";
import { refreshIncidentStatus } from "../incidents";
import { simulateExecutor } from "./simulate";
import type { ExecutionContext, ExecutionResult, ResponseExecutor } from "./types";
import { wazuhExecutor } from "./wazuh";

export function getExecutor(): ResponseExecutor {
  const mode = (process.env.EXECUTOR_MODE ?? "simulate").toLowerCase();
  if (mode === "wazuh") return wazuhExecutor();
  return simulateExecutor();
}

export async function executeAction(orgId: string, actionId: string, executor = getExecutor()): Promise<void> {
  // Claim it. Zero rows = someone else already ran it, or it isn't approved. Either way, stop.
  const claim = await exec(
    `UPDATE actions SET status = 'executing', executed_at = NOW(3)
     WHERE action_id = ? AND org_id = ? AND status = 'approved'`,
    [actionId, orgId]
  );
  if (claim.affectedRows !== 1) return;

  const action = (await one<ActionRow>(`SELECT * FROM actions WHERE action_id = ? AND org_id = ?`, [actionId, orgId]))!;
  await audit({
    orgId,
    actorType: "system",
    actorId: `executor:${executor.name}`,
    event: "action_execution_started",
    incidentId: action.incident_id,
    actionId,
    details: { type: action.type, target: action.target },
  });

  const assets = await rows<ExecutionContext["assets"][number]>(
    `SELECT a.hostname, a.ip, a.os, a.kind, a.agent_ref, a.agent_status
     FROM incident_assets ia JOIN assets a ON a.asset_id = ia.asset_id AND a.org_id = ia.org_id
     WHERE ia.org_id = ? AND ia.incident_id = ?`,
    [orgId, action.incident_id]
  );

  let result: ExecutionResult;
  try {
    result = await executor.run({ action, assets });
  } catch (err) {
    result = { ok: false, verified: false, detail: `Executor error: ${err instanceof Error ? err.message : String(err)}`.slice(0, 500) };
  }

  await exec(
    `UPDATE actions SET status = ?, completed_at = NOW(3), result_verified = ?, result_detail = ?
     WHERE action_id = ? AND org_id = ? AND status = 'executing'`,
    [result.ok ? "succeeded" : "failed", result.verified, result.detail, actionId, orgId]
  );
  await audit({
    orgId,
    actorType: "system",
    actorId: `executor:${executor.name}`,
    event: result.ok ? "action_succeeded" : "action_failed",
    incidentId: action.incident_id,
    actionId,
    details: { verified: result.verified, detail: result.detail },
  });

  await settleIncidentAfterExecution(orgId, action.incident_id);
}

/**
 * When nothing is left waiting or running and at least one response succeeded,
 * the incident is contained. A person still decides when it's resolved.
 */
async function settleIncidentAfterExecution(orgId: string, incidentId: string): Promise<void> {
  const counts = await one<{ busy: number; done: number }>(
    `SELECT
       SUM(status IN ('awaiting_approval','approved','executing')) AS busy,
       SUM(status = 'succeeded') AS done
     FROM actions WHERE org_id = ? AND incident_id = ?`,
    [orgId, incidentId]
  );
  if (Number(counts?.busy ?? 0) === 0 && Number(counts?.done ?? 0) > 0) {
    const res = await exec(
      `UPDATE incidents SET status = 'contained'
       WHERE incident_id = ? AND org_id = ? AND status IN ('open','investigating','awaiting_approval')`,
      [incidentId, orgId]
    );
    if (res.affectedRows === 1) {
      await audit({ orgId, actorType: "system", actorId: "executor", event: "incident_contained", incidentId });
    }
    return;
  }
  await refreshIncidentStatus(orgId, incidentId);
}
