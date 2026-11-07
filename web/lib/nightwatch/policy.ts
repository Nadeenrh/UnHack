// The autonomy dial. Deterministic code, never the AI, decides how much each action may
// happen on its own:
//   auto   run without asking (only ever allowed for low-risk actions)
//   ask    wait for an approver
//   never  recommend only; a person does it themselves
// Risk per action type is fixed here, not configurable and not set by agents.

import type { ActionRisk, ActionType, PolicyMode } from "@/contracts/types";
import { exec, one, rows, type Executor } from "./db";
import { badRequest } from "./http";

export const ACTION_TYPES: ActionType[] = [
  "block_ip",
  "block_domain",
  "isolate_host",
  "quarantine_file",
  "disable_account",
  "notify_only",
];

export const ACTION_RISK: Record<ActionType, ActionRisk> = {
  block_ip: "low",
  block_domain: "low",
  isolate_host: "high",
  quarantine_file: "high",
  disable_account: "critical",
  notify_only: "low",
};

export const DEFAULT_MODE: Record<ActionType, PolicyMode> = {
  block_ip: "ask",
  block_domain: "auto",
  isolate_host: "ask",
  quarantine_file: "ask",
  disable_account: "never",
  notify_only: "auto",
};

/** Minutes an approval request stays open before it expires. */
export const APPROVAL_WINDOW_MINUTES = 30;

export function isActionType(v: unknown): v is ActionType {
  return typeof v === "string" && (ACTION_TYPES as string[]).includes(v);
}

/** Guardrail: anything above low risk can never be fully automatic. */
export function assertModeAllowed(type: ActionType, mode: PolicyMode): void {
  if (mode === "auto" && ACTION_RISK[type] !== "low") {
    throw badRequest(`${type} is ${ACTION_RISK[type]} risk and can't be automatic. Use "ask" or "never".`);
  }
}

export async function ensureDefaultPolicies(orgId: string, conn?: Executor): Promise<void> {
  for (const type of ACTION_TYPES) {
    await exec(
      `INSERT IGNORE INTO policies (org_id, action_type, risk, mode) VALUES (?, ?, ?, ?)`,
      [orgId, type, ACTION_RISK[type], DEFAULT_MODE[type]],
      conn
    );
  }
}

export async function decide(
  orgId: string,
  type: ActionType,
  conn?: Executor
): Promise<{ risk: ActionRisk; mode: PolicyMode }> {
  const row = await one<{ mode: PolicyMode }>(
    `SELECT mode FROM policies WHERE org_id = ? AND action_type = ?`,
    [orgId, type],
    conn
  );
  let mode = row?.mode ?? DEFAULT_MODE[type];
  // Re-check the guardrail at decision time too, in case a row was edited by hand.
  if (mode === "auto" && ACTION_RISK[type] !== "low") mode = "ask";
  return { risk: ACTION_RISK[type], mode };
}

export async function listPolicies(orgId: string) {
  const found = await rows<{ action_type: ActionType; mode: PolicyMode; updated_at: Date }>(
    `SELECT action_type, mode, updated_at FROM policies WHERE org_id = ?`,
    [orgId]
  );
  return ACTION_TYPES.map((type) => {
    const r = found.find((f) => f.action_type === type);
    return {
      action_type: type,
      risk: ACTION_RISK[type],
      mode: r?.mode ?? DEFAULT_MODE[type],
      auto_allowed: ACTION_RISK[type] === "low",
      updated_at: r ? r.updated_at.toISOString() : null,
    };
  });
}
