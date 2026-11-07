import type { PolicyMode } from "@/contracts/types";
import { requireOrgAccess } from "@/lib/nightwatch/access";
import { audit } from "@/lib/nightwatch/audit";
import { exec, one } from "@/lib/nightwatch/db";
import { badRequest, readJson } from "@/lib/nightwatch/http";
import { ACTION_RISK, assertModeAllowed, isActionType, listPolicies } from "@/lib/nightwatch/policy";
import { authed } from "@/lib/nightwatch/route";

// GET /api/v1/orgs/:orgId/policies — the autonomy dial, one row per action type:
//   { action_type, risk, mode: auto|ask|never, auto_allowed, updated_at }
export const GET = authed<{ orgId: string }>(async (_req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  return listPolicies(access.orgId);
});

// PUT /api/v1/orgs/:orgId/policies  { action_type, mode }   (owners only)
// Only low-risk actions can be set to "auto".
export const PUT = authed<{ orgId: string }>(async (req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "admin");
  const body = await readJson<{ action_type?: unknown; mode?: unknown }>(req);
  if (!isActionType(body.action_type)) throw badRequest("Unknown action_type.");
  if (body.mode !== "auto" && body.mode !== "ask" && body.mode !== "never") {
    throw badRequest('mode must be "auto", "ask" or "never".');
  }
  const type = body.action_type;
  const mode = body.mode as PolicyMode;
  assertModeAllowed(type, mode);

  const before = await one<{ mode: PolicyMode }>(
    `SELECT mode FROM policies WHERE org_id = ? AND action_type = ?`,
    [access.orgId, type]
  );
  await exec(
    `INSERT INTO policies (org_id, action_type, risk, mode, updated_by) VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE mode = VALUES(mode), updated_by = VALUES(updated_by)`,
    [access.orgId, type, ACTION_RISK[type], mode, session.userId]
  );
  await audit({
    orgId: access.orgId,
    actorType: "user",
    actorId: session.userId,
    event: "policy_changed",
    details: { action_type: type, from: before?.mode ?? null, to: mode },
  });
  return listPolicies(access.orgId);
});
