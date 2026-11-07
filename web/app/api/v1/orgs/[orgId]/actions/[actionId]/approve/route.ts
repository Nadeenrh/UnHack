import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { decideAction } from "@/lib/nightwatch/actions";
import { notFound, readJson, str } from "@/lib/nightwatch/http";
import { authed } from "@/lib/nightwatch/route";

// POST /api/v1/orgs/:orgId/actions/:actionId/approve   { target }
// Approvers and owners only. `target` must be the target the person saw on screen; if it
// changed, or the action was already decided or expired, the API answers 409.
// Returns the updated Incident. Execution starts right after the response.
export const POST = authed<{ orgId: string; actionId: string }>(async (req, { orgId, actionId }, session) => {
  const access = await requireOrgAccess(session, orgId, "approve");
  if (!isUuid(actionId)) throw notFound("Action not found.");
  const body = await readJson<{ target?: unknown }>(req);
  return decideAction({
    orgId: access.orgId,
    actionId,
    reviewedTarget: str(body.target, "target", { max: 255 }),
    decision: "approve",
    userId: session.userId,
  });
});
