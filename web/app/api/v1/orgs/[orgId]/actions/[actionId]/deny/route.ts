import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { decideAction } from "@/lib/nightwatch/actions";
import { notFound, readJson, str } from "@/lib/nightwatch/http";
import { authed } from "@/lib/nightwatch/route";

// POST /api/v1/orgs/:orgId/actions/:actionId/deny   { target, reason? }
// Approvers and owners only. Same binding rules as approve. Returns the updated Incident.
export const POST = authed<{ orgId: string; actionId: string }>(async (req, { orgId, actionId }, session) => {
  const access = await requireOrgAccess(session, orgId, "approve");
  if (!isUuid(actionId)) throw notFound("Action not found.");
  const body = await readJson<{ target?: unknown; reason?: unknown }>(req);
  const reason = typeof body.reason === "string" && body.reason.trim() ? body.reason.trim().slice(0, 500) : null;
  return decideAction({
    orgId: access.orgId,
    actionId,
    reviewedTarget: str(body.target, "target", { max: 255 }),
    decision: "deny",
    userId: session.userId,
    reason,
  });
});
