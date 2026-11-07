import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { badRequest } from "@/lib/nightwatch/http";
import { authed } from "@/lib/nightwatch/route";
import { auditFor } from "@/lib/nightwatch/snapshots";

// GET /api/v1/orgs/:orgId/audit?limit=100&incident_id=...
// AuditEvent[] (contracts/types.ts), newest first. Includes provider support-session events,
// so clients can see when our staff looked at their workspace.
export const GET = authed<{ orgId: string }>(async (req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  const incidentId = req.nextUrl.searchParams.get("incident_id") ?? undefined;
  if (incidentId && !isUuid(incidentId)) throw badRequest("incident_id is not valid.");
  const limit = Number(req.nextUrl.searchParams.get("limit") ?? 100);
  return auditFor(access.orgId, { incidentId, limit: Number.isFinite(limit) ? limit : 100 });
});
