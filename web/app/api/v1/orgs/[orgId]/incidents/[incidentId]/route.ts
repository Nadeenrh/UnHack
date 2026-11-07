import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { notFound } from "@/lib/nightwatch/http";
import { expireStaleActions, loadIncident } from "@/lib/nightwatch/incidents";
import { authed } from "@/lib/nightwatch/route";

// GET /api/v1/orgs/:orgId/incidents/:incidentId — one Incident (contracts/types.ts).
export const GET = authed<{ orgId: string; incidentId: string }>(async (_req, { orgId, incidentId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  if (!isUuid(incidentId)) throw notFound("Incident not found.");
  await expireStaleActions(access.orgId);
  const incident = await loadIncident(access.orgId, incidentId);
  if (!incident) throw notFound("Incident not found.");
  return incident;
});
