import { requireOrgAccess } from "@/lib/nightwatch/access";
import { authed } from "@/lib/nightwatch/route";
import { listAssets } from "@/lib/nightwatch/snapshots";

// GET /api/v1/orgs/:orgId/assets — monitored machines and whether their agent is online.
export const GET = authed<{ orgId: string }>(async (_req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  return listAssets(access.orgId);
});
