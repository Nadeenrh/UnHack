import { requireOrgAccess } from "@/lib/nightwatch/access";
import { authed } from "@/lib/nightwatch/route";
import { snapshots } from "@/lib/nightwatch/snapshots";

// GET /api/v1/orgs/:orgId — the client dashboard summary (same shape as one provider snapshot):
// health, open incidents, pending approvals, assets online, recent incidents.
export const GET = authed<{ orgId: string }>(async (_req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  const [snap] = await snapshots([access.orgId]);
  return { ...snap, access: { via: access.via, role: access.role } };
});
