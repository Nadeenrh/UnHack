import { requireOrgAccess } from "@/lib/nightwatch/access";
import { badRequest } from "@/lib/nightwatch/http";
import { expireStaleActions, loadIncidents } from "@/lib/nightwatch/incidents";
import { authed } from "@/lib/nightwatch/route";

// GET /api/v1/orgs/:orgId/incidents?status=open|closed|all&limit=50
// Returns Incident[] (contracts/types.ts), newest first.
export const GET = authed<{ orgId: string }>(async (req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  const status = req.nextUrl.searchParams.get("status") ?? "all";
  if (!["open", "closed", "all"].includes(status)) throw badRequest("status must be open, closed or all.");
  const limit = Number(req.nextUrl.searchParams.get("limit") ?? 50);
  await expireStaleActions(access.orgId);
  return loadIncidents(access.orgId, { status: status as "open" | "closed" | "all", limit: Number.isFinite(limit) ? limit : 50 });
});
