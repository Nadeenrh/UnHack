import { authed } from "@/lib/nightwatch/route";
import { placeholders, rows } from "@/lib/nightwatch/db";

// GET /api/v1/orgs — organizations the signed-in user belongs to (the client portal's org switcher).
// Provider staff use /api/v1/provider/overview instead.
export const GET = authed(async (_req, _params, session) => {
  if (!session.memberships.length) return [];
  const ids = session.memberships.map((m) => m.orgId);
  const orgs = await rows<{ org_id: string; name: string; slug: string; sector: string; plan: string }>(
    `SELECT org_id, name, slug, sector, plan FROM organizations WHERE org_id IN (${placeholders(ids.length)}) ORDER BY name`,
    ids
  );
  return orgs.map((o) => ({
    id: o.org_id,
    name: o.name,
    slug: o.slug,
    sector: o.sector,
    plan: o.plan,
    role: session.memberships.find((m) => m.orgId === o.org_id)!.role,
  }));
});
