import { requireOrgAccess } from "@/lib/nightwatch/access";
import { rows } from "@/lib/nightwatch/db";
import { authed } from "@/lib/nightwatch/route";

// GET /api/v1/orgs/:orgId/sites — where telemetry comes from. Keys are never returned,
// only the first characters so people can tell which key a site uses.
export const GET = authed<{ orgId: string }>(async (_req, { orgId }, session) => {
  const access = await requireOrgAccess(session, orgId, "read");
  const sites = await rows<{ site_id: string; name: string; ingest_key_prefix: string; created_at: Date; revoked_at: Date | null }>(
    `SELECT site_id, name, ingest_key_prefix, created_at, revoked_at FROM sites WHERE org_id = ? ORDER BY created_at`,
    [access.orgId]
  );
  return sites.map((s) => ({
    id: s.site_id,
    name: s.name,
    ingest_key_prefix: s.ingest_key_prefix,
    active: s.revoked_at === null,
    created_at: s.created_at.toISOString(),
  }));
});
