import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { audit } from "@/lib/nightwatch/audit";
import { exec } from "@/lib/nightwatch/db";
import { notFound } from "@/lib/nightwatch/http";
import { newIngestKey } from "@/lib/nightwatch/orgs";
import { authed } from "@/lib/nightwatch/route";

// POST /api/v1/orgs/:orgId/sites/:siteId/rotate-key   (owners only)
// Issues a new ingest key and invalidates the old one immediately. The new key is shown once.
export const POST = authed<{ orgId: string; siteId: string }>(async (_req, { orgId, siteId }, session) => {
  const access = await requireOrgAccess(session, orgId, "admin");
  if (!isUuid(siteId)) throw notFound("Site not found.");
  const key = newIngestKey();
  const res = await exec(
    `UPDATE sites SET ingest_key_hash = ?, ingest_key_prefix = ?, revoked_at = NULL WHERE site_id = ? AND org_id = ?`,
    [key.hash, key.prefix, siteId, access.orgId]
  );
  if (res.affectedRows !== 1) throw notFound("Site not found.");
  await audit({
    orgId: access.orgId,
    actorType: "user",
    actorId: session.userId,
    event: "ingest_key_rotated",
    details: { site_id: siteId, prefix: key.prefix },
  });
  return { site_id: siteId, ingest_key: key.key, ingest_key_note: "Copy this now. It won't be shown again." };
});
