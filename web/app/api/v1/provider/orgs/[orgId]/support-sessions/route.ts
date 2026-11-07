import { isUuid, requireProvider } from "@/lib/nightwatch/access";
import { audit } from "@/lib/nightwatch/audit";
import { newId } from "@/lib/nightwatch/crypto";
import { exec, one } from "@/lib/nightwatch/db";
import { notFound, readJson, str } from "@/lib/nightwatch/http";
import { authed } from "@/lib/nightwatch/route";

const SUPPORT_MINUTES = 30;

// POST /api/v1/provider/orgs/:orgId/support-sessions  { reason }
// Opens a 30-minute, read-only window into one client's workspace. Recorded in that
// client's audit log, so the client can see who looked and why.
export const POST = authed<{ orgId: string }>(async (req, { orgId }, session) => {
  requireProvider(session);
  if (!isUuid(orgId)) throw notFound("Organization not found.");
  const org = await one<{ name: string }>(`SELECT name FROM organizations WHERE org_id = ? AND status = 'active'`, [orgId]);
  if (!org) throw notFound("Organization not found.");
  const reason = str((await readJson<{ reason?: unknown }>(req)).reason, "Reason", { min: 5, max: 300 });

  const sessionId = newId();
  await exec(
    `INSERT INTO support_sessions (session_id, org_id, staff_user_id, reason, expires_at)
     VALUES (?, ?, ?, ?, NOW(3) + INTERVAL ${SUPPORT_MINUTES} MINUTE)`,
    [sessionId, orgId, session.userId, reason]
  );
  await audit({
    orgId,
    actorType: "provider_support",
    actorId: session.userId,
    event: "support_session_started",
    details: { reason, minutes: SUPPORT_MINUTES, session_id: sessionId },
  });
  const row = await one<{ expires_at: Date }>(`SELECT expires_at FROM support_sessions WHERE session_id = ?`, [sessionId]);
  return { id: sessionId, org_id: orgId, org_name: org.name, reason, expires_at: row!.expires_at.toISOString(), read_only: true };
});
