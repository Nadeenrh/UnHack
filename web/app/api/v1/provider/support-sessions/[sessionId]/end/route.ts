import { isUuid, requireProvider } from "@/lib/nightwatch/access";
import { audit } from "@/lib/nightwatch/audit";
import { exec, one } from "@/lib/nightwatch/db";
import { notFound } from "@/lib/nightwatch/http";
import { authed } from "@/lib/nightwatch/route";

// POST /api/v1/provider/support-sessions/:sessionId/end — close your support window early.
export const POST = authed<{ sessionId: string }>(async (_req, { sessionId }, session) => {
  requireProvider(session);
  if (!isUuid(sessionId)) throw notFound("Support session not found.");
  const s = await one<{ org_id: string }>(
    `SELECT org_id FROM support_sessions WHERE session_id = ? AND staff_user_id = ? AND ended_at IS NULL`,
    [sessionId, session.userId]
  );
  if (!s) throw notFound("Support session not found.");
  await exec(`UPDATE support_sessions SET ended_at = NOW(3) WHERE session_id = ?`, [sessionId]);
  await audit({ orgId: s.org_id, actorType: "provider_support", actorId: session.userId, event: "support_session_ended" });
  return { id: sessionId, ended: true };
});
