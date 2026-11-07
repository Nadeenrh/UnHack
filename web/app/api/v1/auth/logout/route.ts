import { NextResponse } from "next/server";
import { audit } from "@/lib/nightwatch/audit";
import { clearSessionCookie, revokeSession } from "@/lib/nightwatch/auth";
import { authed } from "@/lib/nightwatch/route";

// POST /api/v1/auth/logout — revokes the session server-side and clears the cookie.
export const POST = authed(async (_req, _params, session) => {
  await revokeSession(session.tokenHash);
  await audit({ orgId: null, actorType: "user", actorId: session.userId, event: "logout" });
  const res = NextResponse.json({ success: true, data: null });
  clearSessionCookie(res);
  return res;
});
