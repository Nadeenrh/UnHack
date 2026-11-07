import { NextResponse } from "next/server";
import { login, publicSession, setSessionCookie } from "@/lib/nightwatch/auth";
import { clientIp, readJson, str } from "@/lib/nightwatch/http";
import { open } from "@/lib/nightwatch/route";

// POST /api/v1/auth/login  { email, password }
// Sets the HttpOnly session cookie. The response never contains the token.
export const POST = open(async (req) => {
  const body = await readJson<{ email?: unknown; password?: unknown }>(req);
  const email = str(body.email, "Email", { max: 150 });
  const password = str(body.password, "Password", { max: 200 });

  const { token, session } = await login(email, password, {
    ip: clientIp(req),
    userAgent: req.headers.get("user-agent"),
  });

  const res = NextResponse.json({ success: true, data: publicSession(session) });
  setSessionCookie(res, token);
  return res;
});
