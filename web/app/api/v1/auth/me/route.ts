import { publicSession } from "@/lib/nightwatch/auth";
import { authed } from "@/lib/nightwatch/route";

// GET /api/v1/auth/me — who is signed in, and which organizations they belong to.
export const GET = authed(async (_req, _params, session) => publicSession(session));
