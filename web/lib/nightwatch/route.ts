// Wrapper for /api/v1 route handlers: origin check on writes, session required,
// consistent JSON envelope ({ success, data } / { success, message, code }).

import { NextRequest, NextResponse } from "next/server";
import { getRequestSession, type Session } from "./auth";
import { assertSameOrigin, fail, ok, unauthorized } from "./http";

type Params = Record<string, string>;
type Ctx<P extends Params> = { params: Promise<P> };

export function authed<P extends Params = Params>(
  handler: (req: NextRequest, params: P, session: Session) => Promise<unknown>
) {
  return async (req: NextRequest, ctx: Ctx<P>): Promise<NextResponse> => {
    try {
      assertSameOrigin(req);
      const session = await getRequestSession(req);
      if (!session) throw unauthorized();
      const out = await handler(req, ((await ctx?.params) ?? {}) as P, session);
      return out instanceof NextResponse ? out : ok(out);
    } catch (err) {
      return fail(err);
    }
  };
}

export function open<P extends Params = Params>(
  handler: (req: NextRequest, params: P) => Promise<unknown>,
  { checkOrigin = true } = {}
) {
  return async (req: NextRequest, ctx: Ctx<P>): Promise<NextResponse> => {
    try {
      if (checkOrigin) assertSameOrigin(req);
      const out = await handler(req, ((await ctx?.params) ?? {}) as P);
      return out instanceof NextResponse ? out : ok(out);
    } catch (err) {
      return fail(err);
    }
  };
}
