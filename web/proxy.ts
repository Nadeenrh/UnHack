import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { SESSION_COOKIE } from "@/lib/nightwatch/auth";

/**
 * Next.js 16 network boundary (replaces middleware.ts).
 *
 * Fast first gate only: no session cookie on a portal page → send to /login and come back after.
 * The real check (is the session valid? may this person see this org?) happens on the server in
 * every page and API route, so a forged or expired cookie gets nowhere past this point either.
 */
export function proxy(request: NextRequest) {
  if (request.cookies.get(SESSION_COOKIE)?.value) return NextResponse.next();
  const login = new URL("/login", request.url);
  login.searchParams.set("next", request.nextUrl.pathname + request.nextUrl.search);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/app/:path*", "/provider/:path*"],
};
