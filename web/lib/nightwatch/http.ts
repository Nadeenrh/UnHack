// Shared HTTP plumbing for /api/v1 routes: errors, JSON responses, CSRF origin check.

import { NextRequest, NextResponse } from "next/server";

export class HttpError extends Error {
  constructor(public status: number, message: string, public code?: string) {
    super(message);
  }
}

export const badRequest = (msg: string) => new HttpError(400, msg, "bad_request");
export const unauthorized = (msg = "Sign in required.") => new HttpError(401, msg, "unauthorized");
export const forbidden = (msg = "You don't have access to this.") => new HttpError(403, msg, "forbidden");
export const notFound = (msg = "Not found.") => new HttpError(404, msg, "not_found");
export const conflict = (msg: string) => new HttpError(409, msg, "conflict");

export function ok<T>(data: T, status = 200): NextResponse {
  return NextResponse.json({ success: true, data }, { status });
}

export function fail(err: unknown): NextResponse {
  if (err instanceof HttpError) {
    return NextResponse.json(
      { success: false, message: err.message, code: err.code ?? "error" },
      { status: err.status }
    );
  }
  // Never leak internals (SQL, stack traces) to the client.
  console.error("[nightwatch] unhandled error:", err);
  return NextResponse.json({ success: false, message: "Something went wrong.", code: "internal" }, { status: 500 });
}

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * CSRF defence for cookie-authenticated writes. SameSite=Lax already blocks most
 * cross-site POSTs; this also requires the Origin (or Referer) to be this site.
 * Ingest uses its own key header, not cookies, and skips this check.
 */
export function assertSameOrigin(req: NextRequest): void {
  if (!UNSAFE.has(req.method)) return;
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  const source = req.headers.get("origin") ?? req.headers.get("referer");
  if (!host || !source) throw forbidden("Request origin could not be verified.");
  let sourceHost: string;
  try {
    sourceHost = new URL(source).host;
  } catch {
    throw forbidden("Request origin could not be verified.");
  }
  if (sourceHost !== host) throw forbidden("Cross-site request blocked.");
}

export async function readJson<T = Record<string, unknown>>(req: NextRequest): Promise<T> {
  try {
    const body = await req.json();
    if (body === null || typeof body !== "object") throw new Error();
    return body as T;
  } catch {
    throw badRequest("Request body must be a JSON object.");
  }
}

export function str(value: unknown, field: string, { min = 1, max = 500 } = {}): string {
  if (typeof value !== "string") throw badRequest(`${field} is required.`);
  const v = value.trim();
  if (v.length < min) throw badRequest(`${field} is required.`);
  if (v.length > max) throw badRequest(`${field} is too long.`);
  return v;
}

export function clientIp(req: NextRequest): string | null {
  const fwd = req.headers.get("x-forwarded-for");
  return (fwd ? fwd.split(",")[0].trim() : req.headers.get("x-real-ip")) || null;
}
