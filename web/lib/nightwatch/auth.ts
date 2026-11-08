// Sessions for NightWatch.
//
// The browser gets a random 256-bit token in an HttpOnly cookie. The database stores only
// its SHA-256, with an expiry, and logout revokes it server-side. No JWTs, nothing in
// localStorage, nothing a script on the page can read.

import bcrypt from "bcrypt";
import type { NextRequest, NextResponse } from "next/server";
import { audit } from "./audit";
import { randomToken, sha256 } from "./crypto";
import { exec, one, rows } from "./db";
import { HttpError, unauthorized } from "./http";

export const SESSION_COOKIE = "nw_session";
export const SESSION_HOURS = 12;

export type PlatformRole = "none" | "provider_staff" | "provider_admin";
export type MembershipRole = "owner" | "approver" | "analyst" | "viewer";

export interface Membership {
  orgId: string;
  orgName: string;
  orgSlug: string;
  role: MembershipRole;
}

export interface Session {
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  platformRole: PlatformRole;
  memberships: Membership[];
  tokenHash: string;
  expiresAt: string;
}

/** What the API returns about the current user (no token material). */
export function publicSession(s: Session) {
  return {
    user: {
      id: s.userId,
      email: s.email,
      first_name: s.firstName,
      last_name: s.lastName,
      platform_role: s.platformRole,
    },
    memberships: s.memberships.map((m) => ({
      org_id: m.orgId,
      org_name: m.orgName,
      org_slug: m.orgSlug,
      role: m.role,
    })),
    expires_at: s.expiresAt,
  };
}

// --- Brute-force throttle (per email + IP, in memory; fine for one server) -----------

const ATTEMPT_LIMIT = 10;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const attempts = new Map<string, { count: number; resetAt: number }>();

function throttle(key: string): void {
  const now = Date.now();
  const entry = attempts.get(key);
  if (!entry || entry.resetAt < now) {
    attempts.set(key, { count: 1, resetAt: now + ATTEMPT_WINDOW_MS });
    return;
  }
  entry.count += 1;
  if (entry.count > ATTEMPT_LIMIT) {
    throw new HttpError(429, "Too many sign-in attempts. Try again in a few minutes.", "rate_limited");
  }
}

export function resetThrottleForTests(): void {
  attempts.clear();
}

// A real bcrypt hash of a random string, made once. Comparing against it when the email
// doesn't exist keeps response time the same, so attackers can't tell which emails exist.
let dummyHash: Promise<string> | null = null;
function getDummyHash(): Promise<string> {
  dummyHash ??= bcrypt.hash(randomToken(), 12);
  return dummyHash;
}

interface UserRow {
  user_id: string;
  email: string;
  first_name: string;
  last_name: string;
  password_hash: string;
  platform_role: PlatformRole;
  is_active: number;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

/** Verify credentials and open a session. Same error for every failure reason. */
export async function login(
  email: string,
  password: string,
  meta: { ip: string | null; userAgent: string | null }
): Promise<{ token: string; session: Session }> {
  const normalized = email.trim().toLowerCase();
  throttle(`${normalized}|${meta.ip ?? "?"}`);

  const user = await one<UserRow>(
    `SELECT user_id, email, first_name, last_name, password_hash, platform_role, is_active
     FROM users WHERE email = ? LIMIT 1`,
    [normalized]
  );
  const valid = await bcrypt.compare(password, user?.password_hash ?? (await getDummyHash()));
  if (!user || !valid || !user.is_active) {
    throw unauthorized("Email or password is incorrect.");
  }

  const token = await createSession(user.user_id, meta);
  await exec(`UPDATE users SET last_login_at = NOW(3) WHERE user_id = ?`, [user.user_id]);
  await audit({ orgId: null, actorType: "user", actorId: user.user_id, event: "login", details: { ip: meta.ip } });
  const session = await sessionFromToken(token);
  if (!session) throw new Error("session vanished right after creation");
  return { token, session };
}

export async function createSession(
  userId: string,
  meta: { ip: string | null; userAgent: string | null }
): Promise<string> {
  const token = randomToken();
  await exec(
    `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent)
     VALUES (?, ?, NOW(3) + INTERVAL ${SESSION_HOURS} HOUR, ?, ?)`,
    [sha256(token), userId, meta.ip, meta.userAgent?.slice(0, 255) ?? null]
  );
  return token;
}

export async function sessionFromToken(token: string | undefined | null): Promise<Session | null> {
  if (!token || token.length > 200) return null;
  const tokenHash = sha256(token);
  const row = await one<UserRow & { expires_at: Date }>(
    `SELECT u.user_id, u.email, u.first_name, u.last_name, u.platform_role, u.is_active, s.expires_at
     FROM sessions s JOIN users u ON u.user_id = s.user_id
     WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > NOW(3) AND u.is_active = TRUE
     LIMIT 1`,
    [tokenHash]
  );
  if (!row) return null;
  const memberships = await rows<{ org_id: string; name: string; slug: string; role: MembershipRole }>(
    `SELECT m.org_id, o.name, o.slug, m.role
     FROM memberships m JOIN organizations o ON o.org_id = m.org_id
     WHERE m.user_id = ? AND o.status = 'active'
     ORDER BY o.name`,
    [row.user_id]
  );
  return {
    userId: row.user_id,
    email: row.email,
    firstName: row.first_name,
    lastName: row.last_name,
    platformRole: row.platform_role,
    memberships: memberships.map((m) => ({ orgId: m.org_id, orgName: m.name, orgSlug: m.slug, role: m.role })),
    tokenHash,
    expiresAt: row.expires_at.toISOString(),
  };
}

export async function revokeSession(tokenHash: string): Promise<void> {
  await exec(`UPDATE sessions SET revoked_at = NOW(3) WHERE token_hash = ? AND revoked_at IS NULL`, [tokenHash]);
}

/** For API routes: read the session from the request cookie. */
export async function getRequestSession(req: NextRequest): Promise<Session | null> {
  return sessionFromToken(req.cookies.get(SESSION_COOKIE)?.value);
}

/** For server components / layouts: `const session = await getServerSession();` */
export async function getServerSession(): Promise<Session | null> {
  const { cookies } = await import("next/headers");
  const store = await cookies();
  return sessionFromToken(store.get(SESSION_COOKIE)?.value);
}

export function setSessionCookie(res: NextResponse, token: string): void {
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_HOURS * 3600,
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set(SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0,
  });
}
