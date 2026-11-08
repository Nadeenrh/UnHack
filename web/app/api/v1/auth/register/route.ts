import { NextResponse } from "next/server";
import type { OrgSector } from "@/contracts/types";
import { audit } from "@/lib/nightwatch/audit";
import { createSession, hashPassword, publicSession, sessionFromToken, setSessionCookie } from "@/lib/nightwatch/auth";
import { newId } from "@/lib/nightwatch/crypto";
import { one, tx } from "@/lib/nightwatch/db";
import { badRequest, clientIp, conflict, readJson, str } from "@/lib/nightwatch/http";
import { createOrganization, SECTORS } from "@/lib/nightwatch/orgs";
import { isPlanId, type PlanId } from "@/lib/nightwatch/plans";
import { open } from "@/lib/nightwatch/route";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// POST /api/v1/auth/register
// {
//   organization: { name, sector },            sector: small_business | healthcare | community_org | municipality | utility | other
//   user: { first_name, last_name, email, password }
// }
// Creates the org, its owner, default policies and a first site, then signs the owner in.
// The response includes the site's ingest key ONCE. It can't be shown again (only a hash is stored).
//
// Not built yet (zero-spend MVP): email verification. Add it before real customers sign up.
export const POST = open(async (req) => {
  const body = await readJson<{
    organization?: { name?: unknown; sector?: unknown; plan?: unknown; phone?: unknown };
    user?: { first_name?: unknown; last_name?: unknown; email?: unknown; password?: unknown };
  }>(req);
  const org = body.organization ?? {};
  const user = body.user ?? {};

  const orgName = str(org.name, "Organization name", { min: 2, max: 150 });
  const sector = String(org.sector ?? "") as OrgSector;
  if (!SECTORS.includes(sector)) throw badRequest(`Sector must be one of: ${SECTORS.join(", ")}.`);
  const plan: PlanId = isPlanId(org.plan) ? org.plan : "pilot";
  const phone = typeof org.phone === "string" && org.phone.trim() ? org.phone.trim().slice(0, 32) : null;

  const firstName = str(user.first_name, "First name", { max: 100 });
  const lastName = str(user.last_name, "Last name", { max: 100 });
  const email = str(user.email, "Email", { max: 150 }).toLowerCase();
  if (!EMAIL.test(email)) throw badRequest("Enter a valid email address.");
  const password = typeof user.password === "string" ? user.password : "";
  if (password.length < 12) throw badRequest("Password must be at least 12 characters.");
  if (password.length > 200) throw badRequest("Password is too long.");

  if (await one(`SELECT 1 FROM users WHERE email = ?`, [email])) {
    throw conflict("An account with this email already exists. Sign in instead.");
  }

  const userId = newId();
  const passwordHash = await hashPassword(password);
  const created = await tx(async (conn) => {
    await conn.execute(
      `INSERT INTO users (user_id, first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?, ?)`,
      [userId, firstName, lastName, email, passwordHash]
    );
    await audit({ orgId: null, actorType: "user", actorId: userId, event: "user_registered" }, conn);
    return createOrganization({ name: orgName, sector, ownerUserId: userId, plan, phone }, conn);
  });

  const token = await createSession(userId, { ip: clientIp(req), userAgent: req.headers.get("user-agent") });
  const session = await sessionFromToken(token);
  const res = NextResponse.json(
    {
      success: true,
      data: {
        ...publicSession(session!),
        organization: { id: created.orgId, slug: created.slug },
        first_site: {
          id: created.siteId,
          ingest_key: created.ingestKey,
          ingest_key_note: "Copy this now. It won't be shown again.",
        },
      },
    },
    { status: 201 }
  );
  setSessionCookie(res, token);
  return res;
});
