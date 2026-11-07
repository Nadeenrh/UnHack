// Who may see or do what, per organization. Every org-scoped API route calls requireOrgAccess.
//
//   viewer   read
//   analyst  read
//   approver read, approve/deny actions
//   owner    read, approve/deny, change policies and settings
//
// Provider staff (us) are NOT members of client orgs. They can read a client's workspace
// only through an open, time-boxed support session, which is audited when it starts.
// Support access is read-only: approving a client's response is the client's decision.

import type { MembershipRole, Session } from "./auth";
import { one } from "./db";
import { forbidden, notFound } from "./http";

const RANK: Record<MembershipRole, number> = { viewer: 1, analyst: 2, approver: 3, owner: 4 };
const NEED: Record<"read" | "approve" | "admin", number> = { read: 1, approve: 3, admin: 4 };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface OrgAccess {
  orgId: string;
  orgName: string;
  via: "membership" | "support";
  role: MembershipRole | null;
  supportSessionId: string | null;
}

export function isUuid(value: string): boolean {
  return UUID.test(value);
}

export function isProvider(session: Session): boolean {
  return session.platformRole === "provider_staff" || session.platformRole === "provider_admin";
}

export function requireProvider(session: Session): void {
  if (!isProvider(session)) throw forbidden("Provider access only.");
}

export async function requireOrgAccess(
  session: Session,
  orgId: string,
  need: "read" | "approve" | "admin"
): Promise<OrgAccess> {
  // Unknown and forbidden orgs look identical (404), so org ids can't be probed.
  if (!isUuid(orgId)) throw notFound("Organization not found.");

  const m = session.memberships.find((x) => x.orgId === orgId);
  if (m) {
    if (RANK[m.role] < NEED[need]) {
      throw forbidden(need === "approve" ? "Only approvers and owners can do this." : "Only owners can do this.");
    }
    return { orgId, orgName: m.orgName, via: "membership", role: m.role, supportSessionId: null };
  }

  if (isProvider(session)) {
    const support = await one<{ session_id: string; name: string }>(
      `SELECT s.session_id, o.name
       FROM support_sessions s JOIN organizations o ON o.org_id = s.org_id
       WHERE s.org_id = ? AND s.staff_user_id = ? AND s.ended_at IS NULL AND s.expires_at > NOW(3)
       ORDER BY s.started_at DESC LIMIT 1`,
      [orgId, session.userId]
    );
    if (support) {
      if (need !== "read") throw forbidden("Support access is read-only. The client makes this decision.");
      return { orgId, orgName: support.name, via: "support", role: null, supportSessionId: support.session_id };
    }
  }

  throw notFound("Organization not found.");
}
