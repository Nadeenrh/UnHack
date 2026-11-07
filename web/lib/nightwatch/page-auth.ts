// Auth for server-rendered pages. Every page calls one of these itself (not just the layout),
// because layouts don't re-run on every navigation.

import { notFound, redirect } from "next/navigation";
import { requireOrgAccess, isProvider, type OrgAccess } from "./access";
import { getServerSession, type Session } from "./auth";
import { HttpError } from "./http";

export async function requirePageSession(next?: string): Promise<Session> {
  const session = await getServerSession();
  if (!session) redirect(next ? `/login?next=${encodeURIComponent(next)}` : "/login");
  return session;
}

/** Session + read access to this org, or a 404 page (same for "doesn't exist" and "not yours"). */
export async function requirePageOrg(orgId: string): Promise<{ session: Session; access: OrgAccess }> {
  const session = await requirePageSession(`/app/${orgId}`);
  try {
    const access = await requireOrgAccess(session, orgId, "read");
    return { session, access };
  } catch (err) {
    if (err instanceof HttpError) notFound();
    throw err;
  }
}

export async function requirePageProvider(): Promise<Session> {
  const session = await requirePageSession("/provider");
  if (!isProvider(session)) notFound();
  return session;
}

/** Can this person approve/deny in this org? (Support access never can.) */
export function canApprove(access: OrgAccess): boolean {
  return access.via === "membership" && (access.role === "approver" || access.role === "owner");
}

export function isOwner(access: OrgAccess): boolean {
  return access.via === "membership" && access.role === "owner";
}
