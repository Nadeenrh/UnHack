import { Shell } from "@/components/shell/Shell";
import { SupportBanner } from "@/components/provider/SupportBanner";
import { isProvider } from "@/lib/nightwatch/access";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";
import { pendingApprovals } from "@/lib/nightwatch/snapshots";

export default async function ClientPortalLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ orgId: string }>;
}) {
  const { orgId } = await params;
  const { session, access } = await requirePageOrg(orgId);
  const pending = await pendingApprovals(orgId);
  const base = `/app/${orgId}`;

  // Members see their orgs in the switcher; provider staff in a support session see just this one.
  const orgs =
    access.via === "membership"
      ? session.memberships.map((m) => ({ id: m.orgId, name: m.orgName }))
      : [{ id: orgId, name: access.orgName }];

  return (
    <Shell
      nav={[
        { href: base, label: "Dashboard", exact: true },
        { href: `${base}/incidents`, label: "Incidents", count: pending },
        { href: `${base}/machines`, label: "Machines" },
        { href: `${base}/connect`, label: "Connect machines" },
        { href: `${base}/activity`, label: "Activity log" },
        { href: `${base}/settings`, label: "Settings" },
      ]}
      user={{ name: `${session.firstName} ${session.lastName}`, email: session.email }}
      orgs={orgs}
      currentOrgId={orgId}
      providerLink={isProvider(session)}
      banner={access.via === "support" ? <SupportBanner orgName={access.orgName} sessionId={access.supportSessionId!} /> : undefined}
    >
      {children}
    </Shell>
  );
}
