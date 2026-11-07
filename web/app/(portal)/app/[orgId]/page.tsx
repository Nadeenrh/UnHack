import Link from "next/link";
import { ACTION_LABEL, formatDateTime, timeAgo } from "@/components/format";
import { IncidentTable } from "@/components/incidents/IncidentTable";
import { HealthBadge } from "@/components/ui/Badges";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { ActivityChart } from "@/components/ui/ActivityChart";
import { StatTile } from "@/components/ui/StatTile";
import { loadIncidents } from "@/lib/nightwatch/incidents";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";
import { alertsByHour, snapshots } from "@/lib/nightwatch/snapshots";

export const metadata = { title: "Dashboard" };

export default async function DashboardPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const { access } = await requirePageOrg(orgId);
  const [[snap], open, hourly] = await Promise.all([
    snapshots([orgId]),
    loadIncidents(orgId, { status: "open", limit: 50 }),
    alertsByHour(orgId),
  ]);
  const base = `/app/${orgId}`;

  const waiting = open.flatMap((i) => i.actions.filter((a) => a.status === "awaiting_approval").map((a) => ({ a, i })));
  const criticalOpen = open.filter((i) => i.severity === "critical").length;

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={snap.last_activity_at ? `Last activity ${timeAgo(snap.last_activity_at)}` : "No activity yet"}
      >
        <HealthBadge health={snap.health} />
      </PageHeader>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        <StatTile tone={waiting.length ? "lantern" : "quiet"} value={waiting.length} label="Waiting for your decision" href={`${base}/incidents?status=open`} linkText="Review" />
        <StatTile tone="info" value={snap.open_incidents} label="Open incidents" href={`${base}/incidents?status=open`} linkText="View incidents" />
        <StatTile tone={criticalOpen ? "critical" : "quiet"} value={criticalOpen} label="Critical and open" href={`${base}/incidents?status=open`} linkText="View" />
        <StatTile tone="ok" value={`${snap.assets_online}/${snap.assets_total}`} label="Machines reporting in" href={`${base}/machines`} linkText="View machines" />
      </div>

      {waiting.length > 0 && (
        <Panel title="Waiting for your decision" tone="lantern" className="mt-6">
          <ul>
            {waiting.map(({ a, i }) => (
              <li key={a.id} className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-3 last:border-0">
                <div className="min-w-0">
                  <div className="font-medium">
                    {ACTION_LABEL[a.type]} <span className="font-mono">{a.target}</span>
                  </div>
                  <div className="text-sm text-muted">
                    {i.ref}: {i.title}. Requested {formatDateTime(a.requested_at)}
                  </div>
                </div>
                <Link
                  href={`${base}/incidents/${i.id}`}
                  className="rounded-md bg-lantern px-4 py-2 text-sm font-semibold text-night hover:brightness-105"
                >
                  Review and decide
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel title="Alerts, last 24 hours" className="mt-6">
        <ActivityChart buckets={hourly} />
      </Panel>

      <Panel
        title="Open incidents"
        className="mt-6"
        action={
          <Link href={`${base}/incidents`} className="text-sm font-medium text-info hover:underline">
            All incidents
          </Link>
        }
      >
        {open.length ? <IncidentTable incidents={open.slice(0, 8)} orgId={orgId} /> : <EmptyState title="Nothing open right now">Nightwatch is watching. New incidents show up here.</EmptyState>}
      </Panel>
    </>
  );
}
