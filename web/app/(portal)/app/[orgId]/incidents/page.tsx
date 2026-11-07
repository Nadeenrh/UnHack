import Link from "next/link";
import { IncidentTable } from "@/components/incidents/IncidentTable";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { expireStaleActions, loadIncidents } from "@/lib/nightwatch/incidents";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";

export const metadata = { title: "Incidents" };

const TABS = [
  { key: "open", label: "Open" },
  { key: "closed", label: "Closed" },
  { key: "all", label: "All" },
] as const;

export default async function IncidentsPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgId: string }>;
  searchParams: Promise<{ status?: string }>;
}) {
  const { orgId } = await params;
  const { status: raw } = await searchParams;
  await requirePageOrg(orgId);
  const status = raw === "closed" || raw === "all" ? raw : "open";
  await expireStaleActions(orgId);
  const incidents = await loadIncidents(orgId, { status, limit: 200 });

  return (
    <>
      <PageHeader title="Incidents" subtitle="Everything Nightwatch has investigated, newest first." />
      <nav aria-label="Filter incidents" className="mb-4 flex gap-1">
        {TABS.map((t) => (
          <Link
            key={t.key}
            href={`/app/${orgId}/incidents?status=${t.key}`}
            aria-current={status === t.key ? "page" : undefined}
            className={`rounded-md px-3 py-1.5 text-sm font-medium ${status === t.key ? "bg-ink text-night" : "text-muted hover:bg-panel"}`}
          >
            {t.label}
          </Link>
        ))}
      </nav>
      <Panel>
        {incidents.length ? (
          <IncidentTable incidents={incidents} orgId={orgId} />
        ) : (
          <EmptyState title={status === "open" ? "Nothing open right now" : "No incidents here yet"} />
        )}
      </Panel>
    </>
  );
}
