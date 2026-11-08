import Link from "next/link";
import { notFound } from "next/navigation";
import { ConnectSteps } from "@/components/connect/ConnectSteps";
import { capitalize, formatDateTime, SECTOR_LABEL, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { iso, one, rows } from "@/lib/nightwatch/db";
import { isUuid } from "@/lib/nightwatch/access";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";
import { isLoopback, publicBaseUrl } from "@/lib/nightwatch/public-url";
import { connection } from "../page";

const ROLE_LABEL: Record<string, string> = {
  owner: "Owner",
  approver: "Approver",
  analyst: "Analyst",
  viewer: "Viewer",
};

export default async function ClientDetailPage({ params }: { params: Promise<{ orgId: string }> }) {
  await requirePageProvider();
  const { orgId } = await params;
  if (!isUuid(orgId)) notFound();
  const baseUrl = await publicBaseUrl();

  const org = await one<{ name: string; sector: string; plan: string; created_at: Date; contact_phone: string | null }>(
    `SELECT name, sector, plan, created_at, contact_phone FROM organizations WHERE org_id = ? AND status = 'active'`,
    [orgId]
  );
  if (!org) notFound();

  const [site, contacts, stats] = await Promise.all([
    one<{ ingest_key_prefix: string; last_alert: Date | null }>(
      `SELECT s.ingest_key_prefix,
              (SELECT MAX(a.received_at) FROM alerts a WHERE a.org_id = s.org_id) AS last_alert
         FROM sites s WHERE s.org_id = ? AND s.revoked_at IS NULL ORDER BY s.created_at LIMIT 1`,
      [orgId]
    ),
    rows<{ first_name: string; last_name: string; email: string; role: string }>(
      `SELECT u.first_name, u.last_name, u.email, m.role
         FROM memberships m JOIN users u ON u.user_id = m.user_id
        WHERE m.org_id = ?
        ORDER BY FIELD(m.role, 'owner', 'approver', 'analyst', 'viewer'), u.first_name`,
      [orgId]
    ),
    one<{ machines: number; incidents: number }>(
      `SELECT (SELECT COUNT(*) FROM assets WHERE org_id = ?) AS machines,
              (SELECT COUNT(*) FROM incidents WHERE org_id = ?) AS incidents`,
      [orgId, orgId]
    ),
  ]);

  const lastAlert = iso(site?.last_alert ?? null);
  const [statusLabel, dot] = connection(lastAlert);
  const owner = contacts.find((c) => c.role === "owner");

  return (
    <>
      <Link href="/provider/connect" className="text-sm font-medium text-info hover:underline">
        ‹ Back to clients
      </Link>

      <PageHeader title={org.name} subtitle={`${SECTOR_LABEL[org.sector] ?? org.sector} · ${capitalize(org.plan)} plan · Client since ${formatDateTime(iso(org.created_at))}`}>
        <span className="inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm ring-1 ring-line">
          <span aria-hidden className={`size-2 rounded-full ${dot}`} />
          {statusLabel}
        </span>
      </PageHeader>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="space-y-6">
          <Panel title="Who to contact">
            {org.contact_phone && (
              <div className="flex items-center justify-between gap-2 border-b border-line px-5 py-3">
                <div>
                  <div className="font-medium">Business line</div>
                  <a href={`tel:${org.contact_phone.replace(/[^\d+]/g, "")}`} className="text-sm text-info hover:underline">
                    {org.contact_phone}
                  </a>
                </div>
                <span className="rounded-full bg-canvas px-2 py-0.5 text-xs font-medium text-muted">Phone</span>
              </div>
            )}
            {contacts.length ? (
              <ul>
                {contacts.map((c) => (
                  <li key={c.email} className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-5 py-3 last:border-0">
                    <div>
                      <div className="font-medium">
                        {c.first_name} {c.last_name}
                      </div>
                      <a href={`mailto:${c.email}`} className="text-sm text-info hover:underline">
                        {c.email}
                      </a>
                    </div>
                    <span className="rounded-full bg-canvas px-2 py-0.5 text-xs font-medium text-muted">{ROLE_LABEL[c.role] ?? c.role}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No contacts yet" />
            )}
          </Panel>

          <Panel title="Connect this client in Wazuh">
            <div className="space-y-3 px-5 py-4 text-sm">
              <p className="text-muted">
                Paste the client&apos;s ingest key into the block below, then add it to their Wazuh manager&apos;s{" "}
                <span className="font-mono">ossec.conf</span>. The key is shown once at sign-up, so ask{" "}
                {owner ? `${owner.first_name} (${owner.email})` : "the owner"} for it if you don&apos;t have it.
              </p>
              <p>
                This client&apos;s key starts with <span className="font-mono">{site?.ingest_key_prefix ?? "no active key"}</span>, so you can
                check you&apos;re pasting the right one.
              </p>
              <ConnectSteps baseUrl={baseUrl} ingestKey={null} keyPrefix={site?.ingest_key_prefix} loopback={isLoopback(baseUrl)} />
            </div>
          </Panel>
        </div>

        <aside className="space-y-6">
          <Panel title="At a glance">
            <dl className="space-y-3 px-5 py-4 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Alerts</dt>
                <dd className="flex items-center gap-2 font-medium">
                  <span aria-hidden className={`size-2 rounded-full ${dot}`} />
                  {lastAlert ? `Last ${timeAgo(lastAlert)}` : "None yet"}
                </dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Machines</dt>
                <dd className="font-medium tabular-nums">{Number(stats?.machines ?? 0)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Incidents, all time</dt>
                <dd className="font-medium tabular-nums">{Number(stats?.incidents ?? 0)}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Key starts with</dt>
                <dd className="font-mono">{site?.ingest_key_prefix ?? "none"}</dd>
              </div>
            </dl>
          </Panel>
        </aside>
      </div>
    </>
  );
}
