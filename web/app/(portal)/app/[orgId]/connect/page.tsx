import Link from "next/link";
import { ConnectSteps } from "@/components/connect/ConnectSteps";
import { timeAgo } from "@/components/format";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { iso, one, rows } from "@/lib/nightwatch/db";
import { isOwner, requirePageOrg } from "@/lib/nightwatch/page-auth";
import { isLoopback, publicBaseUrl } from "@/lib/nightwatch/public-url";

export const metadata = { title: "Connect machines" };

export default async function ConnectPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const { access } = await requirePageOrg(orgId);
  const baseUrl = await publicBaseUrl();

  const [sites, last, machines] = await Promise.all([
    rows<{ ingest_key_prefix: string }>(
      `SELECT ingest_key_prefix FROM sites WHERE org_id = ? AND revoked_at IS NULL ORDER BY created_at LIMIT 1`,
      [orgId]
    ),
    one<{ at: Date | null }>(`SELECT MAX(received_at) AS at FROM alerts WHERE org_id = ?`, [orgId]),
    one<{ n: number }>(`SELECT COUNT(*) AS n FROM assets WHERE org_id = ?`, [orgId]),
  ]);
  const lastAlert = iso(last?.at ?? null);
  const machineCount = Number(machines?.n ?? 0);

  return (
    <>
      <PageHeader
        title="Connect machines"
        subtitle="Nightwatch works on top of Wazuh, the free open-source security monitor. Four steps, about 15 minutes."
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <Panel title="Set up">
          <div className="px-5 py-5">
            <ConnectSteps baseUrl={baseUrl} ingestKey={null} keyPrefix={sites[0]?.ingest_key_prefix} loopback={isLoopback(baseUrl)} />
          </div>
        </Panel>

        <aside className="space-y-6">
          <Panel title="Status">
            <dl className="space-y-3 px-5 py-4 text-sm">
              <div>
                <dt className="text-muted">Last alert received</dt>
                <dd className="mt-0.5 flex items-center gap-2 font-medium">
                  <span aria-hidden className={`size-2 rounded-full ${lastAlert ? "bg-ok" : "bg-muted"}`} />
                  {lastAlert ? timeAgo(lastAlert) : "Waiting for the first alert"}
                </dd>
              </div>
              <div>
                <dt className="text-muted">Machines seen</dt>
                <dd className="mt-0.5 font-medium">
                  {machineCount ? (
                    <Link href={`/app/${orgId}/machines`} className="text-info hover:underline">
                      {machineCount} {machineCount === 1 ? "machine" : "machines"}
                    </Link>
                  ) : (
                    "None yet"
                  )}
                </dd>
              </div>
            </dl>
          </Panel>

          <Panel title="What gets sent">
            <ul className="list-disc space-y-1.5 py-4 pr-5 pl-9 text-sm text-muted">
              <li>Security events only: sign-ins, blocked connections, programs started, files changed.</li>
              <li>Never patient records, documents or email contents.</li>
              <li>Nothing on your network changes without your approval, unless you allow it in Settings.</li>
            </ul>
          </Panel>

          {isOwner(access) && (
            <p className="px-1 text-sm text-muted">
              Need a new key?{" "}
              <Link href={`/app/${orgId}/settings`} className="font-medium text-info hover:underline">
                Settings → Monitoring connections
              </Link>
            </p>
          )}
        </aside>
      </div>
    </>
  );
}
