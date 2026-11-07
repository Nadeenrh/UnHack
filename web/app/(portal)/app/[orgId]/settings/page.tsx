import Link from "next/link";
import { PolicyEditor } from "@/components/settings/PolicyEditor";
import { SiteKeys } from "@/components/settings/SiteKeys";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { rows } from "@/lib/nightwatch/db";
import { isOwner, requirePageOrg } from "@/lib/nightwatch/page-auth";
import { listPolicies } from "@/lib/nightwatch/policy";
import { ingestUrl, publicBaseUrl } from "@/lib/nightwatch/public-url";

export const metadata = { title: "Settings" };

export default async function SettingsPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const { access } = await requirePageOrg(orgId);
  const owner = isOwner(access);
  const [policies, sites, baseUrl] = await Promise.all([
    listPolicies(orgId),
    rows<{ site_id: string; name: string; ingest_key_prefix: string; revoked_at: Date | null }>(
      `SELECT site_id, name, ingest_key_prefix, revoked_at FROM sites WHERE org_id = ? ORDER BY created_at`,
      [orgId]
    ),
    publicBaseUrl(),
  ]);

  return (
    <>
      <PageHeader title="Settings" subtitle={owner ? undefined : "Only owners can change these."} />
      <div className="space-y-6">
        <Panel title="What Nightwatch may do on its own">
          <p className="border-b border-line px-5 py-3 text-sm text-muted">
            For each kind of response, choose whether Nightwatch acts right away, asks an approver, or only recommends it. Anything that
            affects a machine or an account always needs a person.
          </p>
          <PolicyEditor orgId={orgId} policies={policies} editable={owner} />
        </Panel>

        <Panel title="Monitoring connections">
          <p className="border-b border-line px-5 py-3 text-sm text-muted">
            Each site sends its alerts to Nightwatch with its own key. Replace a key if you think it leaked.{" "}
            <Link href={`/app/${orgId}/connect`} className="font-medium text-info hover:underline">
              Setup steps
            </Link>
          </p>
          <SiteKeys
            orgId={orgId}
            editable={owner}
            hookUrl={ingestUrl(baseUrl)}
            sites={sites.map((s) => ({ id: s.site_id, name: s.name, ingest_key_prefix: s.ingest_key_prefix, active: s.revoked_at === null }))}
          />
        </Panel>
      </div>
    </>
  );
}
