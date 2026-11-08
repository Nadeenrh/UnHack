import { PolicyEditor } from "@/components/settings/PolicyEditor";
import { SiteKeys } from "@/components/settings/SiteKeys";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { rows } from "@/lib/nightwatch/db";
import { isOwner, requirePageOrg } from "@/lib/nightwatch/page-auth";
import { listPolicies } from "@/lib/nightwatch/policy";
import { supportContact } from "@/lib/nightwatch/support";

export const metadata = { title: "Settings" };

export default async function SettingsPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  const { access } = await requirePageOrg(orgId);
  const owner = isOwner(access);
  const support = supportContact();
  const [policies, sites] = await Promise.all([
    listPolicies(orgId),
    rows<{ site_id: string; name: string; ingest_key_prefix: string; revoked_at: Date | null }>(
      `SELECT site_id, name, ingest_key_prefix, revoked_at FROM sites WHERE org_id = ? ORDER BY created_at`,
      [orgId]
    ),
  ]);

  return (
    <>
      <PageHeader title="Settings" subtitle={owner ? undefined : "Only owners can change these."} />
      <div className="space-y-6">
        <Panel title="Your NightWatch team">
          <div className="grid gap-4 px-5 py-4 text-sm sm:grid-cols-3">
            <div>
              <div className="text-muted">Email</div>
              <a href={`mailto:${support.email}`} className="font-medium text-info hover:underline">
                {support.email}
              </a>
            </div>
            <div>
              <div className="text-muted">Phone</div>
              <a href={`tel:${support.phone.replace(/[^\d+]/g, "")}`} className="font-medium text-info hover:underline">
                {support.phone}
              </a>
            </div>
            <div>
              <div className="text-muted">Availability</div>
              <div className="font-medium">{support.hours}</div>
            </div>
          </div>
          <p className="border-t border-line px-5 py-3 text-sm text-muted">
            We watch your network for you. Reach out any time something looks wrong, or you want to add or remove a machine.
          </p>
        </Panel>

        <Panel title="What NightWatch may do on its own">
          <p className="border-b border-line px-5 py-3 text-sm text-muted">
            For each kind of response, choose whether NightWatch acts right away, asks an approver, or only recommends it. Anything that
            affects a machine or an account always needs a person.
          </p>
          <PolicyEditor orgId={orgId} policies={policies} editable={owner} />
        </Panel>

        <Panel title="Monitoring connections">
          <p className="border-b border-line px-5 py-3 text-sm text-muted">
            Each site sends its alerts to NightWatch with its own key. Replace a key if you think it leaked, then send the new one to your NightWatch team.
          </p>
          <SiteKeys
            orgId={orgId}
            editable={owner}
            sites={sites.map((s) => ({ id: s.site_id, name: s.name, ingest_key_prefix: s.ingest_key_prefix, active: s.revoked_at === null }))}
          />
        </Panel>
      </div>
    </>
  );
}
