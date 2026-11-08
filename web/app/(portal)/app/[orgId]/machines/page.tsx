import { capitalize, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";
import { listAssets } from "@/lib/nightwatch/snapshots";

export const metadata = { title: "Machines" };

const AGENT: Record<string, [string, string]> = {
  online: ["Reporting in", "bg-ok"],
  offline: ["Not reporting", "bg-bad"],
  never_connected: ["Never connected", "bg-muted"],
};

export default async function MachinesPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  await requirePageOrg(orgId);
  const assets = await listAssets(orgId);
  const offline = assets.filter((a) => a.agent_status !== "online").length;

  return (
    <>
      <PageHeader
        title="Machines"
        subtitle="The computers Nightwatch watches for you. This list updates by itself. Your Nightwatch team adds and removes machines."
      />
      {offline > 0 && (
        <div role="status" className="mb-4 rounded-lg border border-lantern/50 bg-lantern-soft px-5 py-3 text-sm">
          <p className="font-semibold">
            {offline} of {assets.length} {assets.length === 1 ? "machine isn't" : "machines aren't"} reporting in
          </p>
          <p className="mt-0.5">
            Nightwatch can&apos;t protect a computer it can&apos;t hear from. Usually it&apos;s just switched off or off the network. If it
            should be on, tell your Nightwatch team. They can see this too.
          </p>
        </div>
      )}
      <Panel>
        {assets.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-muted">
                  <th className="px-5 py-2 font-medium">Machine</th>
                  <th className="px-3 py-2 font-medium">Type</th>
                  <th className="hidden px-3 py-2 font-medium sm:table-cell">System</th>
                  <th className="px-3 py-2 font-medium">Monitoring</th>
                  <th className="px-5 py-2 text-right font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => {
                  const [label, dot] = AGENT[a.agent_status];
                  return (
                    <tr key={a.id} className="border-b border-line last:border-0">
                      <td className="px-5 py-3">
                        <div className="font-mono font-medium">{a.hostname}</div>
                        {a.ip && <div className="font-mono text-xs text-muted">{a.ip}</div>}
                      </td>
                      <td className="px-3 py-3">{capitalize(a.kind)}</td>
                      <td className="hidden px-3 py-3 text-muted sm:table-cell">{a.os ?? "Unknown"}</td>
                      <td className="px-3 py-3">
                        <span className="inline-flex items-center gap-2">
                          <span aria-hidden className={`size-2 rounded-full ${dot}`} />
                          {label}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-right text-muted">{timeAgo(a.last_seen_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No machines yet">
            Your Nightwatch team is connecting your computers. They appear here by themselves once they start reporting.
          </EmptyState>
        )}
      </Panel>
    </>
  );
}
