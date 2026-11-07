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
        subtitle={
          assets.length
            ? `${assets.length - offline} of ${assets.length} reporting in.${offline ? " A machine that stops reporting can't be protected." : ""}`
            : undefined
        }
      />
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
          <EmptyState title="No machines yet">Machines appear here as soon as your monitoring sends its first alert.</EmptyState>
        )}
      </Panel>
    </>
  );
}
