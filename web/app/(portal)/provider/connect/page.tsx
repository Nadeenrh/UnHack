import { ConnectSteps } from "@/components/connect/ConnectSteps";
import { SECTOR_LABEL, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { iso, rows } from "@/lib/nightwatch/db";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";
import { isLoopback, publicBaseUrl } from "@/lib/nightwatch/public-url";

export const metadata = { title: "Connect a client" };

// A client counts as connected once Wazuh has delivered at least one alert with their key.
const QUIET_AFTER_MS = 24 * 60 * 60 * 1000;

export default async function ProviderConnectPage() {
  await requirePageProvider();
  const baseUrl = await publicBaseUrl();
  const clients = await rows<{
    org_id: string;
    name: string;
    sector: string;
    key_prefix: string | null;
    last_alert: Date | null;
    machines: number;
  }>(
    `SELECT o.org_id, o.name, o.sector,
            (SELECT s.ingest_key_prefix FROM sites s WHERE s.org_id = o.org_id AND s.revoked_at IS NULL ORDER BY s.created_at LIMIT 1) AS key_prefix,
            (SELECT MAX(a.received_at) FROM alerts a WHERE a.org_id = o.org_id) AS last_alert,
            (SELECT COUNT(*) FROM assets m WHERE m.org_id = o.org_id) AS machines
     FROM organizations o WHERE o.status = 'active' ORDER BY o.name`
  );
  const now = Date.now();

  return (
    <>
      <PageHeader
        title="Connect a client"
        subtitle="We connect each client's computers through Wazuh. The client never installs or configures anything themselves."
      />

      <div className="space-y-6">
        <Panel title="Connection status">
          {clients.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-muted">
                    <th className="px-5 py-2 font-medium">Client</th>
                    <th className="px-3 py-2 font-medium">Key starts with</th>
                    <th className="px-3 py-2 font-medium">Machines</th>
                    <th className="px-5 py-2 text-right font-medium">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map((c) => {
                    const last = iso(c.last_alert);
                    const state = !last ? "waiting" : now - new Date(last).getTime() > QUIET_AFTER_MS ? "quiet" : "receiving";
                    const [label, dot] = {
                      waiting: ["Waiting for the first alert", "bg-muted"],
                      quiet: [`Quiet since ${timeAgo(last)}`, "bg-lantern"],
                      receiving: [`Receiving, last ${timeAgo(last)}`, "bg-ok"],
                    }[state];
                    return (
                      <tr key={c.org_id} className="border-b border-line last:border-0">
                        <td className="px-5 py-3">
                          <div className="font-medium">{c.name}</div>
                          <div className="text-xs text-muted">{SECTOR_LABEL[c.sector] ?? c.sector}</div>
                        </td>
                        <td className="px-3 py-3 font-mono">{c.key_prefix ?? "No active key"}</td>
                        <td className="px-3 py-3 tabular-nums">{Number(c.machines)}</td>
                        <td className="px-5 py-3 text-right">
                          <span className="inline-flex items-center gap-2">
                            <span aria-hidden className={`size-2 rounded-full ${dot}`} />
                            {label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No clients yet">Clients appear here when they sign up.</EmptyState>
          )}
        </Panel>

        <Panel title="Setup steps">
          <div className="px-5 py-5">
            <ConnectSteps baseUrl={baseUrl} ingestKey={null} loopback={isLoopback(baseUrl)} />
          </div>
        </Panel>
      </div>
    </>
  );
}
