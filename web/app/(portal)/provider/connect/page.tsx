import Link from "next/link";
import { SECTOR_LABEL, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { iso, rows } from "@/lib/nightwatch/db";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";

export const metadata = { title: "Connect a client" };

// A client counts as connected once Wazuh has delivered at least one alert with their key.
const QUIET_AFTER_MS = 24 * 60 * 60 * 1000;

export function connection(last: string | null, now = Date.now()): [string, string] {
  if (!last) return ["Waiting for the first alert", "bg-muted"];
  if (now - new Date(last).getTime() > QUIET_AFTER_MS) return [`Quiet since ${timeAgo(last)}`, "bg-lantern"];
  return [`Receiving, last ${timeAgo(last)}`, "bg-ok"];
}

export default async function ProviderConnectPage() {
  await requirePageProvider();
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

  return (
    <>
      <PageHeader title="Connect a client" subtitle="Every organization we protect. Open one to see its contact, its key and how to connect it.">
        <span className="rounded-md px-3 py-1.5 text-sm font-medium text-muted ring-1 ring-line">Add a client — coming soon</span>
      </PageHeader>

      <Panel title="Connection status">
        {clients.length ? (
          <ul>
            {clients.map((c) => {
              const [label, dot] = connection(iso(c.last_alert));
              return (
                <li key={c.org_id}>
                  <Link
                    href={`/provider/connect/${c.org_id}`}
                    className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line px-5 py-4 last:border-0 hover:bg-canvas"
                  >
                    <div className="min-w-48 flex-1">
                      <div className="font-medium">{c.name}</div>
                      <div className="text-xs text-muted">{SECTOR_LABEL[c.sector] ?? c.sector}</div>
                    </div>
                    <div className="text-sm text-muted">
                      Key <span className="font-mono">{c.key_prefix ?? "none"}</span>
                    </div>
                    <div className="text-sm tabular-nums text-muted">
                      {Number(c.machines)} {Number(c.machines) === 1 ? "machine" : "machines"}
                    </div>
                    <div className="flex min-w-48 items-center gap-2 text-sm">
                      <span aria-hidden className={`size-2 rounded-full ${dot}`} />
                      {label}
                    </div>
                    <span aria-hidden className="text-muted">
                      ›
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        ) : (
          <EmptyState title="No clients yet">Clients appear here when they sign up.</EmptyState>
        )}
      </Panel>
    </>
  );
}
