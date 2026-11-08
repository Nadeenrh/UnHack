import type { ProviderOrgSnapshot } from "@/contracts/types";
import { capitalize, formatDateTime, SECTOR_LABEL, timeAgo } from "@/components/format";
import { OpenWorkspace } from "@/components/provider/OpenWorkspace";
import { DataSourceBadge, HealthBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/Badges";
import { PageHeader } from "@/components/ui/Panel";
import { StatTile } from "@/components/ui/StatTile";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";
import { snapshots } from "@/lib/nightwatch/snapshots";
import { wazuhHomeLink } from "@/lib/nightwatch/wazuh-link";

export const metadata = { title: "Clients" };

const ORDER = { attention: 0, watch: 1, healthy: 2 } as const;

export default async function ProviderOverview() {
  await requirePageProvider();
  const clients = (await snapshots()).sort((a, b) => ORDER[a.health] - ORDER[b.health] || a.org.name.localeCompare(b.org.name));

  const wazuh = wazuhHomeLink();
  const pending = clients.reduce((n, c) => n + c.pending_approvals, 0);
  const open = clients.reduce((n, c) => n + c.open_incidents, 0);
  const attention = clients.filter((c) => c.health === "attention").length;
  const online = clients.reduce((n, c) => n + c.assets_online, 0);
  const total = clients.reduce((n, c) => n + c.assets_total, 0);

  return (
    <>
      <PageHeader title="Clients" subtitle="Status of every organization Nightwatch protects. Clients needing attention are listed first." />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        <StatTile tone={attention ? "lantern" : "quiet"} value={attention} label="Clients needing attention" />
        <StatTile tone="info" value={open} label="Open incidents, all clients" />
        <StatTile tone={pending ? "high" : "quiet"} value={pending} label="Waiting on a client decision" />
        <StatTile tone="ok" value={`${online}/${total}`} label="Machines reporting in" />
      </div>

      <div className="mt-6 space-y-3">
        {clients.map((c) => (
          <ClientCard key={c.org.id} c={c} wazuh={wazuh} />
        ))}
      </div>
    </>
  );
}

function ClientCard({ c, wazuh }: { c: ProviderOrgSnapshot; wazuh: string | null }) {
  return (
    <details open={c.health === "attention"} className="group rounded-lg border border-line bg-panel">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-6 gap-y-2 px-5 py-4 [&::-webkit-details-marker]:hidden">
        <span aria-hidden className="text-muted transition-transform group-open:rotate-90">
          ▸
        </span>
        <div className="min-w-48 flex-1">
          <div className="font-semibold">{c.org.name}</div>
          <div className="text-sm text-muted">
            {SECTOR_LABEL[c.org.sector]}, {capitalize(c.org.plan)} plan
          </div>
        </div>
        <HealthBadge health={c.health} />
        <dl className="flex gap-6 text-sm">
          <div>
            <dt className="text-muted">Open</dt>
            <dd className="font-semibold tabular-nums">{c.open_incidents}</dd>
          </div>
          <div>
            <dt className="text-muted">Waiting</dt>
            <dd className={`font-semibold tabular-nums ${c.pending_approvals ? "text-lantern-deep" : ""}`}>{c.pending_approvals}</dd>
          </div>
          <div>
            <dt className="text-muted">Machines</dt>
            <dd className="font-semibold tabular-nums">
              {c.assets_online}/{c.assets_total}
            </dd>
          </div>
        </dl>
        <span className="text-sm text-muted">{c.last_activity_at ? timeAgo(c.last_activity_at) : "No activity"}</span>
      </summary>

      <div className="grid gap-6 border-t border-line px-5 py-4 md:grid-cols-2">
        <div>
          <h3 className="text-sm font-semibold">Recent incidents</h3>
          {c.recent_incidents.length ? (
            <ul className="mt-2 space-y-2">
              {c.recent_incidents.map((i) => (
                <li key={i.id} className="text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-muted">{i.ref}</span>
                    <SeverityBadge severity={i.severity} />
                    <IncidentStatusBadge status={i.status} />
                  </div>
                  <div className="mt-0.5">{i.title}</div>
                  <div className="text-xs text-muted">{formatDateTime(i.detected_at)}</div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-muted">None yet.</p>
          )}
        </div>
        <div>
          <h3 className="text-sm font-semibold">Machines</h3>
          <ul className="mt-2 space-y-1 text-sm">
            {c.assets.map((a) => (
              <li key={a.id} className="flex items-center gap-2">
                <span aria-hidden className={`size-2 rounded-full ${a.agent_status === "online" ? "bg-ok" : "bg-bad"}`} />
                <span className="font-mono">{a.hostname}</span>
                <span className="text-muted">{a.agent_status === "online" ? "reporting" : "not reporting"}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-4 md:col-span-2">
          <DataSourceBadge source={c.data_source} />
          <div className="flex flex-wrap items-center gap-3">
            {wazuh && (
              <a href={wazuh} target="_blank" rel="noreferrer" className="rounded-md px-3 py-1.5 text-sm font-medium ring-1 ring-line hover:bg-canvas">
                Open in Wazuh
              </a>
            )}
            <OpenWorkspace orgId={c.org.id} orgName={c.org.name} />
          </div>
        </div>
      </div>
    </details>
  );
}
