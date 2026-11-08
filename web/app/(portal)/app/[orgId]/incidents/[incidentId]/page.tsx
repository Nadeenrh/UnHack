import Link from "next/link";
import { notFound } from "next/navigation";
import { AGENT_LABEL, capitalize, formatDateTime, formatTime } from "@/components/format";
import { ActionPanel } from "@/components/incidents/ActionPanel";
import { DataSourceBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/Badges";
import { Panel } from "@/components/ui/Panel";
import { isProvider, isUuid } from "@/lib/nightwatch/access";
import { placeholders, rows } from "@/lib/nightwatch/db";
import { expireStaleActions, loadIncident } from "@/lib/nightwatch/incidents";
import { canApprove, requirePageOrg } from "@/lib/nightwatch/page-auth";
import { wazuhAgentLink, wazuhHomeLink } from "@/lib/nightwatch/wazuh-link";

const SOURCE_LABEL: Record<string, string> = {
  wazuh: "Wazuh",
  sysmon: "Sysmon",
  windows_security: "Windows security log",
  virustotal: "VirusTotal",
  urlscan: "urlscan",
  pihole: "DNS filter",
  logwatch: "LogWatch",
  agent: "Nightwatch analysis",
};

/** "under a second", "4.2 seconds", "3 minutes". */
function formatCaught(ms: number): string {
  if (ms < 1000) return "under a second";
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} seconds`;
  const min = Math.round(ms / 60_000);
  return `${min} minute${min === 1 ? "" : "s"}`;
}

export default async function IncidentPage({ params }: { params: Promise<{ orgId: string; incidentId: string }> }) {
  const { orgId, incidentId } = await params;
  const { session, access } = await requirePageOrg(orgId);
  if (!isUuid(incidentId)) notFound();
  await expireStaleActions(orgId);
  const incident = await loadIncident(orgId, incidentId);
  if (!incident) notFound();

  // Provider staff get a way into the raw Wazuh view. Clients only ever see the plain-language page.
  const wazuhHome = isProvider(session) ? wazuhHomeLink() : null;
  const wazuhLinks = new Map<string, string>();
  if (wazuhHome && incident.assets.length) {
    const refs = await rows<{ asset_id: string; hostname: string; agent_ref: string | null }>(
      `SELECT asset_id, hostname, agent_ref FROM assets WHERE org_id = ? AND asset_id IN (${placeholders(incident.assets.length)})`,
      [orgId, ...incident.assets.map((a) => a.id)]
    );
    for (const r of refs) {
      const link = wazuhAgentLink(r);
      if (link) wazuhLinks.set(r.asset_id, link);
    }
  }

  // How fast Nightwatch caught it: from the alert firing on the machine (detected_at) to this
  // incident opening (created_at). Fixture data is loaded in bulk, so only live and replayed
  // incidents get a number, and only when the clocks agree (0 to 10 minutes).
  const caughtMs = Date.parse(incident.created_at) - Date.parse(incident.detected_at);
  const caught = incident.data_source !== "fixture" && caughtMs >= 0 && caughtMs <= 600_000 ? formatCaught(caughtMs) : null;

  const approver = canApprove(access);
  const readOnlyReason =
    access.via === "support" ? "You're viewing in support mode. Only the client can approve or deny." : "Only approvers and owners can decide this.";

  return (
    <article>
      <Link href={`/app/${orgId}/incidents`} className="text-sm font-medium text-info hover:underline">
        Back to incidents
      </Link>

      <header className="mt-3 mb-6">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm text-muted">{incident.ref}</span>
          <SeverityBadge severity={incident.severity} />
          <IncidentStatusBadge status={incident.status} />
          <DataSourceBadge source={incident.data_source} />
        </div>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">{incident.title}</h1>
        <p className="mt-1 text-sm text-muted">
          Verdict: {incident.verdict}, {Math.round(incident.confidence * 100)}% confidence. Detected {formatDateTime(incident.detected_at)}
        </p>
        {caught && (
          <p className="mt-3 inline-flex items-center gap-1.5 rounded-md bg-ok-soft px-2.5 py-1 text-sm font-medium text-ok">
            <svg aria-hidden viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M13 3 5 14h6l-1 7 8-11h-6l1-7z" />
            </svg>
            Caught {caught} after the alert fired
          </p>
        )}
      </header>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-6">
          <Panel title="What happened">
            <p className="max-w-prose px-5 py-4 leading-relaxed">{incident.summary}</p>
            {incident.injection_detected && (
              <div className="mx-5 mb-4 rounded-md border border-sev-high/40 bg-sev-high/5 px-4 py-3 text-sm">
                <p className="font-semibold text-sev-high">Someone tried to trick the AI</p>
                <p className="mt-1">
                  {incident.injection_notes ?? "The logs contained text written as instructions to the AI. It was treated as evidence, not as an instruction."}
                </p>
              </div>
            )}
          </Panel>

          <Panel title="Response" tone={incident.actions.some((a) => a.status === "awaiting_approval") ? "lantern" : "default"}>
            <ActionPanel
              orgId={orgId}
              actions={incident.actions}
              incidentStatus={incident.status}
              canApprove={approver}
              readOnlyReason={readOnlyReason}
            />
          </Panel>

          <Panel title="Evidence">
            {incident.evidence.length ? (
              <ol>
                {incident.evidence.map((e) => (
                  <li key={e.id} className="grid gap-1 border-b border-line px-5 py-3 last:border-0 sm:grid-cols-[6.5rem_minmax(0,1fr)]">
                    <time dateTime={e.observed_at} className="text-sm text-muted tabular-nums">
                      {formatTime(e.observed_at)}
                    </time>
                    <div className="min-w-0">
                      <p>{e.claim}</p>
                      <p className="mt-0.5 text-xs text-muted">
                        {SOURCE_LABEL[e.source] ?? e.source}
                        {e.log_ref && (
                          <>
                            , record <span className="font-mono">{e.log_ref}</span>
                          </>
                        )}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="px-5 py-4 text-sm text-muted">No evidence recorded yet.</p>
            )}
          </Panel>
        </div>

        <aside className="min-w-0 space-y-6">
          <Panel title="Machines involved">
            <ul>
              {incident.assets.map((a) => (
                <li key={a.id} className="border-b border-line px-5 py-3 last:border-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="min-w-0 font-mono text-sm font-medium">{a.hostname}</span>
                    {wazuhLinks.has(a.id) && (
                      <a href={wazuhLinks.get(a.id)} target="_blank" rel="noreferrer" className="shrink-0 text-xs font-medium whitespace-nowrap text-info hover:underline">
                        Wazuh events
                      </a>
                    )}
                  </div>
                  <div className="text-xs text-muted">
                    {capitalize(a.kind)}
                    {a.ip && (
                      <>
                        , <span className="font-mono">{a.ip}</span>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>

          {incident.mitre.length > 0 && (
            <Panel title="Attack techniques">
              <ul className="px-5 py-3 text-sm">
                {incident.mitre.map((m) => (
                  <li key={m.technique_id} className="py-1">
                    <a
                      href={`https://attack.mitre.org/techniques/${m.technique_id.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="hover:underline"
                    >
                      <span className="font-mono text-muted">{m.technique_id}</span> {m.name}
                    </a>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {wazuhHome && (
            <Panel title="For the Nightwatch team">
              <p className="px-5 pt-3 text-sm text-muted">The full alert history and raw logs are in Wazuh. The client doesn&apos;t see this panel.</p>
              <div className="px-5 py-3">
                <a
                  href={wazuhHome}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-block rounded-md px-3 py-1.5 text-sm font-medium ring-1 ring-line hover:bg-canvas"
                >
                  Open in Wazuh
                </a>
              </div>
            </Panel>
          )}

          <Panel title="How the AI agents investigated">
            {incident.agent_runs.length ? (
              <ul className="text-sm">
                {incident.agent_runs.map((r) => (
                  <li key={r.id} className="border-b border-line px-5 py-3 last:border-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium">{AGENT_LABEL[r.agent] ?? capitalize(r.agent)}</span>
                      <span className={r.status === "succeeded" ? "text-ok" : r.status === "failed" ? "text-bad" : "text-muted"}>
                        {capitalize(r.status)}
                      </span>
                    </div>
                    {r.output_summary && <p className="mt-0.5 text-muted">{r.output_summary}</p>}
                    {/* Demo data carries a placeholder model name; only show real ones. */}
                    {!r.model?.includes("fixture") && <p className="mt-0.5 text-xs text-muted">{r.model ?? "Rule-based, no AI model"}</p>}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-5 py-3 text-sm text-muted">Investigation hasn&apos;t started yet.</p>
            )}
          </Panel>
        </aside>
      </div>
    </article>
  );
}
