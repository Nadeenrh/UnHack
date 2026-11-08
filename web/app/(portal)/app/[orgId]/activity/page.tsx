import Link from "next/link";
import { AGENT_LABEL, formatDateTime, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { iso, one, rows } from "@/lib/nightwatch/db";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";
import { alertsByHour, auditFor, pendingApprovals } from "@/lib/nightwatch/snapshots";

export const metadata = { title: "Activity log" };

// Plain-language names for audit events. Unknown events fall back to their raw name.
const EVENT: Record<string, string> = {
  incident_created: "Incident opened",
  incident_contained: "Incident contained",
  agent_run_completed: "AI investigation step finished",
  investigation_completed: "Investigation finished",
  investigation_skipped: "AI investigation skipped",
  investigation_failed: "AI investigation failed",
  recommendation_rejected: "Unsafe recommendation refused",
  action_proposed: "Response proposed",
  action_auto_approved: "Response approved automatically by policy",
  action_approved: "Response approved",
  action_denied: "Response denied",
  action_expired: "Response expired without a decision",
  action_execution_started: "Response started",
  action_succeeded: "Response finished",
  action_failed: "Response failed",
  policy_changed: "Policy changed",
  ingest_key_rotated: "Ingest key replaced",
  organization_created: "Organization created",
  support_session_started: "Nightwatch support opened your workspace",
  support_session_ended: "Nightwatch support closed your workspace",
};

const ACTOR: Record<string, string> = {
  user: "Person",
  agent: "AI agent",
  system: "Nightwatch",
  policy: "Policy",
  provider_support: "Nightwatch support",
};

export default async function ActivityPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  await requirePageOrg(orgId);
  const [events, summary] = await Promise.all([auditFor(orgId, { limit: 200 }), lastDay(orgId)]);

  // Names for people and incident numbers, so the log reads like a log, not a list of ids.
  const userIds = [...new Set(events.filter((e) => e.actor_type === "user" || e.actor_type === "provider_support").map((e) => e.actor_id!))];
  const incidentIds = [...new Set(events.map((e) => e.incident_id).filter(Boolean))] as string[];
  const [people, incidents] = await Promise.all([
    userIds.length
      ? rows<{ user_id: string; name: string }>(
          `SELECT user_id, CONCAT(first_name, ' ', last_name) AS name FROM users WHERE user_id IN (${userIds.map(() => "?").join(",")})`,
          userIds
        )
      : [],
    incidentIds.length
      ? rows<{ incident_id: string; ref: string }>(
          `SELECT incident_id, ref FROM incidents WHERE org_id = ? AND incident_id IN (${incidentIds.map(() => "?").join(",")})`,
          [orgId, ...incidentIds]
        )
      : [],
  ]);
  const nameOf = new Map(people.map((p) => [p.user_id, p.name]));
  const refOf = new Map(incidents.map((i) => [i.incident_id, i.ref]));

  return (
    <>
      <PageHeader title="Activity log" subtitle="What the AI agents saw and did on your network, and every decision since. Entries can't be edited or deleted." />
      <AiSummary orgId={orgId} s={summary} />
      <Panel title="Full log">
        {events.length ? (
          <ol>
            {events.map((e, idx) => {
              const who =
                (e.actor_id && nameOf.get(e.actor_id)) ?? (e.actor_type === "agent" && e.actor_id ? (AGENT_LABEL[e.actor_id] ?? `AI ${e.actor_id}`) : ACTOR[e.actor_type]);
              const detail =
                e.event === "support_session_started" && typeof e.details?.reason === "string"
                  ? `Reason: ${e.details.reason}`
                  : e.event === "recommendation_rejected" && typeof e.details?.reason === "string"
                    ? `${String(e.details.type)} ${String(e.details.target)}: ${e.details.reason}`
                    : e.event === "action_denied" && typeof e.details?.reason === "string"
                      ? `Reason: ${e.details.reason}`
                      : e.event === "policy_changed"
                        ? `${String(e.details?.action_type)}: ${String(e.details?.from)} to ${String(e.details?.to)}`
                        : null;
              return (
                <li key={idx} className="grid gap-1 border-b border-line px-5 py-3 last:border-0 sm:grid-cols-[9rem_1fr_auto]">
                  <time dateTime={e.created_at} className="text-sm text-muted tabular-nums">
                    {formatDateTime(e.created_at)}
                  </time>
                  <div>
                    <p className={e.actor_type === "provider_support" ? "font-semibold" : undefined}>{EVENT[e.event] ?? e.event}</p>
                    {detail && <p className="text-sm text-muted">{detail}</p>}
                  </div>
                  <div className="text-sm sm:text-right">
                    <span className="text-muted">{who}</span>
                    {e.incident_id && refOf.get(e.incident_id) && (
                      <Link href={`/app/${orgId}/incidents/${e.incident_id}`} className="ml-2 font-medium text-info hover:underline">
                        {refOf.get(e.incident_id)}
                      </Link>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        ) : (
          <EmptyState title="No activity yet" />
        )}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------------------
// Last 24 hours, in plain words: the transparency view of what the AI agents are doing.
// ---------------------------------------------------------------------------

interface DaySummary {
  seen: number;
  flagged: number;
  machines: number;
  incidents: number;
  investigated: number;
  responses: number;
  tricks: number;
  waiting: number;
  notes: { agent: string; summary: string; at: string | null; ref: string; incidentId: string }[];
}

async function lastDay(orgId: string): Promise<DaySummary> {
  const since = "UTC_TIMESTAMP(3) - INTERVAL 24 HOUR";
  const [hours, counts, waiting, notes] = await Promise.all([
    alertsByHour(orgId, 24),
    one<{ machines: number; incidents: number; investigated: number; responses: number; tricks: number }>(
      `SELECT (SELECT COUNT(*) FROM assets WHERE org_id = ?) AS machines,
              (SELECT COUNT(*) FROM incidents WHERE org_id = ? AND detected_at >= ${since}) AS incidents,
              (SELECT COUNT(DISTINCT incident_id) FROM agent_runs WHERE org_id = ? AND status = 'succeeded' AND finished_at >= ${since}) AS investigated,
              (SELECT COUNT(*) FROM actions WHERE org_id = ? AND status = 'succeeded' AND completed_at >= ${since}) AS responses,
              (SELECT COUNT(*) FROM incidents WHERE org_id = ? AND injection_detected AND detected_at >= ${since}) AS tricks`,
      [orgId, orgId, orgId, orgId, orgId]
    ),
    pendingApprovals(orgId),
    rows<{ agent: string; output_summary: string; finished_at: Date | null; ref: string; incident_id: string }>(
      `SELECT r.agent, r.output_summary, r.finished_at, i.ref, i.incident_id
         FROM agent_runs r JOIN incidents i ON i.incident_id = r.incident_id AND i.org_id = r.org_id
        WHERE r.org_id = ? AND r.status = 'succeeded' AND r.output_summary IS NOT NULL
        ORDER BY r.finished_at DESC LIMIT 6`,
      [orgId]
    ),
  ]);
  return {
    seen: hours.reduce((n, h) => n + h.flagged + h.routine, 0),
    flagged: hours.reduce((n, h) => n + h.flagged, 0),
    machines: Number(counts?.machines ?? 0),
    incidents: Number(counts?.incidents ?? 0),
    investigated: Number(counts?.investigated ?? 0),
    responses: Number(counts?.responses ?? 0),
    tricks: Number(counts?.tricks ?? 0),
    waiting,
    notes: notes.map((n) => ({ agent: n.agent, summary: n.output_summary, at: iso(n.finished_at), ref: n.ref, incidentId: n.incident_id })),
  };
}

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

function AiSummary({ orgId, s }: { orgId: string; s: DaySummary }) {
  const sentence =
    s.seen === 0
      ? "No events from your machines in the last 24 hours. If that's unexpected, check the Machines page."
      : `Nightwatch watched ${plural(s.seen, "event", "events")} from ${plural(s.machines, "machine", "machines")}. ` +
        `${s.flagged ? `${s.flagged} needed a closer look` : "None needed a closer look"}` +
        `${s.incidents ? `, and the AI agents opened ${plural(s.incidents, "incident", "incidents")}` : ""}. ` +
        (s.waiting ? `${plural(s.waiting, "decision is", "decisions are")} waiting for you.` : "Nothing is waiting on you.");

  const stats: [number, string][] = [
    [s.seen, "Events watched"],
    [s.flagged, "Looked at closer"],
    [s.investigated, "Investigated by AI"],
    [s.responses, "Responses carried out"],
    [s.tricks, "Tricks on the AI caught"],
  ];

  return (
    <div className="mb-6 grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <section className="rounded-lg border border-line bg-panel">
        <header className="border-b border-line px-5 py-3">
          <h2 className="text-base font-semibold">Last 24 hours, in plain words</h2>
        </header>
        <p className="px-5 pt-4 leading-relaxed">{sentence}</p>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 px-5 py-4 sm:grid-cols-3">
          {stats.map(([n, label]) => (
            <div key={label}>
              <dd className="text-2xl font-semibold tabular-nums">{n}</dd>
              <dt className="text-xs text-muted">{label}</dt>
            </div>
          ))}
        </dl>
      </section>

      <section className="rounded-lg border border-line bg-panel">
        <header className="border-b border-line px-5 py-3">
          <h2 className="text-base font-semibold">What the AI agents noticed</h2>
        </header>
        {s.notes.length ? (
          <ul>
            {s.notes.map((n, i) => (
              <li key={i} className="border-b border-line px-5 py-3 last:border-0">
                <div className="flex items-baseline justify-between gap-3 text-xs text-muted">
                  <span className="font-semibold text-info">{AGENT_LABEL[n.agent] ?? n.agent}</span>
                  <span>
                    <Link href={`/app/${orgId}/incidents/${n.incidentId}`} className="font-medium text-info hover:underline">
                      {n.ref}
                    </Link>
                    {n.at && <>, {timeAgo(n.at)}</>}
                  </span>
                </div>
                <p className="mt-1 text-sm">{n.summary}</p>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="Nothing to report yet">When the agents investigate something, their notes appear here.</EmptyState>
        )}
      </section>
    </div>
  );
}
