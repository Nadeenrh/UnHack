import Link from "next/link";
import { formatDateTime } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { rows } from "@/lib/nightwatch/db";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";
import { auditFor } from "@/lib/nightwatch/snapshots";

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
  const events = await auditFor(orgId, { limit: 200 });

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
      <PageHeader title="Activity log" subtitle="Everything people, policy and the AI did, newest first. Entries can't be edited or deleted." />
      <Panel>
        {events.length ? (
          <ol>
            {events.map((e, idx) => {
              const who =
                (e.actor_id && nameOf.get(e.actor_id)) ?? (e.actor_type === "agent" && e.actor_id ? `AI ${e.actor_id}` : ACTOR[e.actor_type]);
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
