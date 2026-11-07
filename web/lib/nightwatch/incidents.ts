// Builds contract-shaped incidents (contracts/types.ts → Incident) from the database.
// Every query is scoped by org_id from the caller's verified access, never from the request body.

import type {
  Action,
  ActionStatus,
  AgentRun,
  Evidence,
  Incident,
  IncidentAsset,
  IncidentStatus,
  MitreTag,
} from "@/contracts/types";
import { audit } from "./audit";
import { exec, iso, isoRequired, one, placeholders, rows, type Executor } from "./db";

const OPEN: IncidentStatus[] = ["open", "investigating", "awaiting_approval", "contained"];
const CLOSED: IncidentStatus[] = ["resolved", "false_positive"];

interface IncidentRow {
  incident_id: string;
  org_id: string;
  org_name: string;
  ref: string;
  title: string;
  summary: string;
  severity: Incident["severity"];
  verdict: Incident["verdict"];
  confidence: string | number;
  status: IncidentStatus;
  data_source: Incident["data_source"];
  injection_detected: number;
  injection_notes: string | null;
  detected_at: Date;
  created_at: Date;
  updated_at: Date;
}

export interface IncidentQuery {
  ids?: string[];
  status?: "open" | "closed" | "all";
  limit?: number;
}

export async function loadIncidents(orgId: string, q: IncidentQuery = {}): Promise<Incident[]> {
  const where = ["i.org_id = ?"];
  const params: (string | number)[] = [orgId];
  if (q.ids) {
    if (!q.ids.length) return [];
    where.push(`i.incident_id IN (${placeholders(q.ids.length)})`);
    params.push(...q.ids);
  }
  if (q.status === "open" || q.status === "closed") {
    const set = q.status === "open" ? OPEN : CLOSED;
    where.push(`i.status IN (${placeholders(set.length)})`);
    params.push(...set);
  }
  const limit = Math.min(Math.max(Math.trunc(q.limit ?? 50), 1), 200);

  const incidents = await rows<IncidentRow>(
    `SELECT i.*, o.name AS org_name
     FROM incidents i JOIN organizations o ON o.org_id = i.org_id
     WHERE ${where.join(" AND ")}
     ORDER BY i.detected_at DESC
     LIMIT ${limit}`,
    params
  );
  if (!incidents.length) return [];

  const ids = incidents.map((i) => i.incident_id);
  const inIds = placeholders(ids.length);
  const scoped = [orgId, ...ids];

  const [assets, alertIds, mitre, evidence, runs, actions] = await Promise.all([
    rows<{ incident_id: string; asset_id: string; hostname: string; ip: string | null; kind: IncidentAsset["kind"] }>(
      `SELECT ia.incident_id, a.asset_id, a.hostname, a.ip, a.kind
       FROM incident_assets ia JOIN assets a ON a.asset_id = ia.asset_id AND a.org_id = ia.org_id
       WHERE ia.org_id = ? AND ia.incident_id IN (${inIds}) ORDER BY a.hostname`,
      scoped
    ),
    rows<{ incident_id: string; source_alert_id: string }>(
      `SELECT incident_id, source_alert_id FROM alerts
       WHERE org_id = ? AND incident_id IN (${inIds}) ORDER BY observed_at`,
      scoped
    ),
    rows<{ incident_id: string; technique_id: string; technique_name: string }>(
      `SELECT m.incident_id, m.technique_id, m.technique_name
       FROM incident_mitre m JOIN incidents i ON i.incident_id = m.incident_id
       WHERE i.org_id = ? AND m.incident_id IN (${inIds}) ORDER BY m.technique_id`,
      scoped
    ),
    rows<{ incident_id: string; evidence_id: number; claim: string; source: Evidence["source"]; log_ref: string | null; observed_at: Date }>(
      `SELECT incident_id, evidence_id, claim, source, log_ref, observed_at FROM evidence
       WHERE org_id = ? AND incident_id IN (${inIds}) ORDER BY observed_at, evidence_id`,
      scoped
    ),
    rows<{ incident_id: string; run_id: string; agent: AgentRun["agent"]; status: AgentRun["status"]; model: string | null; started_at: Date; finished_at: Date | null; output_summary: string | null }>(
      `SELECT incident_id, run_id, agent, status, model, started_at, finished_at, output_summary FROM agent_runs
       WHERE org_id = ? AND incident_id IN (${inIds}) ORDER BY started_at`,
      scoped
    ),
    rows<ActionRow>(
      `SELECT a.*, u.first_name, u.last_name FROM actions a
       LEFT JOIN users u ON u.user_id = a.decided_by
       WHERE a.org_id = ? AND a.incident_id IN (${inIds}) ORDER BY a.requested_at`,
      scoped
    ),
  ]);

  const by = <T extends { incident_id: string }>(list: T[], id: string) => list.filter((x) => x.incident_id === id);

  return incidents.map<Incident>((i) => ({
    contract_version: "0.1",
    id: i.incident_id,
    ref: i.ref,
    org: { id: i.org_id, name: i.org_name },
    title: i.title,
    summary: i.summary,
    severity: i.severity,
    verdict: i.verdict,
    confidence: Number(i.confidence),
    status: i.status,
    data_source: i.data_source,
    detected_at: isoRequired(i.detected_at),
    created_at: isoRequired(i.created_at),
    updated_at: isoRequired(i.updated_at),
    assets: by(assets, i.incident_id).map((a) => ({ id: a.asset_id, hostname: a.hostname, ip: a.ip, kind: a.kind })),
    source_alert_ids: by(alertIds, i.incident_id).map((a) => a.source_alert_id),
    mitre: by(mitre, i.incident_id).map<MitreTag>((m) => ({ technique_id: m.technique_id, name: m.technique_name })),
    evidence: by(evidence, i.incident_id).map<Evidence>((e) => ({
      id: Number(e.evidence_id),
      claim: e.claim,
      source: e.source,
      log_ref: e.log_ref,
      observed_at: isoRequired(e.observed_at),
    })),
    injection_detected: Boolean(i.injection_detected),
    injection_notes: i.injection_notes,
    agent_runs: by(runs, i.incident_id).map<AgentRun>((r) => ({
      id: r.run_id,
      agent: r.agent,
      status: r.status,
      model: r.model,
      started_at: isoRequired(r.started_at),
      finished_at: iso(r.finished_at),
      output_summary: r.output_summary,
    })),
    actions: by(actions, i.incident_id).map(toContractAction),
  }));
}

export async function loadIncident(orgId: string, incidentId: string): Promise<Incident | null> {
  const [found] = await loadIncidents(orgId, { ids: [incidentId], status: "all", limit: 1 });
  return found ?? null;
}

// ---- actions -----------------------------------------------------------------

export interface ActionRow {
  action_id: string;
  org_id: string;
  incident_id: string;
  type: Action["type"];
  target: string;
  risk: Action["risk"];
  policy_decision: Action["policy_decision"];
  status: ActionStatus;
  rationale: string;
  idempotency_key: string;
  requested_at: Date;
  expires_at: Date | null;
  decided_by: string | null;
  decided_at: Date | null;
  executed_at: Date | null;
  completed_at: Date | null;
  result_verified: number | null;
  result_detail: string | null;
  first_name?: string | null;
  last_name?: string | null;
}

export function toContractAction(a: ActionRow): Action {
  let decided_by: Action["decided_by"] = null;
  if (a.decided_by) {
    decided_by = { user_id: a.decided_by, name: `${a.first_name ?? ""} ${a.last_name ?? ""}`.trim(), kind: "human" };
  } else if (a.decided_at && a.policy_decision === "auto") {
    decided_by = { user_id: null, name: "Policy (automatic)", kind: "policy" };
  }
  return {
    id: a.action_id,
    type: a.type,
    target: a.target,
    risk: a.risk,
    policy_decision: a.policy_decision,
    status: a.status,
    rationale: a.rationale,
    requested_at: isoRequired(a.requested_at),
    decided_by,
    decided_at: iso(a.decided_at),
    result:
      a.completed_at && a.result_detail !== null
        ? { verified: Boolean(a.result_verified), detail: a.result_detail, completed_at: isoRequired(a.completed_at) }
        : null,
  };
}

/**
 * Approval requests that nobody answered within the window become "expired".
 * Runs lazily on reads and before decisions, so no background job is needed.
 */
export async function expireStaleActions(orgId: string): Promise<void> {
  const stale = await rows<{ action_id: string; incident_id: string }>(
    `SELECT action_id, incident_id FROM actions
     WHERE org_id = ? AND status = 'awaiting_approval' AND expires_at IS NOT NULL AND expires_at < NOW(3)`,
    [orgId]
  );
  for (const s of stale) {
    const res = await exec(
      `UPDATE actions SET status = 'expired' WHERE action_id = ? AND org_id = ? AND status = 'awaiting_approval'`,
      [s.action_id, orgId]
    );
    if (res.affectedRows === 1) {
      await audit({
        orgId,
        actorType: "system",
        actorId: "scheduler",
        event: "action_expired",
        incidentId: s.incident_id,
        actionId: s.action_id,
      });
      await refreshIncidentStatus(orgId, s.incident_id);
    }
  }
}

/**
 * Keep the incident's status consistent with its actions:
 * any action waiting on a person → awaiting_approval; when none are left waiting,
 * an incident that was awaiting_approval goes back to investigating. Closed incidents
 * and human-set states (contained/resolved/false_positive) are left alone.
 */
export async function refreshIncidentStatus(orgId: string, incidentId: string, conn?: Executor): Promise<void> {
  const inc = await one<{ status: IncidentStatus }>(
    `SELECT status FROM incidents WHERE incident_id = ? AND org_id = ?`,
    [incidentId, orgId],
    conn
  );
  if (!inc || !["open", "investigating", "awaiting_approval"].includes(inc.status)) return;
  const waiting = await one<{ n: number }>(
    `SELECT COUNT(*) AS n FROM actions WHERE incident_id = ? AND org_id = ? AND status = 'awaiting_approval'`,
    [incidentId, orgId],
    conn
  );
  const next: IncidentStatus = Number(waiting?.n ?? 0) > 0 ? "awaiting_approval" : "investigating";
  if (next !== inc.status) {
    await exec(`UPDATE incidents SET status = ? WHERE incident_id = ? AND org_id = ?`, [next, incidentId, orgId], conn);
  }
}
