// Nightwatch contract v0.1 — TypeScript mirror of contracts/*.schema.json.
// If you change a type here, change the JSON Schema too (and vice versa).
// The agents layer depends on these. Change them through a PR.

export type Uuid = string;
export type Timestamp = string; // ISO 8601, UTC

export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "malicious" | "suspicious" | "benign" | "undetermined";

export type IncidentStatus =
  | "open"
  | "investigating"
  | "awaiting_approval"
  | "contained"
  | "resolved"
  | "false_positive";

/** Anything that is not "live" must be visibly labelled in the UI. */
export type DataSource = "live" | "replay" | "fixture";

export type EvidenceSource =
  | "wazuh"
  | "sysmon"
  | "windows_security"
  | "virustotal"
  | "urlscan"
  | "pihole"
  | "logwatch"
  | "agent";

export type ActionType =
  | "block_ip"
  | "block_domain"
  | "isolate_host"
  | "quarantine_file"
  | "disable_account"
  | "notify_only";

export type ActionRisk = "low" | "high" | "critical";
export type PolicyMode = "auto" | "ask" | "never";

/**
 * Action lifecycle. Each is a distinct UI state:
 *   proposed          agents recommended it; policy says a human must do it themselves ("never")
 *   awaiting_approval policy says "ask"; waiting on an approver
 *   approved          approved, not yet started
 *   executing         executor is running it
 *   succeeded         done (check result.verified)
 *   failed            tried and failed (result.detail says why)
 *   denied            a human said no
 *   expired           nobody decided in time
 */
export type ActionStatus =
  | "proposed"
  | "awaiting_approval"
  | "approved"
  | "executing"
  | "succeeded"
  | "failed"
  | "denied"
  | "expired";

export interface OrgRef {
  id: Uuid;
  name: string;
}

export interface IncidentAsset {
  id: Uuid;
  hostname: string;
  ip: string | null;
  kind: "endpoint" | "server" | "network" | "other";
}

export interface MitreTag {
  technique_id: string; // e.g. "T1110" or "T1059.001"
  name: string;
}

export interface Evidence {
  id: number;
  claim: string;
  source: EvidenceSource;
  log_ref: string | null;
  observed_at: Timestamp;
}

export interface AgentRun {
  id: Uuid;
  agent: "triage" | "intel" | "investigator";
  status: "running" | "succeeded" | "failed" | "skipped";
  model: string | null; // null = rule-based fallback
  started_at: Timestamp;
  finished_at: Timestamp | null;
  output_summary: string | null;
}

export interface ActionDecider {
  user_id: Uuid | null;
  name: string;
  kind: "human" | "policy";
}

export interface ActionResult {
  verified: boolean; // true only when the platform confirmed the effect
  detail: string;
  completed_at: Timestamp;
}

export interface Action {
  id: Uuid;
  type: ActionType;
  target: string;
  risk: ActionRisk; // set by server policy, never by an agent
  policy_decision: PolicyMode; // set by server policy, never by an agent
  status: ActionStatus;
  rationale: string;
  requested_at: Timestamp;
  decided_by: ActionDecider | null;
  decided_at: Timestamp | null;
  result: ActionResult | null;
}

export interface Incident {
  contract_version: "0.1";
  id: Uuid;
  ref: string; // "INC-0001", unique per org
  org: OrgRef;
  title: string;
  summary: string;
  severity: Severity;
  verdict: Verdict;
  confidence: number; // 0..1
  status: IncidentStatus;
  data_source: DataSource;
  detected_at: Timestamp;
  created_at: Timestamp;
  updated_at: Timestamp;
  assets: IncidentAsset[];
  source_alert_ids: string[];
  mitre: MitreTag[];
  evidence: Evidence[];
  injection_detected: boolean;
  injection_notes: string | null;
  agent_runs: AgentRun[];
  actions: Action[];
}

// ---- Provider portal: one snapshot per client org ----

export type OrgHealth = "attention" | "watch" | "healthy";
export type OrgSector = "small_business" | "healthcare" | "community_org" | "municipality" | "utility" | "other";

export interface MonitoredAsset extends IncidentAsset {
  os: string | null;
  agent_status: "online" | "offline" | "never_connected";
  last_seen_at: Timestamp | null;
}

export interface ProviderOrgSnapshot {
  org: OrgRef & { slug: string; sector: OrgSector; plan: "pilot" | "standard" | "plus" };
  data_source: DataSource;
  /** attention = pending approval or critical open incident; watch = open incidents; healthy = none */
  health: OrgHealth;
  open_incidents: number;
  pending_approvals: number;
  highest_open_severity: Severity | null;
  assets: MonitoredAsset[];
  assets_online: number;
  assets_total: number;
  last_activity_at: Timestamp | null;
  recent_incidents: Pick<Incident, "id" | "ref" | "title" | "severity" | "status" | "detected_at">[];
}

// ---- Audit log ----

export interface AuditEvent {
  org_id: Uuid | null;
  actor_type: "user" | "agent" | "system" | "policy" | "provider_support";
  actor_id: string | null;
  event: string; // e.g. incident_created, action_approved, support_session_started
  incident_id: Uuid | null;
  action_id: Uuid | null;
  details: Record<string, unknown> | null;
  created_at: Timestamp;
}

// ---- Agent service boundary (contracts/investigation.schema.json) ----

export interface InvestigationRequest {
  contract_version: "0.1";
  incident_id: string;
  org_name: string;
  alert: Record<string, unknown>; // untrusted
  related_events: Record<string, unknown>[]; // untrusted
}

export interface RecommendedAction {
  type: ActionType;
  target: string;
  rationale: string;
}

export interface InvestigationResult {
  contract_version: "0.1";
  incident_id: string;
  title: string;
  summary: string;
  severity: Severity;
  verdict: Verdict;
  confidence: number;
  mitre: MitreTag[];
  evidence: Omit<Evidence, "id">[];
  injection_detected: boolean;
  injection_notes: string | null;
  recommended_actions: RecommendedAction[];
  agent_runs: (Omit<AgentRun, "id" | "status" | "finished_at"> & {
    status: "succeeded" | "failed" | "skipped";
    finished_at: Timestamp;
  })[];
}
