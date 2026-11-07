// Append-only audit trail. The database refuses UPDATE/DELETE on audit_log (triggers),
// so this module only ever inserts.

import { exec, type Executor } from "./db";

export type ActorType = "user" | "agent" | "system" | "policy" | "provider_support";

export interface AuditEntry {
  orgId: string | null;
  actorType: ActorType;
  actorId: string | null;
  event: string;
  incidentId?: string | null;
  actionId?: string | null;
  details?: Record<string, unknown> | null;
}

export async function audit(entry: AuditEntry, conn?: Executor): Promise<void> {
  await exec(
    `INSERT INTO audit_log (org_id, actor_type, actor_id, event, incident_id, action_id, details)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      entry.orgId,
      entry.actorType,
      entry.actorId,
      entry.event,
      entry.incidentId ?? null,
      entry.actionId ?? null,
      entry.details ? JSON.stringify(entry.details) : null,
    ],
    conn
  );
}
