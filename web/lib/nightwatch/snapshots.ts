// Per-org status snapshot (contracts/types.ts → ProviderOrgSnapshot).
// The client dashboard shows its own; the provider overview shows one per client.

import type { AuditEvent, MonitoredAsset, OrgHealth, ProviderOrgSnapshot, Severity } from "@/contracts/types";
import { iso, placeholders, rows } from "./db";
import { expireStaleActions } from "./incidents";

const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

interface OrgRow {
  org_id: string;
  name: string;
  slug: string;
  sector: ProviderOrgSnapshot["org"]["sector"];
  plan: ProviderOrgSnapshot["org"]["plan"];
}

export async function listAssets(orgId: string): Promise<MonitoredAsset[]> {
  const found = await rows<{
    asset_id: string;
    hostname: string;
    ip: string | null;
    kind: MonitoredAsset["kind"];
    os: string | null;
    agent_status: MonitoredAsset["agent_status"];
    last_seen_at: Date | null;
  }>(
    `SELECT asset_id, hostname, ip, kind, os, agent_status, last_seen_at
     FROM assets WHERE org_id = ? ORDER BY hostname`,
    [orgId]
  );
  return found.map((a) => ({
    id: a.asset_id,
    hostname: a.hostname,
    ip: a.ip,
    kind: a.kind,
    os: a.os,
    agent_status: a.agent_status,
    last_seen_at: iso(a.last_seen_at),
  }));
}

export async function snapshots(orgIds?: string[]): Promise<ProviderOrgSnapshot[]> {
  if (orgIds && !orgIds.length) return [];
  const orgs = await rows<OrgRow>(
    `SELECT org_id, name, slug, sector, plan FROM organizations
     WHERE status = 'active' ${orgIds ? `AND org_id IN (${placeholders(orgIds.length)})` : ""}
     ORDER BY name`,
    orgIds ?? []
  );

  const out: ProviderOrgSnapshot[] = [];
  for (const org of orgs) {
    await expireStaleActions(org.org_id);

    const incidents = await rows<{
      incident_id: string;
      ref: string;
      title: string;
      severity: Severity;
      status: ProviderOrgSnapshot["recent_incidents"][number]["status"];
      detected_at: Date;
      updated_at: Date;
      data_source: string;
    }>(
      `SELECT incident_id, ref, title, severity, status, detected_at, updated_at, data_source
       FROM incidents WHERE org_id = ? ORDER BY detected_at DESC`,
      [org.org_id]
    );
    const pending = await rows<{ n: number }>(
      `SELECT COUNT(*) AS n FROM actions WHERE org_id = ? AND status = 'awaiting_approval'`,
      [org.org_id]
    );
    const assets = await listAssets(org.org_id);

    const open = incidents.filter((i) => ["open", "investigating", "awaiting_approval", "contained"].includes(i.status));
    const pendingCount = Number(pending[0]?.n ?? 0);
    const worst = open.reduce<Severity | null>((w, i) => (!w || RANK[i.severity] > RANK[w] ? i.severity : w), null);
    const health: OrgHealth = pendingCount > 0 || worst === "critical" ? "attention" : open.length ? "watch" : "healthy";
    const lastActivity = incidents.reduce<Date | null>((m, i) => (!m || i.updated_at > m ? i.updated_at : m), null);
    const sources = new Set(incidents.map((i) => i.data_source));

    out.push({
      org: { id: org.org_id, name: org.name, slug: org.slug, sector: org.sector, plan: org.plan },
      // Label the whole snapshot "fixture" only if every incident is sample data.
      data_source: sources.size === 1 && sources.has("fixture") ? "fixture" : sources.has("replay") && !sources.has("live") ? "replay" : "live",
      health,
      open_incidents: open.length,
      pending_approvals: pendingCount,
      highest_open_severity: worst,
      assets,
      assets_online: assets.filter((a) => a.agent_status === "online").length,
      assets_total: assets.length,
      last_activity_at: iso(lastActivity),
      recent_incidents: incidents.slice(0, 3).map((i) => ({
        id: i.incident_id,
        ref: i.ref,
        title: i.title,
        severity: i.severity,
        status: i.status,
        detected_at: iso(i.detected_at) as string,
      })),
    });
  }
  return out;
}

export async function auditFor(orgId: string, opts: { incidentId?: string; limit?: number } = {}): Promise<AuditEvent[]> {
  const limit = Math.min(Math.max(Math.trunc(opts.limit ?? 100), 1), 500);
  const params: string[] = [orgId];
  let extra = "";
  if (opts.incidentId) {
    extra = "AND incident_id = ?";
    params.push(opts.incidentId);
  }
  const found = await rows<{
    org_id: string | null;
    actor_type: AuditEvent["actor_type"];
    actor_id: string | null;
    event: string;
    incident_id: string | null;
    action_id: string | null;
    details: Record<string, unknown> | string | null;
    created_at: Date;
  }>(
    `SELECT org_id, actor_type, actor_id, event, incident_id, action_id, details, created_at
     FROM audit_log WHERE org_id = ? ${extra} ORDER BY created_at DESC, audit_id DESC LIMIT ${limit}`,
    params
  );
  return found.map((a) => ({
    org_id: a.org_id,
    actor_type: a.actor_type,
    actor_id: a.actor_id,
    event: a.event,
    incident_id: a.incident_id,
    action_id: a.action_id,
    details: typeof a.details === "string" ? JSON.parse(a.details) : a.details,
    created_at: iso(a.created_at) as string,
  }));
}

/** Approvals waiting on a person (for the nav badge). */
export async function pendingApprovals(orgId: string): Promise<number> {
  await expireStaleActions(orgId);
  const r = await rows<{ n: number }>(`SELECT COUNT(*) AS n FROM actions WHERE org_id = ? AND status = 'awaiting_approval'`, [orgId]);
  return Number(r[0]?.n ?? 0);
}

export interface HourBucket {
  /** Start of the hour, ISO. */
  hour: string;
  /** Alerts that became part of an incident. */
  flagged: number;
  /** Everything else Nightwatch saw and logged. */
  routine: number;
}

/** Alerts per hour for the last `hours` hours (oldest first), for the dashboard chart. */
export async function alertsByHour(orgId: string, hours = 24): Promise<HourBucket[]> {
  const data = await rows<{ h: Date; flagged: number; routine: number }>(
    `SELECT TIMESTAMP(DATE(observed_at), MAKETIME(HOUR(observed_at), 0, 0)) AS h,
            SUM(incident_id IS NOT NULL) AS flagged, SUM(incident_id IS NULL) AS routine
       FROM alerts
      WHERE org_id = ? AND observed_at >= UTC_TIMESTAMP() - INTERVAL ? HOUR
      GROUP BY h`,
    [orgId, hours]
  );
  const byHour = new Map(data.map((r) => [new Date(r.h).getTime(), r]));
  const now = new Date();
  now.setUTCMinutes(0, 0, 0);
  const out: HourBucket[] = [];
  for (let i = hours - 1; i >= 0; i--) {
    const t = now.getTime() - i * 3600_000;
    const r = byHour.get(t);
    out.push({ hour: new Date(t).toISOString(), flagged: Number(r?.flagged ?? 0), routine: Number(r?.routine ?? 0) });
  }
  return out;
}
