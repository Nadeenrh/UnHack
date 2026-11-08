// Turns raw Wazuh alerts into stored alerts and incidents.
//
// Auth: the site's ingest key (Bearer). The key alone decides the org. Nothing in the
// payload can choose or change it.
//
// Flow per alert: dedupe → upsert the machine it came from → store the raw alert →
// if severe enough, attach to an open incident on the same machine (30-minute window)
// or open a new one → investigate after the response is sent.
//
// Every string inside an alert is untrusted (attackers control usernames, file names,
// URLs, command lines). It is stored as data and never interpreted.

import type { EvidenceSource, Severity } from "@/contracts/types";
import { audit } from "./audit";
import { runLater } from "./background";
import { newId, sha256 } from "./crypto";
import { exec, one, tx, type Executor } from "./db";
import { badRequest, unauthorized } from "./http";
import { runInvestigation } from "./investigate";

export const MAX_ALERTS_PER_REQUEST = 500;
const CORRELATION_MINUTES = 30;
const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export function minIncidentLevel(): number {
  const n = Number(process.env.INGEST_MIN_LEVEL ?? 7);
  return Number.isFinite(n) ? n : 7;
}

export function severityForLevel(level: number): Severity {
  if (level >= 12) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  return "low";
}

export interface NormalizedAlert {
  sourceAlertId: string;
  ruleId: string | null;
  level: number;
  description: string;
  mitre: { id: string; name: string }[];
  groups: string[];
  agentRef: string | null;
  hostname: string | null;
  agentIp: string | null;
  observedAt: Date;
  evidenceSource: EvidenceSource;
  raw: Record<string, unknown>;
}

const clip = (v: unknown, n: number): string | null => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);

/** Wazuh writes "+0000"; JavaScript wants "+00:00". */
function parseWazuhTime(v: unknown): Date {
  if (typeof v === "string") {
    const d = new Date(v.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
    if (!Number.isNaN(d.getTime())) return d;
  }
  return new Date();
}

export function normalizeWazuhAlert(raw: unknown): NormalizedAlert | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const a = raw as Record<string, any>;
  const rule = (a.rule ?? {}) as Record<string, any>;
  const agent = (a.agent ?? {}) as Record<string, any>;
  const level = Number(rule.level);
  if (!Number.isFinite(level)) return null;

  const ids: unknown[] = Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const names: unknown[] = Array.isArray(rule.mitre?.technique) ? rule.mitre.technique : [];
  const mitre = ids
    .map((id, i) => ({ id: String(id), name: clip(names[i], 150) ?? String(id) }))
    .filter((m) => /^T\d{4}(\.\d{3})?$/.test(m.id));

  const groups: string[] = Array.isArray(rule.groups) ? rule.groups.map(String) : [];
  const channel = String(a.data?.win?.system?.channel ?? "").toLowerCase();
  const evidenceSource: EvidenceSource = groups.includes("sysmon") || channel.includes("sysmon")
    ? "sysmon"
    : channel === "security"
      ? "windows_security"
      : "wazuh";

  return {
    sourceAlertId: clip(a.id, 128) ?? sha256(JSON.stringify(a)).slice(0, 64),
    ruleId: clip(rule.id != null ? String(rule.id) : null, 32),
    level: Math.max(0, Math.min(16, Math.trunc(level))),
    description: clip(rule.description, 500) ?? "Wazuh alert",
    mitre,
    groups,
    agentRef: clip(agent.id != null ? String(agent.id) : null, 64),
    hostname: clip(agent.name, 255),
    agentIp: clip(agent.ip, 45),
    observedAt: parseWazuhTime(a.timestamp),
    evidenceSource,
    raw: a,
  };
}

/** Configuration-checklist results (Wazuh SCA): useful context, never an incident on their own. */
export function isPostureFinding(alert: Pick<NormalizedAlert, "groups">): boolean {
  return alert.groups.includes("sca");
}

export interface IngestResult {
  received: number;
  stored: number;
  duplicates: number;
  ignored: number;
  incidents: { id: string; ref: string; created: boolean }[];
}

export async function ingestWazuh(ingestKey: string | null, payload: unknown, opts: { replay?: boolean } = {}): Promise<IngestResult> {
  if (!ingestKey) throw unauthorized("Missing ingest key.");
  const site = await one<{ site_id: string; org_id: string }>(
    `SELECT site_id, org_id FROM sites WHERE ingest_key_hash = ? AND revoked_at IS NULL`,
    [sha256(ingestKey)]
  );
  if (!site) throw unauthorized("Invalid ingest key.");

  const list: unknown[] = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object" && Array.isArray((payload as any).alerts)
      ? (payload as any).alerts
      : [payload];
  if (list.length > MAX_ALERTS_PER_REQUEST) throw badRequest(`Send at most ${MAX_ALERTS_PER_REQUEST} alerts per request.`);

  const result: IngestResult = { received: list.length, stored: 0, duplicates: 0, ignored: 0, incidents: [] };
  const touched = new Map<string, { ref: string; created: boolean }>();

  for (const item of list) {
    const alert = normalizeWazuhAlert(item);
    if (!alert) {
      result.ignored++;
      continue;
    }
    const outcome = await tx((conn) => storeAlert(conn, site, alert, Boolean(opts.replay)));
    if (outcome === "duplicate") result.duplicates++;
    else {
      result.stored++;
      if (outcome) {
        const prev = touched.get(outcome.id);
        touched.set(outcome.id, { ref: outcome.ref, created: Boolean(prev?.created || outcome.created) });
      }
    }
  }

  for (const [id, info] of touched) {
    result.incidents.push({ id, ...info });
    runLater(`investigate ${id}`, () => runInvestigation(site.org_id, id));
  }
  return result;
}

async function storeAlert(
  conn: Executor,
  site: { site_id: string; org_id: string },
  alert: NormalizedAlert,
  replay: boolean
): Promise<"duplicate" | null | { id: string; ref: string; created: boolean }> {
  const orgId = site.org_id;

  // The machine it came from. (org_id, hostname) is unique.
  let assetId: string | null = null;
  if (alert.hostname) {
    await exec(
      `INSERT INTO assets (asset_id, org_id, site_id, hostname, ip, agent_ref, agent_status, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, 'online', ?)
       ON DUPLICATE KEY UPDATE
         ip = COALESCE(VALUES(ip), ip),
         agent_ref = COALESCE(VALUES(agent_ref), agent_ref),
         agent_status = 'online',
         last_seen_at = GREATEST(COALESCE(last_seen_at, VALUES(last_seen_at)), VALUES(last_seen_at))`,
      [newId(), orgId, site.site_id, alert.hostname, alert.agentIp, alert.agentRef, alert.observedAt],
      conn
    );
    assetId = (await one<{ asset_id: string }>(
      `SELECT asset_id FROM assets WHERE org_id = ? AND hostname = ?`,
      [orgId, alert.hostname],
      conn
    ))!.asset_id;
  }

  const ins = await exec(
    `INSERT IGNORE INTO alerts
       (org_id, site_id, asset_id, source, source_alert_id, rule_id, rule_level, rule_description, raw, observed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      orgId,
      site.site_id,
      assetId,
      replay ? "replay" : "wazuh",
      alert.sourceAlertId,
      alert.ruleId,
      alert.level,
      alert.description,
      JSON.stringify(alert.raw),
      alert.observedAt,
    ],
    conn
  );
  if (ins.affectedRows === 0) return "duplicate";
  const alertRowId = ins.insertId;

  if (alert.level < minIncidentLevel() || !assetId) return null; // kept as context only
  // Wazuh's configuration checklist (SCA, e.g. "CIS: Ensure AppArmor is installed") rates failed
  // checks at level 7, but they are setup hygiene, not attacks. Every new machine produces dozens,
  // and they would swallow real attacks on the same machine into one incident. Keep them as context.
  if (isPostureFinding(alert)) return null;

  const severity = severityForLevel(alert.level);
  const logRef = `wazuh:${alert.sourceAlertId}`;

  const existing = await one<{ incident_id: string; ref: string; severity: Severity }>(
    `SELECT i.incident_id, i.ref, i.severity
     FROM incidents i JOIN incident_assets ia ON ia.incident_id = i.incident_id AND ia.org_id = i.org_id
     WHERE i.org_id = ? AND ia.asset_id = ?
       AND i.status IN ('open','investigating','awaiting_approval')
       AND i.detected_at BETWEEN ? - INTERVAL ${CORRELATION_MINUTES} MINUTE AND ? + INTERVAL ${CORRELATION_MINUTES} MINUTE
     ORDER BY i.detected_at DESC LIMIT 1`,
    [orgId, assetId, alert.observedAt, alert.observedAt],
    conn
  );

  let incidentId: string;
  let ref: string;
  let created = false;

  if (existing) {
    incidentId = existing.incident_id;
    ref = existing.ref;
    if (RANK[severity] > RANK[existing.severity]) {
      await exec(`UPDATE incidents SET severity = ? WHERE incident_id = ? AND org_id = ?`, [severity, incidentId, orgId], conn);
    }
  } else {
    // Atomic per-org counter → INC-0001, INC-0002, ...
    await exec(`UPDATE organizations SET incident_seq = LAST_INSERT_ID(incident_seq + 1) WHERE org_id = ?`, [orgId], conn);
    const seq = (await one<{ n: number }>(`SELECT LAST_INSERT_ID() AS n`, [], conn))!.n;
    ref = `INC-${String(seq).padStart(4, "0")}`;
    incidentId = newId();
    created = true;
    await exec(
      `INSERT INTO incidents (incident_id, org_id, ref, title, summary, severity, status, data_source, detected_at)
       VALUES (?, ?, ?, ?, ?, ?, 'investigating', ?, ?)`,
      [
        incidentId,
        orgId,
        ref,
        alert.description.slice(0, 200),
        `New alert from ${alert.hostname}: ${alert.description} NightWatch is investigating.`,
        severity,
        replay ? "replay" : "live",
        alert.observedAt,
      ],
      conn
    );
    await exec(`INSERT INTO incident_assets (org_id, incident_id, asset_id) VALUES (?, ?, ?)`, [orgId, incidentId, assetId], conn);
    await audit(
      { orgId, actorType: "system", actorId: "ingest", event: "incident_created", incidentId, details: { ref, rule_id: alert.ruleId, level: alert.level, replay } },
      conn
    );
  }

  await exec(`UPDATE alerts SET incident_id = ? WHERE alert_id = ?`, [incidentId, alertRowId], conn);
  await exec(
    `INSERT INTO evidence (org_id, incident_id, claim, source, log_ref, observed_at) VALUES (?, ?, ?, ?, ?, ?)`,
    [orgId, incidentId, `${alert.description} (rule ${alert.ruleId ?? "?"}, level ${alert.level})`, alert.evidenceSource, logRef, alert.observedAt],
    conn
  );
  for (const m of alert.mitre) {
    await exec(
      `INSERT IGNORE INTO incident_mitre (incident_id, technique_id, technique_name) VALUES (?, ?, ?)`,
      [incidentId, m.id, m.name],
      conn
    );
  }
  return { id: incidentId, ref, created };
}
