// Platform side of the agent-service contract (contracts/investigation.schema.json).
//
// The agent service (Python, stateless, separate owner) receives the incident's raw alerts and
// returns a verdict, evidence and RECOMMENDED actions. This module:
//   1. builds and sends the request,
//   2. validates the reply against the JSON Schema,
//   3. re-checks every recommended action against this org's real assets and safety rules,
//   4. lets policy (not the AI) decide auto / ask / never,
//   5. records everything and starts any automatic low-risk actions.
//
// The agent's output is derived from attacker-controlled logs, so it is treated as untrusted
// input too: a recommendation to block the client's own server, or to isolate a machine that
// isn't part of this incident, is rejected and written to the audit log.

import { isIP } from "node:net";
import type { ActionType, InvestigationRequest, InvestigationResult } from "@/contracts/types";
import { audit } from "./audit";
import { runLater } from "./background";
import { validateInvestigationRequest, validateInvestigationResult } from "./contracts";
import { newId, sha256 } from "./crypto";
import { DEMO, scriptedInvestigation } from "./demo";
import { exec, one, rows, tx, type Executor } from "./db";
import { executeAction } from "./executor";
import { refreshIncidentStatus } from "./incidents";
import { APPROVAL_WINDOW_MINUTES, decide } from "./policy";

const running = new Map<string, boolean>(); // incidentId -> rerun requested

/** Investigate an incident; if new alerts arrive mid-run, run once more afterwards. */
export async function runInvestigation(orgId: string, incidentId: string): Promise<void> {
  if (running.has(incidentId)) {
    running.set(incidentId, true);
    return;
  }
  running.set(incidentId, false);
  try {
    do {
      running.set(incidentId, false);
      await investigateOnce(orgId, incidentId);
    } while (running.get(incidentId));
  } finally {
    running.delete(incidentId);
  }
}

export async function buildInvestigationRequest(orgId: string, incidentId: string): Promise<InvestigationRequest | null> {
  const inc = await one<{ org_name: string }>(
    `SELECT o.name AS org_name FROM incidents i JOIN organizations o ON o.org_id = i.org_id
     WHERE i.incident_id = ? AND i.org_id = ?`,
    [incidentId, orgId]
  );
  if (!inc) return null;
  const own = await rows<{ raw: unknown; asset_id: string | null; observed_at: Date }>(
    `SELECT raw, asset_id, observed_at FROM alerts WHERE org_id = ? AND incident_id = ? ORDER BY observed_at LIMIT 100`,
    [orgId, incidentId]
  );
  if (!own.length) return null;
  const parse = (r: unknown) => (typeof r === "string" ? JSON.parse(r) : r) as Record<string, unknown>;

  // Lower-severity events from the same machines around the same time give the agents context.
  const assetIds = [...new Set(own.map((a) => a.asset_id).filter(Boolean))] as string[];
  let context: { raw: unknown }[] = [];
  if (assetIds.length) {
    const first = own[0].observed_at;
    context = await rows<{ raw: unknown }>(
      `SELECT raw FROM alerts
       WHERE org_id = ? AND incident_id IS NULL AND asset_id IN (${assetIds.map(() => "?").join(", ")})
         AND observed_at BETWEEN ? - INTERVAL 30 MINUTE AND ? + INTERVAL 30 MINUTE
       ORDER BY observed_at LIMIT 50`,
      [orgId, ...assetIds, first, first]
    );
  }
  return {
    contract_version: "0.1",
    incident_id: incidentId,
    org_name: inc.org_name,
    alert: parse(own[0].raw),
    related_events: [...own.slice(1), ...context].map((r) => parse(r.raw)),
  };
}

async function investigateOnce(orgId: string, incidentId: string): Promise<void> {
  const request = await buildInvestigationRequest(orgId, incidentId);
  if (!request) return;
  const check = validateInvestigationRequest(request);
  if (!check.ok) throw new Error(`built an invalid investigation request: ${check.error}`);

  const url = process.env.AGENT_SERVICE_URL;
  if (!url && DEMO) {
    // Demo mode: scripted agents built from this incident's own alerts, then the normal path
    // (contract validation, safety re-checks, policy) exactly as for a real agent reply.
    const scripted = validateInvestigationResult(await scriptedInvestigation(request));
    if (!scripted.ok) {
      await recordProblem(orgId, incidentId, "failed", `Scripted investigation didn't match the contract: ${scripted.error}`.slice(0, 1000));
      return;
    }
    await applyInvestigation(orgId, incidentId, scripted.value);
    return;
  }
  if (!url) {
    await recordProblem(orgId, incidentId, "skipped", "Agent service not configured (AGENT_SERVICE_URL), so no AI investigation ran.");
    return;
  }

  let reply: unknown;
  try {
    const res = await fetch(new URL("/investigate", url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(process.env.AGENT_SERVICE_KEY ? { "x-nightwatch-service-key": process.env.AGENT_SERVICE_KEY } : {}),
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(Number(process.env.AGENT_SERVICE_TIMEOUT_MS ?? 90000)),
    });
    if (!res.ok) throw new Error(`agent service answered HTTP ${res.status}`);
    reply = await res.json();
  } catch (err) {
    await recordProblem(orgId, incidentId, "failed", `Agent service unavailable: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  const valid = validateInvestigationResult(reply);
  if (!valid.ok) {
    await recordProblem(orgId, incidentId, "failed", `Agent service reply didn't match the contract: ${valid.error}`.slice(0, 1000));
    return;
  }
  await applyInvestigation(orgId, incidentId, valid.value);
}

async function recordProblem(orgId: string, incidentId: string, status: "skipped" | "failed", message: string): Promise<void> {
  // Alerts often arrive one at a time; don't log "skipped" again for every one of them.
  if (status === "skipped") {
    const last = await one<{ status: string; output_summary: string | null }>(
      `SELECT status, output_summary FROM agent_runs WHERE org_id = ? AND incident_id = ? ORDER BY started_at DESC LIMIT 1`,
      [orgId, incidentId]
    );
    if (last?.status === "skipped" && last.output_summary === message.slice(0, 1000)) return;
  }
  await exec(
    `INSERT INTO agent_runs (run_id, org_id, incident_id, agent, status, model, finished_at, output_summary, error)
     VALUES (?, ?, ?, 'investigator', ?, NULL, NOW(3), ?, ?)`,
    [newId(), orgId, incidentId, status, message.slice(0, 1000), status === "failed" ? message.slice(0, 2000) : null]
  );
  await audit({
    orgId,
    actorType: "system",
    actorId: "investigator",
    event: status === "skipped" ? "investigation_skipped" : "investigation_failed",
    incidentId,
    details: { message: message.slice(0, 500) },
  });
}

// ---- applying a result -----------------------------------------------------------

const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const SHA256 = /^(sha256:)?([a-f0-9]{64})$/i;
const ACCOUNT = /^[A-Za-z0-9._\\@-]{1,64}$/;

function protectedIps(): Set<string> {
  return new Set((process.env.NIGHTWATCH_PROTECTED_IPS ?? "").split(",").map((s) => s.trim()).filter(Boolean));
}

/**
 * Check one recommended action against reality. Returns the normalised target, or a reason
 * it's refused. Recommendations come from agents reading attacker-controlled text.
 */
export async function vetRecommendation(
  orgId: string,
  incidentId: string,
  type: ActionType,
  rawTarget: string,
  conn?: Executor
): Promise<{ ok: true; target: string } | { ok: false; reason: string }> {
  const target = rawTarget.trim();
  switch (type) {
    case "block_ip": {
      if (!isIP(target)) return { ok: false, reason: "not an IP address" };
      if (/^(127\.|0\.|255\.|22[4-9]\.|23\d\.)/.test(target) || target === "::1" || target === "::") {
        return { ok: false, reason: "loopback, broadcast or multicast address" };
      }
      if (protectedIps().has(target)) return { ok: false, reason: "address is on the protected list" };
      const own = await one(`SELECT 1 FROM assets WHERE org_id = ? AND ip = ? LIMIT 1`, [orgId, target], conn);
      if (own) return { ok: false, reason: "address belongs to one of this organization's own machines" };
      return { ok: true, target };
    }
    case "block_domain":
      return DOMAIN.test(target) ? { ok: true, target: target.toLowerCase() } : { ok: false, reason: "not a domain name" };
    case "isolate_host": {
      const host = await one<{ hostname: string }>(
        `SELECT a.hostname FROM incident_assets ia JOIN assets a ON a.asset_id = ia.asset_id AND a.org_id = ia.org_id
         WHERE ia.org_id = ? AND ia.incident_id = ? AND LOWER(a.hostname) = LOWER(?)`,
        [orgId, incidentId, target],
        conn
      );
      return host ? { ok: true, target: host.hostname } : { ok: false, reason: "machine is not part of this incident" };
    }
    case "quarantine_file": {
      const m = SHA256.exec(target);
      return m ? { ok: true, target: `sha256:${m[2].toLowerCase()}` } : { ok: false, reason: "not a SHA-256 file hash" };
    }
    case "disable_account":
      return ACCOUNT.test(target) ? { ok: true, target } : { ok: false, reason: "not a valid account name" };
    case "notify_only":
      return target.length <= 255 ? { ok: true, target } : { ok: false, reason: "too long" };
  }
}

export async function applyInvestigation(orgId: string, incidentId: string, result: InvestigationResult): Promise<void> {
  if (result.incident_id !== incidentId) {
    await recordProblem(orgId, incidentId, "failed", "Agent service returned a result for a different incident.");
    return;
  }

  const autoRun: string[] = [];
  await tx(async (conn) => {
    const updated = await exec(
      `UPDATE incidents
       SET title = ?, summary = ?, severity = ?, verdict = ?, confidence = ?,
           injection_detected = (injection_detected OR ?), injection_notes = COALESCE(?, injection_notes)
       WHERE incident_id = ? AND org_id = ? AND status IN ('open','investigating','awaiting_approval')`,
      [
        result.title.slice(0, 200),
        result.summary,
        result.severity,
        result.verdict,
        result.confidence,
        result.injection_detected,
        result.injection_notes,
        incidentId,
        orgId,
      ],
      conn
    );
    if (updated.affectedRows === 0) return; // closed or not ours: don't touch it

    for (const e of result.evidence) {
      await exec(
        `INSERT INTO evidence (org_id, incident_id, claim, source, log_ref, observed_at) VALUES (?, ?, ?, ?, ?, ?)`,
        [orgId, incidentId, e.claim, e.source, e.log_ref?.slice(0, 255) ?? null, new Date(e.observed_at)],
        conn
      );
    }
    for (const m of result.mitre) {
      await exec(
        `INSERT IGNORE INTO incident_mitre (incident_id, technique_id, technique_name) VALUES (?, ?, ?)`,
        [incidentId, m.technique_id, m.name.slice(0, 150)],
        conn
      );
    }
    for (const r of result.agent_runs) {
      await exec(
        `INSERT INTO agent_runs (run_id, org_id, incident_id, agent, status, model, started_at, finished_at, output_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [newId(), orgId, incidentId, r.agent, r.status, r.model, new Date(r.started_at), new Date(r.finished_at), r.output_summary],
        conn
      );
    }

    for (const rec of result.recommended_actions) {
      const vetted = await vetRecommendation(orgId, incidentId, rec.type, rec.target, conn);
      if (!vetted.ok) {
        await audit(
          { orgId, actorType: "system", actorId: "policy-engine", event: "recommendation_rejected", incidentId, details: { type: rec.type, target: rec.target.slice(0, 255), reason: vetted.reason } },
          conn
        );
        continue;
      }
      const { risk, mode } = await decide(orgId, rec.type, conn);
      const status = mode === "auto" ? "approved" : mode === "ask" ? "awaiting_approval" : "proposed";
      const actionId = newId();
      const ins = await exec(
        `INSERT IGNORE INTO actions
           (action_id, org_id, incident_id, type, target, risk, policy_decision, status, rationale, idempotency_key,
            expires_at, decided_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                 ${mode === "ask" ? `NOW(3) + INTERVAL ${APPROVAL_WINDOW_MINUTES} MINUTE` : "NULL"},
                 ${mode === "auto" ? "NOW(3)" : "NULL"})`,
        [actionId, orgId, incidentId, rec.type, vetted.target, risk, mode, status, rec.rationale, sha256(`${orgId}|${incidentId}|${rec.type}|${vetted.target}`)],
        conn
      );
      if (ins.affectedRows === 0) continue; // already proposed earlier for this incident
      await audit(
        { orgId, actorType: "policy", actorId: "policy-engine", event: "action_proposed", incidentId, actionId, details: { type: rec.type, target: vetted.target, risk, policy_decision: mode } },
        conn
      );
      if (mode === "auto") {
        await audit({ orgId, actorType: "policy", actorId: "policy-engine", event: "action_auto_approved", incidentId, actionId }, conn);
        autoRun.push(actionId);
      }
    }

    await audit(
      { orgId, actorType: "agent", actorId: "agent-service", event: "investigation_completed", incidentId, details: { verdict: result.verdict, confidence: result.confidence, injection_detected: result.injection_detected } },
      conn
    );
    await refreshIncidentStatus(orgId, incidentId, conn);
  });

  for (const actionId of autoRun) runLater(`execute ${actionId}`, () => executeAction(orgId, actionId));
}
