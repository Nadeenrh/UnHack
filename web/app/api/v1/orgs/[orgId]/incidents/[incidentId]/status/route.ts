import type { IncidentStatus } from "@/contracts/types";
import { isUuid, requireOrgAccess } from "@/lib/nightwatch/access";
import { audit } from "@/lib/nightwatch/audit";
import { one, tx } from "@/lib/nightwatch/db";
import { badRequest, conflict, notFound, readJson } from "@/lib/nightwatch/http";
import { loadIncident } from "@/lib/nightwatch/incidents";
import { authed } from "@/lib/nightwatch/route";

const CLOSE: IncidentStatus[] = ["resolved", "false_positive"];

// POST /api/v1/orgs/:orgId/incidents/:incidentId/status   { status: "resolved" | "false_positive" | "reopen", note? }
// Approvers and owners close or reopen an incident. A person always makes this call, never the AI,
// and it is written to the activity log. Returns the updated Incident.
export const POST = authed<{ orgId: string; incidentId: string }>(async (req, { orgId, incidentId }, session) => {
  const access = await requireOrgAccess(session, orgId, "approve");
  if (!isUuid(incidentId)) throw notFound("Incident not found.");
  const body = await readJson<{ status?: unknown; note?: unknown }>(req);
  const wanted = body.status;
  if (wanted !== "reopen" && !CLOSE.includes(wanted as IncidentStatus)) throw badRequest("status must be resolved, false_positive or reopen.");
  const note = typeof body.note === "string" && body.note.trim() ? body.note.trim().slice(0, 500) : null;

  await tx(async (conn) => {
    const inc = await one<{ status: IncidentStatus }>(
      `SELECT status FROM incidents WHERE incident_id = ? AND org_id = ? FOR UPDATE`,
      [incidentId, access.orgId],
      conn
    );
    if (!inc) throw notFound("Incident not found.");
    const closed = CLOSE.includes(inc.status);

    if (wanted === "reopen") {
      if (!closed) throw conflict("This incident is already open.");
      await conn.execute(`UPDATE incidents SET status = 'investigating' WHERE incident_id = ? AND org_id = ?`, [incidentId, access.orgId]);
      await audit({ orgId: access.orgId, actorType: "user", actorId: session.userId, event: "incident_reopened", incidentId, details: { from: inc.status, note } }, conn);
      return;
    }

    if (closed) throw conflict("This incident is already closed.");
    const busy = await one<{ n: number }>(
      `SELECT COUNT(*) AS n FROM actions WHERE incident_id = ? AND org_id = ? AND status IN ('awaiting_approval','approved','executing')`,
      [incidentId, access.orgId],
      conn
    );
    if (Number(busy?.n ?? 0) > 0) throw conflict("A response is still waiting or running. Decide it first, then close the incident.");
    await conn.execute(`UPDATE incidents SET status = ? WHERE incident_id = ? AND org_id = ?`, [wanted as string, incidentId, access.orgId]);
    await audit(
      { orgId: access.orgId, actorType: "user", actorId: session.userId, event: wanted === "resolved" ? "incident_resolved" : "incident_false_positive", incidentId, details: { from: inc.status, note } },
      conn
    );
  });

  return loadIncident(access.orgId, incidentId);
});
