import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { settleBackground } from "@/lib/nightwatch/background";
import { exec, one, rows } from "@/lib/nightwatch/db";
import { executeAction } from "@/lib/nightwatch/executor";
import { wazuhExecutor } from "@/lib/nightwatch/executor/wazuh";
import type { ActionRow } from "@/lib/nightwatch/incidents";
import { body, ctx, enabled, req, resetDatabase, signIn, teardown } from "./harness";

process.env.EXECUTOR_SIMULATE_DELAY_MS = "0";

let mc = "";
let nd = "";
let mcIncident = "";
let mcAction = "";
let ndIsolate = "";

async function approve(orgId: string, actionId: string, cookie: string, target: string) {
  const { POST } = await import("@/app/api/v1/orgs/[orgId]/actions/[actionId]/approve/route");
  return POST(req("POST", `/api/v1/orgs/${orgId}/actions/${actionId}/approve`, { cookie, body: { target } }), ctx({ orgId, actionId }));
}

describe.skipIf(!enabled)("approvals and execution", () => {
  beforeAll(async () => {
    await resetDatabase();
    mc = (await one<{ org_id: string }>(`SELECT org_id FROM organizations WHERE slug = 'maple-creek'`))!.org_id;
    nd = (await one<{ org_id: string }>(`SELECT org_id FROM organizations WHERE slug = 'northfield-dental'`))!.org_id;
    mcIncident = (await one<{ incident_id: string }>(`SELECT incident_id FROM incidents WHERE org_id = ? AND ref = 'INC-0001'`, [mc]))!.incident_id;
    mcAction = (await one<{ action_id: string }>(`SELECT action_id FROM actions WHERE incident_id = ?`, [mcIncident]))!.action_id;
    ndIsolate = (await one<{ action_id: string }>(
      `SELECT a.action_id FROM actions a JOIN incidents i ON i.incident_id = a.incident_id
       WHERE i.org_id = ? AND i.ref = 'INC-0001' AND a.type = 'isolate_host'`,
      [nd]
    ))!.action_id;
  });
  afterAll(() => teardown());

  it("viewers can't approve", async () => {
    const res = await approve(mc, mcAction, await signIn("sam@maplecreek.test"), "192.168.8.66");
    expect(res.status).toBe(403);
  });

  it("members of another org can't approve (looks like 404)", async () => {
    const res = await approve(mc, mcAction, await signIn("chris@northfield.test"), "192.168.8.66");
    expect(res.status).toBe(404);
  });

  it("provider support access can't approve, even with an open support session", async () => {
    const cookie = await signIn("support@nw.test");
    const support = await import("@/app/api/v1/provider/orgs/[orgId]/support-sessions/route");
    await support.POST(req("POST", `/api/v1/provider/orgs/${mc}/support-sessions`, { cookie, body: { reason: "testing approvals" } }), ctx({ orgId: mc }));
    expect((await approve(mc, mcAction, cookie, "192.168.8.66")).status).toBe(403);
  });

  it("refuses an approval whose target doesn't match what's stored (stale or tampered screen)", async () => {
    const res = await approve(mc, mcAction, await signIn("dana@maplecreek.test"), "10.0.0.1");
    expect(res.status).toBe(409);
    const a = await one<{ status: string }>(`SELECT status FROM actions WHERE action_id = ?`, [mcAction]);
    expect(a!.status).toBe("awaiting_approval");
  });

  it("two approvals at the same moment: exactly one wins, and it runs once", async () => {
    const dana = await signIn("dana@maplecreek.test");
    const [a, b] = await Promise.all([approve(mc, mcAction, dana, "192.168.8.66"), approve(mc, mcAction, dana, "192.168.8.66")]);
    expect([a.status, b.status].sort()).toEqual([200, 409]);
    await settleBackground();

    const action = await one<ActionRow>(`SELECT * FROM actions WHERE action_id = ?`, [mcAction]);
    expect(action!.status).toBe("succeeded");
    expect(Boolean(action!.result_verified)).toBe(false); // simulate never claims verification
    expect(action!.result_detail).toMatch(/nothing was changed/);

    const events = await rows<{ event: string }>(`SELECT event FROM audit_log WHERE action_id = ? ORDER BY audit_id`, [mcAction]);
    const names = events.map((e) => e.event);
    expect(names.filter((n) => n === "action_approved")).toHaveLength(1);
    expect(names.filter((n) => n === "action_execution_started")).toHaveLength(1);
    expect(names).toContain("action_succeeded");

    const inc = await one<{ status: string }>(`SELECT status FROM incidents WHERE incident_id = ?`, [mcIncident]);
    expect(inc!.status).toBe("contained");
  });

  it("approving again after it ran is refused", async () => {
    const res = await approve(mc, mcAction, await signIn("dana@maplecreek.test"), "192.168.8.66");
    expect(res.status).toBe(409);
    expect((await body(res)).message).toMatch(/already succeeded/);
  });

  it("the executor itself is idempotent: calling it on a finished action does nothing", async () => {
    const before = await one<{ n: number }>(`SELECT COUNT(*) AS n FROM audit_log WHERE action_id = ?`, [mcAction]);
    await executeAction(mc, mcAction);
    const after = await one<{ n: number }>(`SELECT COUNT(*) AS n FROM audit_log WHERE action_id = ?`, [mcAction]);
    expect(Number(after!.n)).toBe(Number(before!.n));
  });

  it("deny records who and why, and the incident stops waiting", async () => {
    const chris = await signIn("chris@northfield.test");
    const { POST } = await import("@/app/api/v1/orgs/[orgId]/actions/[actionId]/deny/route");
    const res = await POST(
      req("POST", `/api/v1/orgs/${nd}/actions/${ndIsolate}/deny`, { cookie: chris, body: { target: "FRONTDESK-PC", reason: "Already unplugged it by hand" } }),
      ctx({ orgId: nd, actionId: ndIsolate })
    );
    expect(res.status).toBe(200);
    const incident = (await body(res)).data;
    const act = incident.actions.find((a: any) => a.id === ndIsolate);
    expect(act.status).toBe("denied");
    expect(act.decided_by).toMatchObject({ name: "Chris Wu", kind: "human" });
    expect(incident.status).toBe("investigating");
    const ev = await one<{ details: any }>(`SELECT details FROM audit_log WHERE action_id = ? AND event = 'action_denied'`, [ndIsolate]);
    expect(ev!.details.reason).toBe("Already unplugged it by hand");
  });

  it("unanswered approvals expire and can no longer be approved", async () => {
    // Make the Maple Creek clerk-laptop isolation wait again, then let its window lapse.
    const inc4 = (await one<{ incident_id: string }>(`SELECT incident_id FROM incidents WHERE org_id = ? AND ref = 'INC-0004'`, [mc]))!.incident_id;
    const id = (await one<{ action_id: string }>(`SELECT action_id FROM actions WHERE incident_id = ?`, [inc4]))!.action_id;
    await exec(
      `UPDATE actions SET status = 'awaiting_approval', decided_by = NULL, decided_at = NULL, executed_at = NULL,
       completed_at = NULL, result_verified = NULL, result_detail = NULL, expires_at = NOW(3) - INTERVAL 1 MINUTE
       WHERE action_id = ?`,
      [id]
    );
    const res = await approve(mc, id, await signIn("dana@maplecreek.test"), "CLERK-LAPTOP-02");
    expect(res.status).toBe(409);
    expect((await body(res)).message).toMatch(/already expired/);
    const ev = await one<{ n: number }>(`SELECT COUNT(*) AS n FROM audit_log WHERE action_id = ? AND event = 'action_expired'`, [id]);
    expect(Number(ev!.n)).toBe(1);
  });
});

describe("Wazuh executor (against a fake Wazuh API)", () => {
  let server: http.Server;
  let url = "";
  const calls: { method: string; path: string; auth: string; body: any }[] = [];

  beforeAll(async () => {
    server = http.createServer((rq, rs) => {
      let data = "";
      rq.on("data", (c) => (data += c));
      rq.on("end", () => {
        calls.push({ method: rq.method!, path: rq.url!, auth: rq.headers.authorization ?? "", body: data ? JSON.parse(data) : null });
        rs.setHeader("content-type", "application/json");
        if (rq.url === "/security/user/authenticate") return rs.end(JSON.stringify({ data: { token: "tok123" } }));
        if (rq.url!.startsWith("/active-response")) return rs.end(JSON.stringify({ data: { total_affected_items: 1 } }));
        rs.statusCode = 404;
        rs.end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    Object.assign(process.env, { WAZUH_API_URL: url, WAZUH_API_USER: "wazuh-wui", WAZUH_API_PASSWORD: "pw" });
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const action = (type: string, target: string) => ({ type, target }) as unknown as ActionRow;
  const assets = [
    { hostname: "CITYHALL-01", ip: "192.168.8.20", os: "Windows 11 Pro", kind: "endpoint" as const, agent_ref: "001", agent_status: "online" as const },
    { hostname: "DNS-FILTER", ip: "192.168.8.2", os: "Pi-hole", kind: "network" as const, agent_ref: null, agent_status: "online" as const },
  ];

  it("signs in, then sends the Windows block command to the incident's agent only", async () => {
    calls.length = 0;
    const result = await wazuhExecutor().run({ action: action("block_ip", "192.168.8.66"), assets });
    expect(result.ok).toBe(true);
    expect(result.verified).toBe(false);
    expect(calls[0]).toMatchObject({ method: "POST", path: "/security/user/authenticate" });
    expect(calls[0].auth).toBe(`Basic ${Buffer.from("wazuh-wui:pw").toString("base64")}`);
    expect(calls[1]).toMatchObject({ method: "PUT", path: "/active-response?agents_list=001", auth: "Bearer tok123" });
    expect(calls[1].body).toEqual({ command: "!netsh.exe", alert: { data: { srcip: "192.168.8.66" } } });
    expect(calls).toHaveLength(2);
  });

  it("refuses targets that aren't IP addresses", async () => {
    calls.length = 0;
    const result = await wazuhExecutor().run({ action: action("block_ip", "1.2.3.4; rm -rf /"), assets });
    expect(result.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("says plainly when an action type isn't automated yet", async () => {
    const result = await wazuhExecutor().run({ action: action("isolate_host", "CITYHALL-01"), assets });
    expect(result).toMatchObject({ ok: false });
    expect(result.detail).toMatch(/manually/);
  });
});
