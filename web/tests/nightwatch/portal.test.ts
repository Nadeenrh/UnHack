import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { validateIncident } from "@/lib/nightwatch/contracts";
import { one } from "@/lib/nightwatch/db";
import { body, ctx, enabled, req, resetDatabase, signIn, teardown } from "./harness";

const ids: Record<string, string> = {};

describe.skipIf(!enabled)("portal read APIs and tenant isolation", () => {
  beforeAll(async () => {
    await resetDatabase();
    for (const slug of ["maple-creek", "northfield-dental", "riverbend-water"]) {
      ids[slug] = (await one<{ org_id: string }>(`SELECT org_id FROM organizations WHERE slug = ?`, [slug]))!.org_id;
    }
    ids.ndIncident = (await one<{ incident_id: string }>(
      `SELECT incident_id FROM incidents WHERE org_id = ? AND ref = 'INC-0001'`,
      [ids["northfield-dental"]]
    ))!.incident_id;
  });
  afterAll(() => teardown());

  it("a member lists their org's incidents, every one valid against the contract", async () => {
    const cookie = await signIn("dana@maplecreek.test");
    const { GET } = await import("@/app/api/v1/orgs/[orgId]/incidents/route");
    const res = await GET(req("GET", `/api/v1/orgs/${ids["maple-creek"]}/incidents`, { cookie }), ctx({ orgId: ids["maple-creek"] }));
    expect(res.status).toBe(200);
    const incidents = (await body(res)).data;
    expect(incidents).toHaveLength(4);
    for (const inc of incidents) {
      const v = validateIncident(inc);
      expect(v.ok, v.ok ? "" : v.error).toBe(true);
      expect(inc.org.name).toBe("Township of Maple Creek");
    }
    const demo = incidents.find((i: any) => i.ref === "INC-0001");
    expect(demo.status).toBe("awaiting_approval");
    expect(demo.injection_detected).toBe(true);
    expect(demo.actions[0]).toMatchObject({ type: "block_ip", target: "192.168.8.66", status: "awaiting_approval" });
  });

  it("filters open vs closed", async () => {
    const cookie = await signIn("dana@maplecreek.test");
    const { GET } = await import("@/app/api/v1/orgs/[orgId]/incidents/route");
    const open = (await body(await GET(req("GET", `/api/v1/orgs/${ids["maple-creek"]}/incidents?status=open`, { cookie }), ctx({ orgId: ids["maple-creek"] })))).data;
    const closed = (await body(await GET(req("GET", `/api/v1/orgs/${ids["maple-creek"]}/incidents?status=closed`, { cookie }), ctx({ orgId: ids["maple-creek"] })))).data;
    expect(open.map((i: any) => i.status).sort()).toEqual(["awaiting_approval", "contained", "investigating"]);
    expect(closed.map((i: any) => i.status)).toEqual(["false_positive"]);
  });

  it("another org's data is invisible: 404 for their org and for their incident under your org", async () => {
    const cookie = await signIn("dana@maplecreek.test");
    const list = await import("@/app/api/v1/orgs/[orgId]/incidents/route");
    const detail = await import("@/app/api/v1/orgs/[orgId]/incidents/[incidentId]/route");
    const theirOrg = await list.GET(req("GET", `/api/v1/orgs/${ids["northfield-dental"]}/incidents`, { cookie }), ctx({ orgId: ids["northfield-dental"] }));
    expect(theirOrg.status).toBe(404);
    // Their incident id, smuggled under Dana's own org path.
    const smuggled = await detail.GET(
      req("GET", `/api/v1/orgs/${ids["maple-creek"]}/incidents/${ids.ndIncident}`, { cookie }),
      ctx({ orgId: ids["maple-creek"], incidentId: ids.ndIncident })
    );
    expect(smuggled.status).toBe(404);
    // A made-up org id looks exactly the same as a forbidden one.
    const fake = await list.GET(req("GET", `/api/v1/orgs/00000000-0000-4000-8000-000000000000/incidents`, { cookie }), ctx({ orgId: "00000000-0000-4000-8000-000000000000" }));
    expect(fake.status).toBe(404);
  });

  it("dashboard snapshot reflects health", async () => {
    const cookie = await signIn("omar@riverbend.test");
    const { GET } = await import("@/app/api/v1/orgs/[orgId]/route");
    const snap = (await body(await GET(req("GET", `/api/v1/orgs/${ids["riverbend-water"]}`, { cookie }), ctx({ orgId: ids["riverbend-water"] })))).data;
    expect(snap).toMatchObject({ health: "healthy", open_incidents: 0, pending_approvals: 0, assets_total: 2 });
    expect(snap.access).toEqual({ via: "membership", role: "owner" });
  });

  it("policies: viewers can't change them; owners can; high-risk actions can never be automatic", async () => {
    const path = `/api/v1/orgs/${ids["maple-creek"]}/policies`;
    const { PUT, GET } = await import("@/app/api/v1/orgs/[orgId]/policies/route");
    const viewer = await signIn("sam@maplecreek.test");
    expect((await PUT(req("PUT", path, { cookie: viewer, body: { action_type: "block_ip", mode: "auto" } }), ctx({ orgId: ids["maple-creek"] }))).status).toBe(403);

    const owner = await signIn("dana@maplecreek.test");
    const unsafe = await PUT(req("PUT", path, { cookie: owner, body: { action_type: "isolate_host", mode: "auto" } }), ctx({ orgId: ids["maple-creek"] }));
    expect(unsafe.status).toBe(400);
    const okRes = await PUT(req("PUT", path, { cookie: owner, body: { action_type: "block_ip", mode: "never" } }), ctx({ orgId: ids["maple-creek"] }));
    expect(okRes.status).toBe(200);
    const policies = (await body(await GET(req("GET", path, { cookie: viewer }), ctx({ orgId: ids["maple-creek"] })))).data;
    expect(policies.find((p: any) => p.action_type === "block_ip").mode).toBe("never");
    expect(policies.find((p: any) => p.action_type === "isolate_host").auto_allowed).toBe(false);
    // put it back for later tests
    await PUT(req("PUT", path, { cookie: owner, body: { action_type: "block_ip", mode: "ask" } }), ctx({ orgId: ids["maple-creek"] }));
  });

  it("clients can't reach the provider overview", async () => {
    const cookie = await signIn("dana@maplecreek.test");
    const { GET } = await import("@/app/api/v1/provider/overview/route");
    expect((await GET(req("GET", "/api/v1/provider/overview", { cookie }), ctx())).status).toBe(403);
  });

  it("provider: sees every client's status, but needs an audited support session to open a workspace", async () => {
    const cookie = await signIn("support@nw.test");
    const overview = await import("@/app/api/v1/provider/overview/route");
    const snaps = (await body(await overview.GET(req("GET", "/api/v1/provider/overview", { cookie }), ctx()))).data;
    expect(snaps.map((s: any) => [s.org.name, s.health])).toEqual([
      ["Northfield Dental Clinic", "attention"],
      ["Riverbend Water Utility", "healthy"],
      ["Township of Maple Creek", "attention"],
    ]);

    const list = await import("@/app/api/v1/orgs/[orgId]/incidents/route");
    const nd = ids["northfield-dental"];
    expect((await list.GET(req("GET", `/api/v1/orgs/${nd}/incidents`, { cookie }), ctx({ orgId: nd }))).status).toBe(404);

    const support = await import("@/app/api/v1/provider/orgs/[orgId]/support-sessions/route");
    const opened = await support.POST(
      req("POST", `/api/v1/provider/orgs/${nd}/support-sessions`, { cookie, body: { reason: "Client asked for help with INC-0001" } }),
      ctx({ orgId: nd })
    );
    expect(opened.status).toBe(200);
    const sessionId = (await body(opened)).data.id;

    const visible = await list.GET(req("GET", `/api/v1/orgs/${nd}/incidents`, { cookie }), ctx({ orgId: nd }));
    expect(visible.status).toBe(200);
    expect((await body(visible)).data).toHaveLength(4);

    // The client sees that we looked.
    const clientCookie = await signIn("leah@northfield.test");
    const auditRoute = await import("@/app/api/v1/orgs/[orgId]/audit/route");
    const events = (await body(await auditRoute.GET(req("GET", `/api/v1/orgs/${nd}/audit?limit=5`, { cookie: clientCookie }), ctx({ orgId: nd })))).data;
    expect(events[0]).toMatchObject({ event: "support_session_started", actor_type: "provider_support" });

    // Support access is read-only.
    const policies = await import("@/app/api/v1/orgs/[orgId]/policies/route");
    const change = await policies.PUT(
      req("PUT", `/api/v1/orgs/${nd}/policies`, { cookie, body: { action_type: "block_ip", mode: "never" } }),
      ctx({ orgId: nd })
    );
    expect(change.status).toBe(403);

    // Ending the session closes the window again.
    const end = await import("@/app/api/v1/provider/support-sessions/[sessionId]/end/route");
    expect((await end.POST(req("POST", `/api/v1/provider/support-sessions/${sessionId}/end`, { cookie }), ctx({ sessionId }))).status).toBe(200);
    expect((await list.GET(req("GET", `/api/v1/orgs/${nd}/incidents`, { cookie }), ctx({ orgId: nd }))).status).toBe(404);
  });

  it("owners can rotate an ingest key; the response shows it once, the list never does", async () => {
    const cookie = await signIn("dana@maplecreek.test");
    const sites = await import("@/app/api/v1/orgs/[orgId]/sites/route");
    const list = (await body(await sites.GET(req("GET", `/api/v1/orgs/${ids["maple-creek"]}/sites`, { cookie }), ctx({ orgId: ids["maple-creek"] })))).data;
    expect(JSON.stringify(list)).not.toMatch(/hash/);
    const rotate = await import("@/app/api/v1/orgs/[orgId]/sites/[siteId]/rotate-key/route");
    const res = await rotate.POST(
      req("POST", `/api/v1/orgs/${ids["maple-creek"]}/sites/${list[0].id}/rotate-key`, { cookie }),
      ctx({ orgId: ids["maple-creek"], siteId: list[0].id })
    );
    expect(res.status).toBe(200);
    expect((await body(res)).data.ingest_key).toMatch(/^nwk_/);
  });
});
