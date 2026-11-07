import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { body, ctx, DEV_PASSWORD, enabled, req, resetDatabase, sessionCookie, signIn, teardown } from "./harness";

describe.skipIf(!enabled)("auth: login, sessions, register", () => {
  beforeAll(() => resetDatabase());
  afterAll(() => teardown());

  it("logs in, sets an HttpOnly cookie, and never returns the token in the body", async () => {
    const { POST } = await import("@/app/api/v1/auth/login/route");
    const res = await POST(
      req("POST", "/api/v1/auth/login", { body: { email: "dana@maplecreek.test", password: DEV_PASSWORD } }),
      ctx()
    );
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/nw_session=/);
    expect(setCookie.toLowerCase()).toContain("httponly");
    expect(setCookie.toLowerCase()).toContain("samesite=lax");
    const text = JSON.stringify(await body(res));
    const token = /nw_session=([^;]*)/.exec(setCookie)![1];
    expect(text).not.toContain(token);
    expect(text).not.toMatch(/password|hash/i);
  });

  it("gives the same answer for a wrong password and an unknown email (no account probing)", async () => {
    const { POST } = await import("@/app/api/v1/auth/login/route");
    const wrongPw = await POST(
      req("POST", "/api/v1/auth/login", { body: { email: "dana@maplecreek.test", password: "nope-nope-nope" } }),
      ctx()
    );
    const noUser = await POST(
      req("POST", "/api/v1/auth/login", { body: { email: "ghost@nowhere.example", password: "nope-nope-nope" } }),
      ctx()
    );
    expect(wrongPw.status).toBe(401);
    expect(noUser.status).toBe(401);
    expect((await body(wrongPw)).message).toBe((await body(noUser)).message);
  });

  it("throttles repeated failures", async () => {
    const { POST } = await import("@/app/api/v1/auth/login/route");
    let last = 0;
    for (let i = 0; i < 12; i++) {
      const res = await POST(
        req("POST", "/api/v1/auth/login", {
          body: { email: "sam@maplecreek.test", password: "wrong-wrong-wrong" },
          headers: { "x-forwarded-for": "203.0.113.200" },
        }),
        ctx()
      );
      last = res.status;
    }
    expect(last).toBe(429);
  });

  it("/me returns the user with their org memberships", async () => {
    const cookie = await signIn("leah@northfield.test");
    const { GET } = await import("@/app/api/v1/auth/me/route");
    const res = await GET(req("GET", "/api/v1/auth/me", { cookie }), ctx());
    const data = (await body(res)).data;
    expect(res.status).toBe(200);
    expect(data.user.email).toBe("leah@northfield.test");
    expect(data.memberships).toEqual([
      expect.objectContaining({ org_name: "Northfield Dental Clinic", role: "owner" }),
    ]);
  });

  it("rejects requests with no session or a made-up session", async () => {
    const { GET } = await import("@/app/api/v1/auth/me/route");
    expect((await GET(req("GET", "/api/v1/auth/me"), ctx())).status).toBe(401);
    expect((await GET(req("GET", "/api/v1/auth/me", { cookie: "nw_session=forged" }), ctx())).status).toBe(401);
  });

  it("logout revokes the session server-side (the old cookie stops working)", async () => {
    const cookie = await signIn("omar@riverbend.test");
    const { POST } = await import("@/app/api/v1/auth/logout/route");
    const { GET } = await import("@/app/api/v1/auth/me/route");
    expect((await POST(req("POST", "/api/v1/auth/logout", { cookie }), ctx())).status).toBe(200);
    expect((await GET(req("GET", "/api/v1/auth/me", { cookie }), ctx())).status).toBe(401);
  });

  it("blocks cookie-authenticated writes from another site (CSRF)", async () => {
    const cookie = await signIn("chris@northfield.test");
    const { POST } = await import("@/app/api/v1/auth/logout/route");
    const evil = await POST(req("POST", "/api/v1/auth/logout", { cookie, origin: "https://evil.example" }), ctx());
    expect(evil.status).toBe(403);
    const none = await POST(req("POST", "/api/v1/auth/logout", { cookie, origin: null }), ctx());
    expect(none.status).toBe(403);
  });

  it("registers a new business: org, owner, policies, first site; key shown once", async () => {
    const { POST } = await import("@/app/api/v1/auth/register/route");
    const res = await POST(
      req("POST", "/api/v1/auth/register", {
        body: {
          organization: { name: "Elm Street Library", sector: "community_org" },
          user: { first_name: "Ana", last_name: "Lee", email: "Ana@ElmLibrary.example", password: "correct-horse-battery" },
        },
      }),
      ctx()
    );
    expect(res.status).toBe(201);
    const data = (await body(res)).data;
    expect(data.organization.slug).toBe("elm-street-library");
    expect(data.memberships[0]).toMatchObject({ org_name: "Elm Street Library", role: "owner" });
    expect(data.first_site.ingest_key).toMatch(/^nwk_/);
    expect(data.user.email).toBe("ana@elmlibrary.example");
    sessionCookie(res); // signed in straight away

    const dup = await POST(
      req("POST", "/api/v1/auth/register", {
        body: {
          organization: { name: "Elm Street Library", sector: "community_org" },
          user: { first_name: "Ana", last_name: "Lee", email: "ana@elmlibrary.example", password: "correct-horse-battery" },
        },
      }),
      ctx()
    );
    expect(dup.status).toBe(409);
  });

  it("rejects weak passwords and unknown sectors", async () => {
    const { POST } = await import("@/app/api/v1/auth/register/route");
    const weak = await POST(
      req("POST", "/api/v1/auth/register", {
        body: {
          organization: { name: "X Corp", sector: "small_business" },
          user: { first_name: "A", last_name: "B", email: "a@x.example", password: "short" },
        },
      }),
      ctx()
    );
    expect(weak.status).toBe(400);
    const sector = await POST(
      req("POST", "/api/v1/auth/register", {
        body: {
          organization: { name: "X Corp", sector: "casino" },
          user: { first_name: "A", last_name: "B", email: "a@x.example", password: "long-enough-password" },
        },
      }),
      ctx()
    );
    expect(sector.status).toBe(400);
  });
});
