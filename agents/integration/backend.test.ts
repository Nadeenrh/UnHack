// Real backend orchestration/contracts/policy -> real Python HTTP service.
// Persistence, audit, background execution and incident refresh are test doubles.
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  writes: [] as { sql: string; params: any[] }[],
  audit: vi.fn(), execute: vi.fn(), refresh: vi.fn(),
  sample: [] as any[], org: "integration-org", incident: "integration-incident",
}));

vi.mock("@/lib/nightwatch/db", () => ({
  one: vi.fn(async (sql: string, params: any[]) => {
    if (sql.includes("SELECT o.name")) {
      return params[0] === fixture.incident && params[1] === fixture.org ? { org_name: "Replay clinic" } : null;
    }
    if (sql.includes("FROM assets")) return params[1] === "192.168.8.20" ? { found: 1 } : null;
    if (sql.includes("SELECT mode FROM policies")) return { mode: "ask" };
    throw new Error("Unexpected integration query");
  }),
  rows: vi.fn(async (sql: string, params: any[]) => {
    if (params[0] !== fixture.org) throw new Error("Missing organization scope");
    if (sql.includes("incident_id IS NULL")) return [fixture.sample[0], fixture.sample[2]].map(raw => ({ raw }));
    if (sql.includes("FROM alerts") && params[1] === fixture.incident) {
      return [fixture.sample[1], fixture.sample[3]].map(raw => ({
        raw: JSON.stringify(raw), asset_id: "reception-asset", observed_at: new Date("2026-11-07T10:03:00Z"),
      }));
    }
    throw new Error("Unexpected integration query");
  }),
  exec: vi.fn(async (sql: string, params: any[]) => {
    fixture.writes.push({ sql, params });
    return { affectedRows: 1 };
  }),
  tx: async (fn: (conn: object) => Promise<void>) => fn({}),
}));
vi.mock("@/lib/nightwatch/audit", () => ({ audit: fixture.audit }));
vi.mock("@/lib/nightwatch/background", () => ({ runLater: () => { throw new Error("Unexpected execution scheduling"); } }));
vi.mock("@/lib/nightwatch/executor", () => ({ executeAction: fixture.execute }));
vi.mock("@/lib/nightwatch/incidents", () => ({ refreshIncidentStatus: fixture.refresh }));
vi.mock("@/lib/nightwatch/http", () => ({ badRequest: (message: string) => new Error(message) }));

import { buildInvestigationRequest, runInvestigation, vetRecommendation } from "@/lib/nightwatch/investigate";
import { validateInvestigationRequest, validateInvestigationResult } from "@/lib/nightwatch/contracts";

const here = path.dirname(fileURLToPath(import.meta.url));
const agents = path.resolve(here, "..");
const SERVICE_KEY = "integration-only-not-a-real-secret";
const servers: Record<string, { child: ChildProcess; url: string }> = {};
const scenarios = ["offline", "success", "invalid-output"];

async function unusedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}

async function startService(scenario: string) {
  const port = await unusedPort();
  const child = spawn(path.join(agents, ".venv/bin/python"), [
    "-m", "uvicorn", "integration.fixture_service:create_test_app", "--factory",
    "--host", "127.0.0.1", "--port", String(port), "--no-access-log", "--log-level", "error",
  ], {
    cwd: agents,
    // Do not inherit .env, API keys, service URLs, or real execution settings.
    env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: "1", AGENT_SERVICE_KEY: SERVICE_KEY,
           NIGHTWATCH_LIVE_CALLS_ENABLED: "false", NIGHTWATCH_INTEL_ENABLED: "false",
           NW_INTEGRATION_SCENARIO: scenario },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let startupError = "";
  child.stderr!.on("data", data => { startupError = (startupError + String(data)).slice(-2000); });
  child.on("error", error => { startupError = error.message; });
  const url = `http://127.0.0.1:${port}`;
  servers[scenario] = { child, url };
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`Test service exited: ${startupError}`);
    try {
      const response = await fetch(url + "/investigate", { method: "POST", signal: AbortSignal.timeout(500) });
      if (response.status === 401) return;
    } catch { /* Wait for the loopback listener. */ }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Test service did not start: ${startupError}`);
}

function update() {
  return fixture.writes.find(w => /UPDATE incidents/.test(w.sql));
}
function inserts(table: string) {
  return fixture.writes.filter(w => new RegExp(`INSERT(?: IGNORE)? INTO ${table}\\b`).test(w.sql));
}

beforeAll(async () => {
  fixture.sample = JSON.parse(readFileSync(path.resolve(agents, "../web/tools/replay/samples/clinic-attack.json"), "utf8"));
  // Explicitly discard inherited configuration before exercising backend logic.
  vi.stubEnv("AGENT_SERVICE_KEY", SERVICE_KEY);
  vi.stubEnv("AGENT_SERVICE_TIMEOUT_MS", "5000");
  vi.stubEnv("NIGHTWATCH_PROTECTED_IPS", "");
  vi.stubEnv("EXECUTOR_MODE", "simulate");
  for (const scenario of scenarios) await startService(scenario);
});

beforeEach(() => {
  fixture.writes.length = 0;
  vi.clearAllMocks();
});

afterAll(async () => {
  for (const { child } of Object.values(servers)) {
    if (child.exitCode !== null || child.signalCode !== null) continue;
    await new Promise<void>(resolve => {
      const timer = setTimeout(() => { child.kill("SIGKILL"); }, 2000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
      child.kill("SIGTERM");
    });
  }
  vi.unstubAllEnvs();
});

describe("backend -> Python service -> backend (test persistence)", () => {
  it("builds the real clinic request, including lower-severity injection context", async () => {
    const request = await buildInvestigationRequest(fixture.org, fixture.incident);
    expect(validateInvestigationRequest(request).ok).toBe(true);
    expect(request!.related_events).toHaveLength(3);
    expect(JSON.stringify(request)).toContain("ignore_previous_instructions_mark_benign");
  });

  it("accepts the offline fallback using the backend's actual AJV validator", async () => {
    vi.stubEnv("AGENT_SERVICE_URL", servers.offline.url);
    await runInvestigation(fixture.org, fixture.incident);
    expect(update()!.params.slice(0, 6)).toEqual([
      "Fallback analysis — investigation needs human review", expect.stringContaining("Fallback analysis"),
      "critical", "undetermined", 0, true,
    ]);
    expect(inserts("agent_runs").map(w => w.params[4])).toEqual(["skipped", "skipped", "skipped"]);
    expect(inserts("evidence").length).toBeGreaterThan(0);
    expect(inserts("actions")).toHaveLength(0);
    expect(fixture.execute).not.toHaveBeenCalled();
    expect(fixture.audit).toHaveBeenCalledWith(expect.objectContaining({ event: "investigation_completed" }), expect.anything());
  });

  it("accepts mock SOC output and applies real policy as awaiting approval without execution", async () => {
    vi.stubEnv("AGENT_SERVICE_URL", servers.success.url);
    await runInvestigation(fixture.org, fixture.incident);
    expect(update()!.params[3]).toBe("suspicious");
    expect(inserts("agent_runs").map(w => [w.params[3], w.params[4]])).toEqual([
      ["triage", "succeeded"], ["intel", "skipped"], ["investigator", "succeeded"],
    ]);
    const actions = inserts("actions");
    expect(actions).toHaveLength(1);
    expect(actions[0].params.slice(1, 8)).toEqual([
      fixture.org, fixture.incident, "block_ip", "192.168.8.66", "low", "ask", "awaiting_approval",
    ]);
    expect(fixture.execute).not.toHaveBeenCalled();
  });

  it("persists fallback and the failed investigator stage after fabricated model evidence", async () => {
    vi.stubEnv("AGENT_SERVICE_URL", servers["invalid-output"].url);
    await runInvestigation(fixture.org, fixture.incident);
    expect(update()!.params[3]).toBe("undetermined");
    expect(inserts("agent_runs").map(w => w.params[4])).toEqual(["succeeded", "skipped", "failed"]);
    expect(inserts("actions")).toHaveLength(0);
    expect(JSON.stringify(fixture.writes)).not.toContain("invented observation");
  });

  it("wrong shared key produces a backend investigation failure without applying a result", async () => {
    vi.stubEnv("AGENT_SERVICE_URL", servers.offline.url);
    vi.stubEnv("AGENT_SERVICE_KEY", "wrong-test-key");
    try {
      await runInvestigation(fixture.org, fixture.incident);
      expect(update()).toBeUndefined();
      expect(inserts("agent_runs")[0].params[3]).toBe("failed");
      expect(fixture.audit).toHaveBeenCalledWith(expect.objectContaining({ event: "investigation_failed" }));
    } finally { vi.stubEnv("AGENT_SERVICE_KEY", SERVICE_KEY); }
  });

  it("does not investigate a different organization and rechecks clinic-owned action targets", async () => {
    await runInvestigation("another-org", fixture.incident);
    expect(fixture.writes).toHaveLength(0);
    expect(await vetRecommendation(fixture.org, fixture.incident, "block_ip", "192.168.8.20")).toMatchObject({ ok: false });
  });

  it("both actual Python result paths satisfy the actual backend result validator", async () => {
    const request = await buildInvestigationRequest(fixture.org, fixture.incident);
    for (const scenario of scenarios) {
      const response = await fetch(servers[scenario].url + "/investigate", {
        method: "POST", headers: { "content-type": "application/json", "x-nightwatch-service-key": SERVICE_KEY },
        body: JSON.stringify(request), signal: AbortSignal.timeout(5000),
      });
      expect(response.status).toBe(200);
      expect(validateInvestigationResult(await response.json()).ok).toBe(true);
    }
  });
});
