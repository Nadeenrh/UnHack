// Wazuh active-response executor.
//
// Config (env):
//   WAZUH_API_URL            e.g. https://192.168.8.5:55000
//   WAZUH_API_USER / WAZUH_API_PASSWORD
//   WAZUH_TLS_INSECURE=true  accept Wazuh's self-signed certificate (lab only)
//   WAZUH_CMD_BLOCK_LINUX    default "!firewall-drop"
//   WAZUH_CMD_BLOCK_WINDOWS  default "!netsh.exe"
//
// Uses the Wazuh server API: POST /security/user/authenticate, then
// PUT /active-response?agents_list=<ids> with {command, alert: {data: {srcip}}}.
// A leading "!" runs the named active-response script directly on the agent.
//
// Status: written against the Wazuh 4.x API docs and tested against a fake server.
// NOT yet run against a real Wazuh manager. Verify in the lab before the demo.

import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import type { ExecutionContext, ExecutionResult, ResponseExecutor } from "./types";

interface Reply {
  status: number;
  json: any;
}

function request(method: string, url: URL, headers: Record<string, string>, body?: unknown): Promise<Reply> {
  const lib = url.protocol === "https:" ? https : http;
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const r = lib.request(
      url,
      {
        method,
        headers: { ...headers, ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}) },
        rejectUnauthorized: process.env.WAZUH_TLS_INSECURE !== "true",
        timeout: 15000,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          let json: any = null;
          try {
            json = data ? JSON.parse(data) : null;
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      }
    );
    r.on("timeout", () => r.destroy(new Error("Wazuh API timed out")));
    r.on("error", reject);
    if (payload) r.write(payload);
    r.end();
  });
}

export function wazuhExecutor(): ResponseExecutor {
  const base = process.env.WAZUH_API_URL;
  const user = process.env.WAZUH_API_USER;
  const pass = process.env.WAZUH_API_PASSWORD;

  return {
    name: "wazuh",
    async run(ctx: ExecutionContext): Promise<ExecutionResult> {
      if (!base || !user || !pass) {
        return { ok: false, verified: false, detail: "Wazuh executor isn't configured (WAZUH_API_URL / user / password)." };
      }
      if (ctx.action.type !== "block_ip") {
        return {
          ok: false,
          verified: false,
          detail: `${ctx.action.type.replace("_", " ")} isn't automated through Wazuh yet. Please do this one manually.`,
        };
      }
      if (!isIP(ctx.action.target)) {
        return { ok: false, verified: false, detail: `Refused: "${ctx.action.target}" is not an IP address.` };
      }

      const agents = ctx.assets.filter((a) => a.agent_ref && (a.kind === "endpoint" || a.kind === "server"));
      if (!agents.length) {
        return { ok: false, verified: false, detail: "No Wazuh agent is linked to this incident's machines, so there was nowhere to apply the block." };
      }

      const auth = await request("POST", new URL("/security/user/authenticate", base), {
        authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`,
      });
      const token = auth.json?.data?.token;
      if (auth.status !== 200 || !token) {
        return { ok: false, verified: false, detail: `Couldn't sign in to the Wazuh API (HTTP ${auth.status}).` };
      }

      const delivered: string[] = [];
      const failed: string[] = [];
      for (const a of agents) {
        const windows = (a.os ?? "").toLowerCase().includes("windows");
        const command = windows
          ? process.env.WAZUH_CMD_BLOCK_WINDOWS ?? "!netsh.exe"
          : process.env.WAZUH_CMD_BLOCK_LINUX ?? "!firewall-drop";
        const url = new URL("/active-response", base);
        url.searchParams.set("agents_list", a.agent_ref!);
        const res = await request(
          "PUT",
          url,
          { authorization: `Bearer ${token}` },
          { command, alert: { data: { srcip: ctx.action.target } } }
        );
        const affected = Number(res.json?.data?.total_affected_items ?? 0);
        (res.status === 200 && affected > 0 ? delivered : failed).push(`${a.hostname} (agent ${a.agent_ref})`);
      }

      if (!delivered.length) {
        return { ok: false, verified: false, detail: `Wazuh did not accept the block for: ${failed.join(", ")}.` };
      }
      return {
        ok: true,
        verified: false,
        detail:
          `Block for ${ctx.action.target} sent to ${delivered.join(", ")}. ` +
          (failed.length ? `Not delivered to ${failed.join(", ")}. ` : "") +
          "Delivery confirmed by Wazuh; the firewall rule itself was not independently checked.",
      };
    },
  };
}
