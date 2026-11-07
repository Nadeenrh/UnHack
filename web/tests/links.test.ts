import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { integrationXml, KEY_PLACEHOLDER } from "@/components/connect/IntegrationSnippet";
import { ingestUrl, isLoopback } from "@/lib/nightwatch/public-url";
import { wazuhAgentLink, wazuhHomeLink } from "@/lib/nightwatch/wazuh-link";

const env = { ...process.env };
afterEach(() => {
  process.env = { ...env };
});

describe("setup snippet", () => {
  it("fills in the hook URL and key, or a placeholder when the key isn't known", () => {
    const xml = integrationXml(ingestUrl("http://192.168.8.50:3000"), "nwk_abc");
    expect(xml).toContain("<hook_url>http://192.168.8.50:3000/api/v1/ingest/wazuh</hook_url>");
    expect(xml).toContain("<api_key>nwk_abc</api_key>");
    expect(xml).toContain("<name>custom-nightwatch</name>");
    expect(integrationXml("http://x/api/v1/ingest/wazuh", null)).toContain(`<api_key>${KEY_PLACEHOLDER}</api_key>`);
  });

  it("warns only for addresses another machine can't reach", () => {
    expect(isLoopback("http://localhost:3001")).toBe(true);
    expect(isLoopback("http://127.0.0.1:3000")).toBe(true);
    expect(isLoopback("http://192.168.8.50:3000")).toBe(false);
    expect(isLoopback("not a url")).toBe(false);
  });

  it("serves the same forwarder script that wazuh/integration documents", () => {
    const web = readFileSync(path.resolve(__dirname, "../public/downloads/custom-nightwatch.py"), "utf8");
    const wazuh = readFileSync(path.resolve(__dirname, "../../wazuh/integration/custom-nightwatch.py"), "utf8");
    expect(web).toBe(wazuh);
  });
});

describe("Wazuh dashboard links", () => {
  it("are off until WAZUH_DASHBOARD_URL is set", () => {
    delete process.env.WAZUH_DASHBOARD_URL;
    expect(wazuhHomeLink()).toBeNull();
    expect(wazuhAgentLink({ agent_ref: "001", hostname: "RECEPTION-PC" })).toBeNull();
  });

  it("build per-machine links from the template", () => {
    process.env.WAZUH_DASHBOARD_URL = "https://192.168.8.5/";
    expect(wazuhHomeLink()).toBe("https://192.168.8.5/app/threat-hunting");
    expect(wazuhAgentLink({ agent_ref: "001", hostname: "RECEPTION-PC" })).toContain("agentId=001");
    expect(wazuhAgentLink({ agent_ref: null, hostname: "RECEPTION-PC" })).toBeNull();
    process.env.WAZUH_DASHBOARD_LINK = "/app/discover#?q={agent_name}";
    expect(wazuhAgentLink({ agent_ref: "001", hostname: "RECEPTION PC" })).toBe("https://192.168.8.5/app/discover#?q=RECEPTION%20PC");
  });
});
