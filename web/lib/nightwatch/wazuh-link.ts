// Deep links into the Wazuh dashboard for provider staff. Clients never see these:
// they get the plain-language view, we get the full SIEM.
//
// WAZUH_DASHBOARD_URL   e.g. https://192.168.8.5   (unset = no links shown)
// WAZUH_DASHBOARD_LINK  path for one machine's events; {agent_id} and {agent_name} are filled in.
//                       The default suits Wazuh 4.x; check it once on your dashboard version.

const DEFAULT_AGENT_PATH = "/app/threat-hunting#/overview/?tab=general&tabView=events&agentId={agent_id}";

function base(): string | null {
  const url = process.env.WAZUH_DASHBOARD_URL?.trim();
  return url ? url.replace(/\/+$/, "") : null;
}

export function wazuhHomeLink(): string | null {
  const b = base();
  return b ? `${b}/app/threat-hunting` : null;
}

export function wazuhAgentLink(agent: { agent_ref: string | null; hostname: string }): string | null {
  const b = base();
  if (!b || !agent.agent_ref) return null;
  const path = (process.env.WAZUH_DASHBOARD_LINK?.trim() || DEFAULT_AGENT_PATH)
    .replaceAll("{agent_id}", encodeURIComponent(agent.agent_ref))
    .replaceAll("{agent_name}", encodeURIComponent(agent.hostname));
  return `${b}${path.startsWith("/") ? "" : "/"}${path}`;
}
