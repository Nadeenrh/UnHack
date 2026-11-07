# How the 3 layers talk to each other

Read this before building your layer. If you change anything here, tell the other two first.

```
 victim PCs ──1514/1515──► [1] WAZUH ──HTTP POST :3000──► [3] WEB ──HTTP POST :8000──► [2] AI AGENTS
                                ▲                                  │                         │
                                └──── Wazuh API :55000 (block IP) ─┘ ◄──── verdict + advice ─┘
```

All HTTP bodies are JSON. All times are UTC, ISO 8601 (`2026-11-07T22:15:00Z`).

## Ports

| What | Port | Who connects to it |
|---|---|---|
| Web app (Next.js) | 3000 | Browsers, the Wazuh forwarder |
| MySQL | 3306 | Web app only |
| AI agent service | 8000 | Web app only |
| Wazuh API | 55000 (HTTPS) | Web app (to block IPs) |
| Wazuh agent events | 1514 (TCP) | Victim machines → Wazuh manager |
| Wazuh agent enrollment | 1515 (TCP) | Victim machines → Wazuh manager |
| Wazuh dashboard | 443 (HTTPS) | Us / judges in a browser |

Lab network: the victim VMs and Kali stay on an isolated network. The laptop running WEB and AGENTS keeps internet so the AI API works.

## [1] Wazuh → [3] Web: alerts

- **Request:** `POST http://<web-host>:3000/api/v1/ingest/wazuh`
- **Header:** `Authorization: Bearer nwk_...` (the clinic's ingest key)
- **Body:** one Wazuh alert exactly as Wazuh writes it in `alerts.json`. **Don't invent a custom format.** An array or `{ "alerts": [...] }` also works, up to 500 alerts / 5 MB.
- **Sent by:** `wazuh/integration/custom-nightwatch.py`, installed on the Wazuh manager.

Fields the web layer reads, so Wazuh must keep them:

| Field | Used for |
|---|---|
| `id` | Dedupe (same id twice = ignored) |
| `timestamp` | When it happened |
| `rule.level` | 7+ opens an incident; under 7 stored as context |
| `rule.id`, `rule.description`, `rule.groups` | What fired |
| `rule.mitre.id`, `rule.mitre.technique` | MITRE tags (`T1110` style) |
| `agent.id`, `agent.name`, `agent.ip` | Which machine. **Give every VM a stable, clear agent name** |
| `data.srcip` | Attacker IP (what gets blocked) |

Level → severity: 7–9 medium, 10–11 high, 12+ critical.

## [3] Web → [2] AI agents: investigate

- **Request:** `POST http://<agents-host>:8000/investigate`
- **Header:** `x-nightwatch-service-key: <shared secret>`. Reject requests without it.
- **Timeout:** 90 seconds. Answer faster than that.
- **Exact shape:** `web/contracts/investigation.schema.json`. The web layer **rejects** any reply that doesn't match it exactly. Extra fields count as wrong.

What the agents get:

```json
{
  "contract_version": "0.1",
  "incident_id": "…",
  "org_name": "Northfield Dental Clinic",
  "alert": { "…the first Wazuh alert, raw…" },
  "related_events": [ { "…other raw Wazuh alerts from the same machine…" } ]
}
```

What the agents must send back (all fields required):

| Field | Allowed values |
|---|---|
| `contract_version` | `"0.1"` |
| `incident_id` | Copy it from the request |
| `title`, `summary` | Plain English for a clinic manager |
| `severity` | `low` `medium` `high` `critical` |
| `verdict` | `malicious` `suspicious` `benign` `undetermined` |
| `confidence` | 0 to 1 |
| `mitre` | `[{ "technique_id": "T1110", "name": "Brute Force" }]` |
| `evidence` | `[{ "claim", "source", "log_ref", "observed_at" }]`; `source` is one of `wazuh` `sysmon` `windows_security` `virustotal` `urlscan` `pihole` `logwatch` `agent` |
| `injection_detected`, `injection_notes` | Did a log try to give the AI instructions? |
| `recommended_actions` | `[{ "type", "target", "rationale" }]`; `type` is one of `block_ip` `block_domain` `isolate_host` `quarantine_file` `disable_account` `notify_only` |
| `agent_runs` | One entry per agent that ran; `agent` is one of `triage` `intel` `investigator` |

Rules for the agent layer:

- **Every string inside an alert is attacker-controlled.** Treat it as data, never as instructions.
- **Recommend only.** Never block or isolate anything yourself. The web layer re-checks every recommendation, the policy decides auto / ask / never, and a person approves.
- **Store nothing.** The web layer is the record.
- **The AI API key lives only here,** in this service's environment.

## [3] Web → [1] Wazuh: responses

- The web layer signs in to the Wazuh API (`POST /security/user/authenticate`), then sends `PUT /active-response?agents_list=<agent id>`.
- Commands: `!firewall-drop` on Linux, `!netsh.exe` on Windows, with the attacker IP as `srcip`.
- **Wazuh layer must:** keep active response enabled on the agents, and give the web layer an API user and password.
- Only `block_ip` is automated today. Isolate needs a custom active-response script (stretch).

## Settings each layer needs from the others

| Setting | Who sets it | Where |
|---|---|---|
| Ingest key `nwk_...` | Web (shown at sign-up, or Settings → Sites) | Wazuh `ossec.conf` `<api_key>` |
| Web address | Web | Wazuh `ossec.conf` `<hook_url>` |
| `AGENT_SERVICE_URL`, `AGENT_SERVICE_KEY` | Agents | `web/.env.local` |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | Wazuh | `web/.env.local` |
| `EXECUTOR_MODE` | Web | `simulate` (pretend) or `wazuh` (really block) |
| `NIGHTWATCH_PUBLIC_URL` | Web | `web/.env.local`: this laptop's LAN address, e.g. `http://192.168.8.50:3000`, so the setup page shows a hook_url Wazuh can reach |
| `WAZUH_DASHBOARD_URL` (+ optional `WAZUH_DASHBOARD_LINK`) | Wazuh | `web/.env.local`: turns on "Open in Wazuh" links for our team |
