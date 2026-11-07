# Nightwatch build plan (UNHack 2026)

Status as of Saturday 2026-11-07. Target: under-resourced SMEs, including small clinics.

## 1. How the pieces fit

```
Kali VM â”€â”€attacksâ”€â”€â–º victim VMs (Wazuh agent, Sysmon on Windows)
                            â”‚ logs
                            â–¼
                     Wazuh manager + indexer + dashboard     â—„â”€â”€ us / judges (raw SIEM view)
                            â”‚ custom-nightwatch forwarder (../wazuh/integration)
                            â–¼
                     Nightwatch app (Next.js + MySQL)         â—„â”€â”€ client portal + provider portal
                            â”‚ POST /investigate (contracts/investigation.schema.json)
                            â–¼
                     Agent service (Python) â”€â”€â–º LLM API
                            â”‚ verdict + RECOMMENDED actions
                            â–¼
                     Policy engine decides auto / ask / never â”€â”€â–º human approves â”€â”€â–º Wazuh active response
```

## 2. Wazuh, Kibana, Grafana, Airia: what to use

| Tool | Use it? | Why |
|---|---|---|
| **Wazuh** (manager, indexer, dashboard) | **Yes** | The sensor and SIEM. Collects logs, runs detection rules, maps to MITRE, and runs active responses (our `block_ip`). Its dashboard is for us and the judges, not for clients. |
| **Kibana** | **No** | Wazuh's dashboard is already a fork of OpenSearch Dashboards, which is itself a Kibana fork. Kibana would also need Elasticsearch: a second stack doing the same job. |
| **Grafana** | **Not for the hackathon** | Nice for provider-side metrics later (it can read MySQL directly). Our portal already has stat tiles and an activity chart. |
| **Airia** | **No** | An enterprise platform for building and governing AI agents, sold by demo request. Our policy engine already does the governance part (agents only recommend; policy and a human decide). Treat it as a comparison point in the pitch. |
| **Our portal** | **Yes** | The only screen a client sees: plain language, approve / deny, Pi-hole simple. |

## 3. AI: API (recommended) vs local

**Use an API.** Multi-agent reasoning that has to return strict JSON is slow and unreliable on a Pi 5, and the API is what makes the demo work today.

- **Best fit for the "stays in Canada" pitch:** Claude through Amazon Bedrock in `ca-central-1` using the Canada geo inference profile (model IDs starting `ca.anthropic.â€¦`). AWS documents that this profile routes only to `ca-central-1` and `ca-west-1`. Check which Claude models your AWS account can use before choosing.
- **Fastest to set up:** a provider's own API (Anthropic, OpenAI). Fine for the demo because the lab sends fake data, but processing then happens outside Canada. Say that honestly and show Bedrock Canada as the production path.
- **Local (Ollama on the Pi):** keep it as a slide, "air-gapped option for clinics that can't send anything out", not the demo path.

Whatever the provider: turn off training on our data, and keep the API key only in the agent service's environment.

### Privacy step to build (not built yet)

Before the platform sends an incident to the agent service, swap identifying values for tokens and swap them back on the way in:

1. In `buildInvestigationRequest` (`lib/nightwatch/investigate.ts`), replace usernames, hostnames, internal IPs and emails with `USER_1`, `HOST_2`, `IP_3`, keeping a per-incident map in memory.
2. The agent service and the LLM only ever see tokens.
3. In `applyInvestigation`, map `recommended_actions[].target`, the title, summary and evidence claims back **before** `vetRecommendation` runs, so the safety checks still see real values.
4. Never send patient or business data. We only send security logs (logins, firewall, process, file-change events).

Pitch it as: "the AI never sees who you are, only what happened". The law to name for clinics is Ontario's **PHIPA** (plus federal **PIPEDA**), not HIPAA. Treat IPs and account names as personal information.

## 4. Agent service (`agents/` at the repo root)

Not built yet. Without it, incidents still open and say "investigation skipped". Minimum version:

- Python + FastAPI, one route: `POST /investigate`. Reject requests without the `x-nightwatch-service-key` header.
- Input and output must match `contracts/investigation.schema.json`. The platform rejects anything else.
- Three steps: **triage** (what is this, how bad), **intel** (is the IP / hash / domain known bad), **investigator** (story, MITRE, evidence, recommended actions).
- Treat every string in the alert as attacker-controlled. Set `injection_detected` when an alert tries to instruct the AI (the fixtures include an example).
- Stores nothing. Set `AGENT_SERVICE_URL` and `AGENT_SERVICE_KEY` in the app's env to switch it on.

## 5. Attack lab (VMs + Kali)

Only attack machines we own, on the isolated lab network (GL.iNet router).

| VM | Role | Notes |
|---|---|---|
| Wazuh all-in-one (Ubuntu) | SIEM | Needs a laptop with real RAM; check Wazuh's current all-in-one requirements. Install the forwarder from `wazuh/integration/` at the repo root. |
| Ubuntu server | "clinic file server" | Wazuh agent, SSH on. |
| Windows 10/11 | "front desk PC" | Wazuh agent + Sysmon. File integrity monitoring on a shared folder (realtime). |
| Kali | attacker | |
| Nightwatch app + MySQL | platform | Laptop or Pi, via Docker (see README). |

Demo scenarios, best first:

1. **SSH brute force** (Kali `hydra` â†’ Ubuntu). Wazuh's sshd brute-force rules fire at level 10, which opens an incident. `block_ip` is the one action the Wazuh executor automates, so this shows the full loop: detect â†’ AI explains â†’ owner approves â†’ Wazuh blocks Kali. Set `EXECUTOR_MODE=wazuh`.
2. **Password spray on Windows** (Kali `netexec` over SMB/RDP) â†’ "multiple Windows logon failures" (level 10, same as the replay sample).
3. **Ransomware tripwire**: a harmless script on the Windows VM that renames many files in the monitored folder. Shows `isolate_host` as a "do this yourself" recommendation, since only `block_ip` is automated.

Record one run's alerts (`/var/ossec/logs/alerts/alerts.json`) and save them as a replay sample, so the pitch still works if the lab misbehaves on stage.

## 6. What we have, what we don't need, what we still need

**Have (built and tested):** sign-up that creates the org, owner, default policies, first site and a one-time ingest key; login, roles and multi-tenant access rules; Wazuh ingest with dedupe and incident correlation; contract validation and safety checks on every AI recommendation; policy engine (auto / ask / never) with an approval window; Wazuh `block_ip` executor plus a simulate mode; tamper-evident audit log; client and provider portals; fixtures; replay tool; 36 tests.


**Still need, in order:**

1. Agent service (section 4). Without it the AI part of the demo is fixtures only.
2. Lab + forwarder installed on the Wazuh manager (section 5). Verify the Wazuh executor against the real manager.
3. "Connect your first machine" page after sign-up: show the `<integration>` snippet with the org's ingest key filled in (web layer).
4. Privacy tokenizing step (section 3).
5. Demo story for SMEs: the replay sample and the "Township of Maple Creek" fixture are municipality-framed. Rename them to a clinic in `tools/fixtures/build_fixtures.py` and regenerate.
6. Later, not for the demo: email verification, password reset, inviting teammates to an org, login throttling that survives restarts.
