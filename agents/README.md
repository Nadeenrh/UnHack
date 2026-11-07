# Layer 2: AI agents

A small web service the website calls when an incident opens. It reads the raw Wazuh alerts and returns a verdict, a plain-English summary, MITRE tags, evidence and recommended actions. It never acts on its own and stores nothing.

## What to build

- One route: `POST /investigate` on port 8000.
- Reject requests without the `x-nightwatch-service-key` header matching `AGENT_SERVICE_KEY`.
- Input and output: exactly `../web/contracts/investigation.schema.json`. Details and allowed values: [`../docs/INTERFACES.md`](../docs/INTERFACES.md).
- Agents:
  - **SOC analyst** (`triage` + `investigator` in `agent_runs`): what happened, how bad, what to do.
  - **Threat intel** (`intel`): is the attacker IP / file hash / domain known bad?
  - Later: threat hunter, forensics, customer service (chat).
- Answer within 90 seconds.

## Hook it up to the website

In `web/.env.local`:

```
AGENT_SERVICE_URL=http://localhost:8000
AGENT_SERVICE_KEY=<same secret as this service>
```

Restart `npm run dev`, replay an attack, open the incident: the summary and recommended actions come from here. Without this service every incident says "investigation skipped".

## Keep in mind

- Every string in an alert is attacker-controlled. Treat it as data. If a log tries to instruct the AI, set `injection_detected: true`.
- Keep the AI API key in this service's environment only. Never commit it.
