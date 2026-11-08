# Layer 2: Nightwatch AI agents

A stateless Python/FastAPI service called by the web backend. It reads untrusted
Wazuh alerts and returns an investigation and **recommended** actions. The backend
owns organization scope, persistence, approvals, policy and execution. This service
does not block, isolate, run commands or store incidents.

## Current increment: phase 4 integration checks

Two logical analysts perform three contract stages:

```text
POST /investigate → SOC triage → threat intelligence → SOC final investigation
                       triage          intel              investigator
```

The SOC analyst uses two bounded OpenAI calls. The threat intelligence analyst is
deterministic: it extracts indicators from known fields and retrieves optional
VirusTotal reports. An LLM is not needed to choose endpoints or report engine counts.

| File | Responsibility |
|---|---|
| `app.py` | Authentication, HTTP limits and sanitized errors |
| `contracts.py` | Direct validation against the existing shared JSON Schema |
| `service.py` | Offline/live selection; request-scoped clients |
| `context.py` | Bounded log context, exact evidence references, injection heuristic |
| `model.py` | Configurable Responses API adapter with strict structured output |
| `intel.py` | Indicator validation and bounded allowlisted report retrieval |
| `workflow.py` | SOC → intel → SOC orchestration and result assembly |
| `fallback.py` | Conservative rule-based results and request-local stage progress |

The route is `POST /investigate` on port 8000, with `x-nightwatch-service-key`
matching `AGENT_SERVICE_KEY`. The shared contract is
[`../web/contracts/investigation.schema.json`](../web/contracts/investigation.schema.json).
It is read directly at its existing relative path; keep the repository layout when
running the service. No shared contracts or other layers have been edited.

## Local setup

Use the existing Python 3.9.6 virtual environment. From the repository root:

```bash
agents/.venv/bin/python -m pip install -r agents/requirements-dev.txt
cd agents
.venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python -m pyright --pythonpath .venv/bin/python nightwatch_agents
```

Tests use in-process HTTP and mocked provider transports. They disable outbound
socket connections and clear provider configuration, so they cannot spend API
credits. They use the actual clinic replay sample, including its instruction-like
username and private source IP. Fixtures containing antivirus or reputation claims
are demo data and are never treated as real provider reports.

Pyright is included in development dependencies to catch editor type errors as
well as runtime test failures. Stage completion explicitly rejects an absent active
stage, and IP recommendations explicitly reject failed address normalization before
parsing. `pytest.ini` also allows the Python suite to run from the repository root:
`agents/.venv/bin/python -m pytest agents/tests`.

For the separate HTTP integration suite, from the repository root:

```bash
npm ci --prefix agents/integration --ignore-scripts --no-audit --no-fund
npm test --prefix agents/integration
```

This requires Node compatible with the repository's Vitest 4 tooling (verified on
Node 24). Dependencies and the lockfile stay in `agents/integration/`; `web/` is
only read. Tests start and stop temporary Python services on loopback ports with
isolated environments, mock models and disabled external intelligence. No API key,
database or real execution is used. See [integration details](integration/README.md).

## Configuration and secrets

Git ignores `agents/.env`, `agents/.env.local` and `agents/.venv/` while allowing
`agents/.env.example`. Verify from the repository root before adding secrets:

```bash
git check-ignore agents/.env agents/.env.local agents/.venv/example
git check-ignore agents/.env.example  # prints nothing; exits 1
```

From `agents/`, copy `.env.example` to `.env` once, if `.env` does not already
exist. Set a randomly generated `AGENT_SERVICE_KEY` locally with your editor or
password manager. Use that same secret in the web backend. Never paste secrets
into chat, print them, commit `.env`, or put the OpenAI key in the web layer.

Keep `NIGHTWATCH_LIVE_CALLS_ENABLED=false` and leave `OPENAI_API_KEY` blank until
billing and the initial test allowance are confirmed in chat. Offline mode checks
this switch before reading provider keys or constructing a network client. It
returns a clearly labelled **analysis unavailable** result, undetermined verdict,
zero confidence, exact timestamped log observations when available, no action
recommendations and three skipped stages. Provisional severity
follows the highest supplied integer Wazuh rule level (7–9 medium, 10–11 high,
12+ critical, otherwise low). The injection heuristic still runs locally.

Start from `agents/`:

```bash
.venv/bin/python -m uvicorn nightwatch_agents.app:app --host 127.0.0.1 --port 8000 --env-file .env
```

Uvicorn loads `.env` only when explicitly passed. Service authentication is read
at startup; workflow configuration is read per request. During local integration,
ignored `agents/.env` and `web/.env.local` were configured with a matching generated
service credential. Its value was not displayed. Explicitly authorized live
OpenAI investigations were later tested as documented below. VirusTotal remains
disabled and has not been queried live.

## Model and spending limits

Official documentation checked November 7, 2026:

- Default `OPENAI_MODEL=gpt-5.4-mini-2026-03-17`; the verified alias
  `gpt-5.4-mini` is also accepted. Other model IDs are rejected until their pricing
  and parameters are reviewed in code.
- Listed standard price: US$0.75 per million input tokens, US$4.50 per million
  output tokens. Account access and billing remain unverified.
- Responses API, `reasoning.effort="none"`, strict `text.format` JSON Schema,
  `store=false`, no model tools, no conversation history, no retries.
- At most two calls per investigation, 1,800 output tokens per call,
  24,000 bytes per input including instructions/schema, 128,000 response bytes,
  and a 25-second wall deadline per model call. Fixed endpoint:
  `https://api.openai.com/v1/responses`; redirects and environment proxies disabled.

Sources: [model, pricing and supported effort](https://developers.openai.com/api/docs/models/gpt-5.4-mini),
[Responses structured output](https://developers.openai.com/api/docs/guides/structured-outputs).

These are per-investigation limits, **not an account-wide US$5 spending cap**.
Replay can trigger multiple investigations and reruns, so do not begin with a live
replay. First agree a small initial allowance within the approximately US$5 total,
confirm billing, then test one explicit request and check actual API usage before
expanding. The single authorized check below verified model access and one sample;
broader quality, reliability and latency testing remains.

### Authorized single-request smoke test

One investigation was tested against OpenAI using only the repository clinic
sample, with a US$0.25 allowance. Both SOC stages succeeded (two HTTP 200 responses),
the intel stage was skipped, and the shared contract, exact evidence quotes and
action targets passed validation. Elapsed time was 5.8 seconds. Reported usage:
8,443 input tokens and 709 output tokens, estimated US$0.009523 at standard uncached
rates. This is a token-based estimate, not verification of the account invoice.
One successful sample is not a broad quality or reliability evaluation.

The reusable command is `tools/live_smoke.py`. Its default workflow is separate
from web ingestion and never saves results to the database or executes actions:

```bash
# From agents/: local check only, no provider calls.
.venv/bin/python tools/live_smoke.py --check
```

The paid form additionally requires `--live --budget-usd 0.25`. Do not run it again
without a new explicit live-test authorization. It restricts traffic to the
OpenAI Responses endpoint, at most two requests, the verified model snapshot,
no retries, disabled intelligence, and a planning estimate below the allowance.
It reads the existing key only inside the process, never displays or writes it,
and never enables the persistent service's live-call flag. No result artifact is
saved. Automatic model calls remain disabled in the local configuration.

### Authorized dashboard investigation

A second separately authorized investigation was verified through real web
ingestion, the Python HTTP service, OpenAI, backend persistence and dashboard
rendering. Four clinic alerts were posted as one batch using an isolated demo
host label, so they did not mix with the earlier replay's records. The result was
stored as Northfield `INC-0006`, with both SOC stages succeeded, intel skipped,
validated evidence, Replay labelling and the injection warning rendered.

This used two HTTP 200 model requests, 8,356 input tokens and 637 output tokens;
estimated standard-rate cost US$0.009133. Total elapsed time through the backend
was 10.76 seconds. Combined estimate for both authorized investigations is
US$0.018656, below the US$0.25 initial allowance. These are estimates, not invoice
reconciliation or authorization for additional calls.

The backend applied policy: `block_ip` for the observed source address is
`awaiting_approval`. `notify_only` completed via simulation with `verified=false`
and an explicit message that nothing was changed. The block was initially left pending
for the user to review and approve manually. The user subsequently approved it;
the saved block result is `succeeded`, `verified=false`, with an explicit
"Simulation only: nothing was changed" message. No real endpoint block occurred.

`tools/live_dashboard.py` implements the isolated test. It permits at most one
investigation whose four alerts exactly match its prepared sample; the slot is
consumed before any asynchronous model work, including on failures/cancellation.
Other or repeated requests get offline fallback. Eight offline tests cover scope,
concurrency and failure/cancellation behavior; the Python suite now has 110 tests.
The temporary service is stopped and the original backend URL restored on exit.
Persistent live-call flags remain false; external intelligence remains disabled.
Never rerun its `--live` command without a new explicit authorization.

## Evidence, injection and recommendations

All log content and earlier model outputs are treated as untrusted data. A
best-effort heuristic detects patterns such as `ignore_previous_instructions`;
absence of a match does not establish safety. The prompt reinforces the trust
boundary; output validation remains necessary.

The SOC sees at most 20 events, 32 scalar fields per event, 400 characters per
field, and 10,000 bytes of field records. Oversized fields are omitted rather than
partially quoted. Omission is labelled in the final result. Events without valid
timestamps can provide context but cannot be cited as evidence.

Model evidence must quote an exact substring at a server-supplied JSON pointer
into the original request. The service supplies source (`wazuh`) and normalized
timestamp; invented references, quotations and arbitrary provider evidence are
rejected. MITRE tags come from Wazuh rule metadata, not model-generated IDs.
Interpretive model prose still requires human judgment; exact quotations verify
provenance, not every inference in a summary.

Only `notify_only` (target this incident ID) and `block_ip` recommendations are
enabled in this increment. Block targets must be observed source IPs and must not
match any supplied clinic asset address or an unsafe address class. Internal lab
attacker IPs may be recommended for blocking but are never sent for public IP
reputation. The backend independently checks real assets, protected IPs and policy.
The service executes nothing. Other action types remain part of the unchanged
shared contract and can be added later with target validation.

## Controlled enrichment

`NIGHTWATCH_INTEL_ENABLED=false` is the default, independent of the model switch.
Both switches must be enabled, with a local `VIRUSTOTAL_API_KEY`, for external intel.
Do not enable while using sensitive indicators: VirusTotal states that queried
IPs/domains may be scanned and added to its community dataset.

The service only performs fixed-host GET report requests for validated source IPs,
explicit SHA-256 fields, and `data.domain`/`data.query` domains. It does not browse
log URLs, fetch attacker hosts, upload files or request scans. Private, loopback,
link-local, multicast, documentation and other non-global IPs are skipped, as are
known asset IPs and reserved/internal domain suffixes. IPv4-mapped/transition IPv6
addresses are conservatively skipped. This is a deliberately narrow extractor;
indicators embedded only inside arbitrary command text may be missed.

At most 12 extracted indicators are considered and three GETs are attempted,
with four seconds per lookup, zero retries and no redirects. Provider identity,
counts and analysis timestamp are checked before generating evidence. Missing
keys, disabled providers, missing reports, malformed replies, rate limits and
timeouts are **unavailable**, never clean or malicious. Historical provider counts
are rendered by code with the report's analysis time and retrieval time. The SOC
does not author provider evidence. Common provider/reputation claims in model prose
are rejected; validated provider summaries are appended by the service instead.

Provider sources: [IP reports and dataset inclusion](https://docs.virustotal.com/reference/ip-info),
[IP report fields](https://docs.virustotal.com/reference/ip-object),
[file reports](https://docs.virustotal.com/reference/file-info),
[domain reports and dataset inclusion](https://docs.virustotal.com/reference/domain-info).

## Failure handling and remaining phases

The HTTP boundary rejects missing/blank startup credentials, invalid auth (401),
malformed JSON (400), contract violations (422), unsupported content types (415),
and bodies over 2 MiB (413). Input/output validation does not coerce types, and
date-time formats are explicitly checked. Errors omit request and provider values.
The workflow has a 65-second deadline, leaving time to assemble and validate a
fallback within the HTTP boundary's 75 seconds and the backend's 90 seconds.

**Phase 3 is implemented:** disabled live calls, missing keys, unsupported model
configuration, model authentication/rate-limit/transport errors, refusals,
incomplete or invalid output, fabricated evidence, unsafe recommendations and
workflow deadline exhaustion return a validated **Fallback analysis (rule-based)**
result. Authenticated, schema-valid requests receive HTTP 200 for these outcomes;
the summary and stage records distinguish a fallback from a completed AI analysis.
Authentication and malformed/invalid input still return the appropriate HTTP 4xx.
If fallback construction itself unexpectedly fails, the request can still fail;
fallback is not a guarantee against process failure or a broken shared contract.

Fallback always reports `undetermined`, zero confidence, provisional severity
from supplied rule levels, and no action recommendations. It retains only exact
timestamped log observations and previously validated evidence, including provider
reports completed before a later SOC failure. No AI conclusion or action from a
rejected/partial model response survives. Missing or invalid log timestamps are
never replaced with invented observation times. Empty evidence is explicitly labelled.
Instruction detection and context-omission notices still apply.

Completed stage records survive; the interrupted/failed stage is `failed` and
later unstarted stages are `skipped`. Failed model stages retain the configured
model ID; deterministic intel has `model=null`. A configuration failure before
any model runs records three skipped stages. Raw provider errors and generated
failure text are never copied into output. There are no failure retries or extra
model calls. Client/task cancellation propagates and stops work.

An unexpected intel-stage exception is contained: intel is `failed`, enrichment
is unavailable, and the SOC can still finish using local observations. The normal
provider adapter also reports individual missing/failed lookups as unavailable.
If the outer HTTP deadline or final service-output validation is the failure point,
it returns a fresh validated fallback. That boundary cannot reliably recover stage
progress, so it returns `agent_runs=[]` and explicitly labels outcomes unavailable
rather than asserting that a particular model stage ran or succeeded.

**Phase 4 is partially verified:** seven isolated integration checks exercise the
actual `web/lib/nightwatch/investigate.ts`, backend AJV contract validator and policy
code over real HTTP against the Python service, using the clinic replay sample.
They verify request/context assembly, successful mock analysis, offline and invalid-output
fallbacks, service authentication, organization scoping and the awaiting-approval
policy handoff. Persistence/audit/incident refresh are test doubles and no executor
is scheduled. This is not a database transaction or browser test.

The local offline stack was subsequently verified on November 7, 2026: MySQL 8.4
healthy, demo login successful, Python service on loopback port 8000, and all four
clinic replay alerts accepted by the real ingest endpoint. Northfield incident
`INC-0005` stored the labelled fallback, critical rule-based severity, undetermined
verdict, zero confidence, injection detection, evidence and skipped model stages.
The authenticated dashboard page returned HTTP 200 and rendered the Replay label,
fallback summary, injection warning, evidence and agent stages. Two investigations
ran as higher-severity alerts arrived; repeated stage/evidence records are expected
with the backend's append-only investigation history. No actions were created.

Local ignored web configuration now points to `http://127.0.0.1:8000` with the
matching shared service credential and `EXECUTOR_MODE=simulate`. Tracked web source
files were not changed by the agent implementation. Real Wazuh ingestion and
endpoint response verification remain. The first OpenAI check above verified a sample separately from
web ingestion; the second verified a live result persisted and rendered as
`INC-0006`. The earlier `INC-0005` still displays its offline fallback result.

On November 8, 2026, `faran/ai-agents` was fast-forwarded to teammate website
updates at `ba148f8` without switching branches or overwriting agent work. The
reviewed `004_add_org_contact_phone.sql` migration was applied to the existing
local demo database without a reset. Verification passed: 110 Python tests,
seven isolated HTTP integration tests, eight runnable web tests (34 DB-dependent
tests skipped), Pyright and TypeScript checks. A fresh real-stack offline replay
created `INC-0007`; its fallback, Replay label and injection flag persisted and
rendered. `INC-0006` retained the approved simulated block result. No additional
OpenAI calls were made. Local `.env` files and dependency directories remain ignored.

**Phase 5 remains:** finalize dependency/run instructions and handoff after
integration is verified. Then walk through local testing, adding the already-generated
API key safely and the clinic replay/demo flow. The local key setup and first
budget-approved live test have now been walked through; never share the key in
chat, copy it into another file, or enable automatic paid calls without explicit
authorization. No branch switches, agent commits or pushes were performed.
