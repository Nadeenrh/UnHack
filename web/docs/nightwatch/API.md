# Nightwatch API (v1)

Base path `/api/v1`. Types live in [`contracts/types.ts`](../../contracts/types.ts).

**Envelope:** every response is `{ "success": true, "data": … }` or `{ "success": false, "message": "…", "code": "…" }`. Show `message` to people; it's written for them.

**Auth:** sign in once and the browser keeps an HttpOnly `nw_session` cookie. Same-origin `fetch` sends it automatically; never read or store a token yourself. Writes (`POST`/`PUT`) must come from the same site (Origin check), which plain same-origin `fetch` already does.

**Status codes:** `401` not signed in · `403` signed in but not allowed (e.g. a viewer approving) · `404` not found *or* not yours (deliberately identical) · `409` the thing changed under you (already decided, expired, target changed): refresh and show the latest · `429` too many sign-in attempts.

## Auth

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | `/auth/login` | `{ email, password }` | `{ user, memberships[], expires_at }` + sets cookie |
| POST | `/auth/logout` | none | `null`, session revoked server-side |
| GET | `/auth/me` | none | `{ user, memberships[], expires_at }` |
| POST | `/auth/register` | `{ organization: { name, sector }, user: { first_name, last_name, email, password } }` | same as login, plus `organization` and `first_site.ingest_key` (**shown once**) |

`sector`: `small_business`, `healthcare`, `community_org`, `municipality`, `utility`, `other`. Password: 12+ characters. `user.platform_role` is `none` for clients, `provider_staff` / `provider_admin` for us.

**Server components:** `const session = await getServerSession()` from `@/lib/nightwatch/auth` (returns `null` when signed out). Redirect to the login page when it's null.

## Client portal (org-scoped)

Roles: `viewer` and `analyst` read · `approver` also approves/denies · `owner` also changes policies and keys.

| Method | Path | Who | Returns |
|---|---|---|---|
| GET | `/orgs` | any member | `[{ id, name, slug, sector, plan, role }]` (org switcher) |
| GET | `/orgs/:orgId` | read | `ProviderOrgSnapshot` + `access` (the dashboard: health, counts, assets, recent incidents) |
| GET | `/orgs/:orgId/incidents?status=open\|closed\|all&limit=50` | read | `Incident[]`, newest first |
| GET | `/orgs/:orgId/incidents/:incidentId` | read | `Incident` |
| POST | `/orgs/:orgId/actions/:actionId/approve` | approver, owner | `{ target }` → updated `Incident` |
| POST | `/orgs/:orgId/actions/:actionId/deny` | approver, owner | `{ target, reason? }` → updated `Incident` |
| GET | `/orgs/:orgId/audit?limit=100&incident_id=` | read | `AuditEvent[]`, newest first |
| GET | `/orgs/:orgId/assets` | read | `MonitoredAsset[]` |
| GET | `/orgs/:orgId/policies` | read | `[{ action_type, risk, mode, auto_allowed, updated_at }]` |
| PUT | `/orgs/:orgId/policies` | owner | `{ action_type, mode }` → full list. `auto` only allowed where `auto_allowed` |
| GET | `/orgs/:orgId/sites` | read | `[{ id, name, ingest_key_prefix, active, created_at }]` |
| POST | `/orgs/:orgId/sites/:siteId/rotate-key` | owner | `{ ingest_key }` (**shown once**) |

### Approving, the UI rule

Send back the **exact `target` the person saw** on the card. If anything changed (target, someone else decided, it expired), the API answers `409`; re-fetch the incident and show the new state. After an approval the action shows `approved`, then `executing`, then `succeeded`/`failed` within a few seconds, so poll the incident every ~2s while an action is `approved` or `executing`.

Show `result.verified`: `true` means the platform checked the effect; `false` means delivered but not independently confirmed (and in simulate mode, nothing was changed; `result.detail` says so).

## Provider portal

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/provider/overview` | none | `ProviderOrgSnapshot[]`, one per client (the collapsible cards) |
| POST | `/provider/orgs/:orgId/support-sessions` | `{ reason }` (5+ chars) | `{ id, expires_at, read_only: true }` |
| POST | `/provider/support-sessions/:sessionId/end` | none | `{ ended: true }` |

The overview is status-level only. To open a client's full workspace, start a support session; then the normal `/orgs/:orgId/...` GET routes work for 30 minutes, **read-only**. The client sees `support_session_started` (with your reason) in their audit log.

## Ingest (machine to machine)

`POST /ingest/wazuh` with `Authorization: Bearer <site ingest key>`. The body is one Wazuh alert, an array, or `{ "alerts": [...] }` (max 500, 5 MB). No cookie. The key alone decides the org. Optional `X-Nightwatch-Replay: 1` labels the resulting incidents `replay`.

Returns `{ received, stored, duplicates, ignored, incidents: [{ id, ref, created }] }`. Alerts at or above `INGEST_MIN_LEVEL` (default 7) open or join an incident on the same machine (30-minute window); lower ones are kept as context for the agents.

Replay recorded alerts: `node tools/replay/replay.mjs tools/replay/samples/cityhall-attack.json --key <ingest key> --fresh --gap 1500`

## Agent service (contract for the Python service)

The platform calls `POST {AGENT_SERVICE_URL}/investigate` with an `InvestigationRequest` and expects an `InvestigationResult` back; both are defined in [`contracts/investigation.schema.json`](../../contracts/investigation.schema.json). The reply is schema-validated; anything invalid is rejected and logged as `investigation_failed`. Optional header `X-Nightwatch-Service-Key` = `AGENT_SERVICE_KEY`.

Recommended actions are re-checked before policy sees them: block_ip can't target the org's own machines, loopback/multicast or `NIGHTWATCH_PROTECTED_IPS`; isolate_host must be a machine in this incident; file hashes must be SHA-256. Refused ones are logged as `recommendation_rejected` with the reason.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` | none | MySQL (`DB_NAME=nightwatch`) |
| `EXECUTOR_MODE` | `simulate` | `simulate` changes nothing and says so; `wazuh` uses active response |
| `EXECUTOR_SIMULATE_DELAY_MS` | `1500` | how long a simulated action "runs" |
| `WAZUH_API_URL` `WAZUH_API_USER` `WAZUH_API_PASSWORD` | none | for `EXECUTOR_MODE=wazuh` |
| `WAZUH_TLS_INSECURE` | `false` | `true` accepts Wazuh's self-signed cert (lab only) |
| `AGENT_SERVICE_URL` `AGENT_SERVICE_KEY` `AGENT_SERVICE_TIMEOUT_MS` | none / none / `90000` | the Python agent service |
| `INGEST_MIN_LEVEL` | `7` | Wazuh rule level that opens an incident |
| `NIGHTWATCH_PROTECTED_IPS` | none | comma list that can never be blocked (e.g. gateway, DNS) |
