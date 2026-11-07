# Nightwatch contracts (v0.1)

The shapes every part of Nightwatch agrees on. The agents layer depends on them: change them with a PR and tell the other layers first.

| File | What it is | Who uses it |
|---|---|---|
| `incident.schema.json` | One incident as the platform API returns it | Frontend (both portals) |
| `investigation.schema.json` | Request/result between the platform and the agent service | Agent service (Python) |
| `types.ts` | TypeScript mirror of both | Next.js code |

Sample data that matches these lives in [`../fixtures/`](../fixtures).

## Rules baked into the contract

- **The server decides the organization.** `org` comes from the logged-in session (or, for ingestion, from the site's ingest key). A client never sends an org id that the server trusts.
- **Agents recommend, they don't decide.** The agent service returns `recommended_actions` with only a type, target and rationale. The platform's policy code sets `risk` and `policy_decision`. Only the executor, after the required approval, runs anything.
- **Approval is bound to what was reviewed.** An approval applies to one action id, in one organization, for one exact `target`. If the target changes, it is a new action and needs a new approval.
- **Every action state is distinct** in the UI: proposed, awaiting approval, approved, executing, succeeded, failed, denied, expired. `result.verified` is true only when the platform checked that the effect happened.
- **Label non-live data.** `data_source` is `live`, `replay` or `fixture`. The UI shows a visible label for anything that isn't live.
- **Logs are untrusted input.** Anything inside `alert` or `related_events` may be attacker-controlled. `injection_detected` is a best-effort flag, not a guarantee.

## Incident status vs action status

An incident's `status` is the overall case: open → investigating → awaiting approval → contained → resolved (or false positive). Each action inside it has its own status. An incident can be `contained` while one of its actions `failed`, and the UI should show both.
