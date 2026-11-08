# Backend / Python HTTP integration checks

Run from the repository root:

```bash
npm ci --prefix agents/integration --ignore-scripts --no-audit --no-fund
npm test --prefix agents/integration
```

Requires the Python development dependencies in `agents/.venv` and a Node runtime
compatible with Vitest 4 (verified on Node 24). Test listeners need permission to
bind loopback ports. The runner starts three Python subprocesses and stops them
after the suite. It does not load `.env` files or inherit API credentials into the
Python subprocesses. The shared credential is a test-only literal.

Real components exercised:

- Clinic sample from `web/tools/replay/samples/clinic-attack.json`.
- Backend request assembly and HTTP orchestration in `investigate.ts`.
- Backend AJV request/result validation from the shared JSON Schema.
- FastAPI authentication and investigation route over real loopback HTTP.
- Python offline fallback and workflow with explicit mock SOC responses.
- Backend recommendation vetting and policy decision code.

Test doubles replace database access, audit writes, incident status refresh and
execution scheduling. SQL statements/parameters are captured, not executed. The
mock success scenario proposes only `block_ip`; the real policy code returns
`ask`, producing an `awaiting_approval` write. Scheduling or executing an action
fails the test. Provider transports are disabled or mocked. No paid API calls occur.

The invalid-output scenario fabricates an evidence quote deliberately; the real
workflow must reject it, return fallback, preserve completed stage records and
recommend no actions. The test model labels successful output `MOCK`. Its factory
exists only in this test harness; the production service has no mock-response mode.
Never use `integration.fixture_service` to run the demo or production service.

Seven checks passed during development. These checks do **not** verify MySQL SQL
execution, the ingest route, replay labels in the dashboard, approval authorization,
the approval UI, or simulated executor results. Those require the full web stack.
The isolated suite was first run before Docker/MySQL was available. A later
offline replay through the actual local web/MySQL/Python stack is recorded in
the parent README; that check still does not verify interactive approvals or
real Wazuh execution. Do not point the web suite's database-reset harness at real data.
