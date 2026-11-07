# Nightwatch web (layer 3)

The website: a client portal for small businesses and clinics, a provider portal for our team, and the API that takes in Wazuh alerts, asks the AI agents, and runs approved responses. How it talks to the other layers: [`../docs/INTERFACES.md`](../docs/INTERFACES.md).

## Run it

Fastest (database in Docker, app on your machine with hot reload):

```bash
cp .env.example .env.local              # set DB_PASSWORD
docker compose --env-file .env.local -f docker-compose-dev.yml up -d db
npm install
npm run dev                             # http://localhost:3000
```

No Node on your machine? Run both in Docker:

```bash
docker compose --env-file .env.local -f docker-compose-dev.yml --profile app up -d --build
```

Production-style (small standalone image, non-root):

```bash
cp .env.example .env.production         # real values
docker compose --env-file .env.production -f docker-compose-prod.yml up -d --build
```

Demo logins and ingest keys: [`db/nightwatch/README.md`](db/nightwatch/README.md). Replay a sample attack:

```bash
node tools/replay/replay.mjs tools/replay/samples/clinic-attack.json \
  --url http://localhost:3000 --key nwk_dev_northfield_0001 --fresh --gap 1500
```

Live alerts from a Wazuh manager: [`../wazuh/integration/`](../wazuh/integration/README.md).

## Where things are

| Path | What |
|---|---|
| `app/(auth)/`, `app/(portal)/`, `components/` | Pages and UI: sign-in, client portal, provider portal |
| `app/api/v1/` | The API ([docs/nightwatch/API.md](docs/nightwatch/API.md)) |
| `lib/nightwatch/` | Auth, access rules, ingest, AI investigation, policy, Wazuh executor |
| `contracts/` | Shapes shared with the agents layer (JSON Schema + TS types) |
| `db/nightwatch/` | Schema, demo data, manual reset |
| `tools/replay/` | Replays saved Wazuh alerts into the site |
| `tools/fixtures/` | Regenerates the demo database data |
| `tests/` | Unit and integration tests |

## Tests

```bash
npm test                                             # unit tests; integration tests skip without a DB
NW_TEST_DB=1 DB_HOST=127.0.0.1 DB_PORT=3306 DB_USER=root DB_PASSWORD=... npm test   # + integration
```

Integration tests create and drop a database called `nightwatch_test`. Never point them at real data.

## Not built yet

- The AI agent service (`../agents/`). Without `AGENT_SERVICE_URL`, incidents still open and are labelled "investigation skipped".
- Wazuh executor: tested against a fake Wazuh API only. Only `block_ip` is automated; other actions say "do this manually".
- Email verification, password reset, inviting teammates to an org.
- Login throttling is in memory (fine for one server).
