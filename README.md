# Nightwatch (UNHack 2026)

A security operations add-on for small and medium businesses, including small clinics, that can't staff a security team. Wazuh watches the machines, AI agents explain what happened in plain English, and a person approves anything disruptive.

## The 3 layers, one folder each

| Folder | Layer | What it does |
|---|---|---|
| [`wazuh/`](wazuh/) | 1. Detection | Wazuh collects logs from the clinic's machines, fires rules, blocks IPs when told to |
| [`agents/`](agents/) | 2. AI agents | SOC analyst + threat intel agents: read an incident, return a verdict and recommended actions |
| [`web/`](web/) | 3. Website | Client portal + provider portal, stores everything, asks a person before acting |

**Start here:** [`docs/INTERFACES.md`](docs/INTERFACES.md) says exactly how the layers talk: formats, ports, keys. Keep your layer matching it.

## Run the website

```bash
cd web
cp .env.example .env.local      # set DB_PASSWORD
docker compose --env-file .env.local -f docker-compose-dev.yml up -d db
npm install
npm run dev                     # http://localhost:3000
```

Demo login and keys are in [`web/db/nightwatch/README.md`](web/db/nightwatch/README.md). Fake an attack with:

```bash
node tools/replay/replay.mjs tools/replay/samples/clinic-attack.json --url http://localhost:3000 --key nwk_dev_northfield_0001 --fresh --gap 1500
```

## Rules for this repo

- Never commit `.env.local` or any real password or API key.
- Work on your own branch, merge through a pull request.
- Changing anything in `docs/INTERFACES.md` or `web/contracts/`? Tell the other two layers first.
