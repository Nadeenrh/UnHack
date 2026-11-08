#!/usr/bin/env node
// Replay recorded Wazuh alerts into Nightwatch. Demo fallback when the live lab misbehaves:
// the alerts are real recordings, and everything after ingestion (agents, approval,
// executor, audit) still runs live.
//
//   node tools/replay/replay.mjs <alerts.json|alerts.jsonl> --url http://localhost:3000 --key <ingest key> [--fresh] [--gap 1500]
//
//   --fresh     give alerts new ids and stamp each one with the time it is sent, so the same file
//               can be replayed repeatedly (otherwise duplicates are ignored by design)
//   --gap ms    wait between alerts so the dashboard visibly updates (default 0)
//
// Alerts arrive marked as replay (X-Nightwatch-Replay: 1) and the UI labels them that way.
// Record your own from the Wazuh manager: /var/ossec/logs/alerts/alerts.json (one JSON per line).

import { readFileSync } from "node:fs";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--") && !/^\d+$/.test(a) && !args[args.indexOf(a) - 1]?.startsWith("--"));
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const url = opt("url", "http://localhost:3000");
const key = opt("key", process.env.NIGHTWATCH_INGEST_KEY);
const gap = Number(opt("gap", 0));
const fresh = args.includes("--fresh");

if (!file || !key) {
  console.error("usage: node tools/replay/replay.mjs <alerts.json|jsonl> --key <ingest key> [--url ...] [--fresh] [--gap ms]");
  process.exit(1);
}

const text = readFileSync(file, "utf8").trim();
let alerts = text.startsWith("[") ? JSON.parse(text) : text.split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));

if (fresh) {
  const run = Date.now().toString(36);
  alerts = alerts.map((a) => ({ ...a, id: `${a.id ?? "alert"}-${run}` }));
}

for (const [i, alert] of alerts.entries()) {
  // --fresh stamps each alert at the moment it is sent, like a live Wazuh feed, so the timeline
  // matches what the audience watches and "caught in N seconds" on the incident page is real.
  if (fresh) alert.timestamp = new Date().toISOString();
  const res = await fetch(new URL("/api/v1/ingest/wazuh", url), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${key}`, "x-nightwatch-replay": "1" },
    body: JSON.stringify(alert),
  });
  const body = await res.json().catch(() => ({}));
  const inc = body?.data?.incidents?.map((x) => `${x.ref}${x.created ? " (new)" : ""}`).join(", ") || "-";
  console.log(`${i + 1}/${alerts.length}  HTTP ${res.status}  level ${alert.rule?.level ?? "?"}  ${alert.rule?.description ?? ""}  -> ${inc}`);
  if (!res.ok) process.exitCode = 1;
  if (gap && i < alerts.length - 1) await new Promise((r) => setTimeout(r, gap));
}
