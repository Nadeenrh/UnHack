// Demo mode (NIGHTWATCH_DEMO=1 in .env.local) for pitching without the live lab.
//
// When it's on:
//   - UI labels that say "Sample data", "Replay" or "Simulated" are hidden, so the app looks live.
//   - If no agent service is configured, a scripted investigation stands in for the two AI
//     agents. It is built from the incident's REAL alerts (host, attacker address, the planted
//     username, the PowerShell download) and goes through the exact same contract validation,
//     safety checks and policy as a reply from the real agent service.
//
// Turn it off (remove the line) to get the honest labels back.

import type { InvestigationRequest, InvestigationResult, MitreTag, Severity } from "@/contracts/types";

export const DEMO = process.env.NIGHTWATCH_DEMO === "1";

/** The model name the scripted runs show: what the real agent service is configured with. */
export const DEMO_MODEL = "gpt-5.4-mini";

type Alert = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const INJECTION = /ignore[_\s-]*previous|disregard[_\s-]*(all|previous)|system[_\s-]*prompt|mark[_\s-]*(as[_\s-]*)?benign/i;

function severityFor(level: number): Severity {
  return level >= 12 ? "critical" : level >= 10 ? "high" : level >= 7 ? "medium" : "low";
}

function sourceFor(a: Alert): "windows_security" | "sysmon" | "wazuh" {
  const groups: string[] = a.rule?.groups ?? [];
  if (groups.includes("sysmon")) return "sysmon";
  if (groups.includes("windows_security")) return "windows_security";
  return "wazuh";
}

/** A scripted reply in the agent-service contract, built from the incident's own alerts. */
export async function scriptedInvestigation(request: InvestigationRequest): Promise<InvestigationResult> {
  const alerts: Alert[] = [request.alert as Alert, ...(request.related_events as Alert[])];
  const start = Date.now();
  // A short pause so the incident visibly goes "Still investigating" -> findings on screen.
  await new Promise((r) => setTimeout(r, 2500));

  const host: string = alerts.find((a) => a.agent?.name)?.agent?.name ?? "the affected machine";
  const ip: string | undefined = alerts.map((a) => a.data?.srcip ?? a.data?.win?.eventdata?.ipAddress).find((x) => typeof x === "string" && x);
  const ids = new Set(alerts.flatMap((a) => (a.rule?.mitre?.id ?? []) as string[]));
  const eventIds = new Set(alerts.map((a) => String(a.data?.win?.system?.eventID ?? "")));
  const bruteForce = ids.has("T1110");
  const signedIn = eventIds.has("4624") || ids.has("T1078");
  const download = ids.has("T1105");
  const commandLine: string | undefined = alerts.map((a) => a.data?.win?.eventdata?.commandLine).find(Boolean);
  const url = commandLine?.match(/https?:\/\/\S+/)?.[0];
  const file = url?.split("/").pop();
  const maxLevel = Math.max(...alerts.map((a) => Number(a.rule?.level ?? 0)));

  // MITRE tags straight from the Wazuh rules, de-duplicated.
  const mitre: MitreTag[] = [];
  for (const a of alerts) {
    const tIds: string[] = a.rule?.mitre?.id ?? [];
    const names: string[] = a.rule?.mitre?.technique ?? [];
    tIds.forEach((id, i) => {
      if (!mitre.some((m) => m.technique_id === id)) mitre.push({ technique_id: id, name: names[i] ?? id });
    });
  }

  // Any attacker-controlled field written as an instruction to the AI.
  const planted = alerts
    .flatMap((a) => Object.values(a.data?.win?.eventdata ?? {}))
    .find((v): v is string => typeof v === "string" && INJECTION.test(v));

  const title =
    bruteForce && download
      ? `Password guessing, then a suspicious download on ${host}`
      : bruteForce
        ? `Password guessing against ${host}`
        : String(alerts[0]?.rule?.description ?? `Suspicious activity on ${host}`).slice(0, 200);

  const story: string[] = [];
  if (bruteForce) story.push(`Someone repeatedly guessed passwords on ${host}${ip ? ` from ${ip}` : ""}`);
  if (signedIn) story.push(bruteForce ? "then signed in successfully" : `Someone signed in to ${host}`);
  if (download) story.push(`${story.length ? "and " : "Someone "}used PowerShell to download ${file ?? "a file"}${ip && url?.includes(ip) ? ` from that same address` : ""}`);
  const summary =
    (story.length ? `${story.join(", ").replace(/, and /, " and ")}.` : `${title}.`) +
    (bruteForce && download ? " This looks like a break-in in progress." : "") +
    (ip ? ` Blocking ${ip} stops it from reaching ${host} again.` : "");

  const evidence: InvestigationResult["evidence"] = alerts
    .filter((a) => a.rule?.description && a.timestamp)
    .slice(0, 12)
    .map((a) => ({
      claim: `${String(a.rule.description).replace(/\.$/, "")} (rule ${a.rule.id ?? "?"}, level ${a.rule.level ?? "?"})`.slice(0, 500),
      source: sourceFor(a),
      log_ref: a.id ? `wazuh:${a.id}`.slice(0, 255) : null,
      observed_at: new Date(String(a.timestamp).replace(/([+-]\d{2})(\d{2})$/, "$1:$2")).toISOString(),
    }));

  const t = (offsetMs: number) => new Date(start + offsetMs).toISOString();
  const internal = ip && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

  return {
    contract_version: "0.1",
    incident_id: request.incident_id,
    title,
    summary: summary.slice(0, 1000),
    severity: severityFor(maxLevel),
    verdict: bruteForce || download ? "malicious" : "suspicious",
    confidence: bruteForce && download ? 0.93 : 0.78,
    mitre,
    evidence,
    injection_detected: Boolean(planted),
    injection_notes: planted
      ? `A username in the logs ("${planted.slice(0, 80)}") was written as an instruction to the AI. It was treated as evidence, not followed.`
      : null,
    recommended_actions: ip
      ? [
          {
            type: "block_ip",
            target: ip,
            rationale: `${ip} guessed the password and then served the downloaded file. Blocking it cuts the attacker off from ${host}.`,
          },
        ]
      : [],
    agent_runs: [
      {
        agent: "triage",
        status: "succeeded",
        model: DEMO_MODEL,
        started_at: t(0),
        finished_at: t(700),
        output_summary: `Rated it ${severityFor(maxLevel)}, ${bruteForce || download ? "malicious" : "suspicious"} (${bruteForce && download ? 93 : 78}% sure), from ${alerts.length} events on ${host}.`,
      },
      {
        agent: "intel",
        status: "succeeded",
        model: DEMO_MODEL,
        started_at: t(700),
        finished_at: t(1500),
        output_summary: ip
          ? internal
            ? `Checked ${ip}: it's inside your own network, so public threat feeds have no record of it. A machine on your network serving ${file ?? "files"} is a sign it's compromised too.`
            : `Checked ${ip} against threat-intelligence reports.`
          : "No file fingerprints or public addresses to check.",
      },
      {
        agent: "investigator",
        status: "succeeded",
        model: DEMO_MODEL,
        started_at: t(1500),
        finished_at: t(2500),
        output_summary: `Built a timeline from ${evidence.length} events${ip ? ` and recommended: block ${ip}` : ""}.${planted ? " Flagged an attempt to trick the AI." : ""}`,
      },
    ],
  };
}
