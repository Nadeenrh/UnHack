import { AGENT_LABEL, capitalize, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { StatTile } from "@/components/ui/StatTile";
import { iso, one, rows } from "@/lib/nightwatch/db";
import { DEMO, DEMO_MODEL } from "@/lib/nightwatch/demo";
import { requirePageProvider } from "@/lib/nightwatch/page-auth";

export const metadata = { title: "AI agents" };
export const dynamic = "force-dynamic";

type Role = "soc" | "intel";
const ROLE: Record<Role, { name: string; job: string; from: string; to: string; icon: string }> = {
  soc: {
    name: "SOC Analyst",
    job: "Triage and investigation",
    from: "#2dd4bf",
    to: "#1e40af",
    icon: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z M9.5 11.5a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0 M14 14l2 2",
  },
  intel: {
    name: "Threat Intel",
    job: "VirusTotal lookups",
    from: "#fb7185",
    to: "#7c3aed",
    icon: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-4-4 M8 11h6 M11 8v6",
  },
};

type Num = number | string | null;
type AgentRow = { role: Role; runs: Num; ok: Num; failed: Num; skipped: Num; avg_ms: Num; last_at: Date | null; model: string | null };
type OrgRow = { org_id: string; name: string; investigations: Num; ok: Num; failed: Num; avg_ms: Num; last_at: Date | null; injections: Num };
type RecentRow = { run_id: string; agent: string; status: string; started_at: Date; output_summary: string | null; ref: string; org: string };

const n = (v: Num | undefined) => Number(v ?? 0);
const showModel = (m: string | null) => (m && !m.includes("fixture") ? m : DEMO ? DEMO_MODEL : null);
const seconds = (ms: Num) => (ms == null ? "None yet" : n(ms) < 1000 ? "< 1 s" : `${(n(ms) / 1000).toFixed(1)} s`);

/** Is the agent service answering right now? Short timeout so the page never hangs on it. */
async function serviceStatus(): Promise<"online" | "offline" | "not_configured"> {
  const url = process.env.AGENT_SERVICE_URL;
  if (!url) return DEMO ? "online" : "not_configured";
  try {
    const res = await fetch(new URL("/openapi.json", url), { signal: AbortSignal.timeout(1500), cache: "no-store" });
    return res.ok ? "online" : "offline";
  } catch {
    return "offline";
  }
}

export default async function ProviderAgents() {
  await requirePageProvider();

  const [status, agents, orgs, guard, recent] = await Promise.all([
    serviceStatus(),
    rows<AgentRow>(
      `SELECT CASE WHEN agent = 'intel' THEN 'intel' ELSE 'soc' END AS role,
              COUNT(*) AS runs, SUM(status = 'succeeded') AS ok, SUM(status = 'failed') AS failed, SUM(status = 'skipped') AS skipped,
              AVG(CASE WHEN status = 'succeeded' THEN TIMESTAMPDIFF(MICROSECOND, started_at, finished_at) END) / 1000 AS avg_ms,
              MAX(finished_at) AS last_at,
              SUBSTRING_INDEX(GROUP_CONCAT(CASE WHEN status = 'succeeded' THEN model END ORDER BY finished_at DESC SEPARATOR '|'), '|', 1) AS model
         FROM agent_runs GROUP BY role`
    ),
    rows<OrgRow>(
      `SELECT o.org_id, o.name,
              COUNT(DISTINCT r.incident_id) AS investigations,
              SUM(r.status = 'succeeded' AND r.agent <> 'intel') AS ok,
              SUM(r.status = 'failed' AND r.agent <> 'intel') AS failed,
              AVG(CASE WHEN r.status = 'succeeded' THEN TIMESTAMPDIFF(MICROSECOND, r.started_at, r.finished_at) END) / 1000 AS avg_ms,
              MAX(r.finished_at) AS last_at,
              (SELECT COALESCE(SUM(i.injection_detected), 0) FROM incidents i WHERE i.org_id = o.org_id) AS injections
         FROM organizations o LEFT JOIN agent_runs r ON r.org_id = o.org_id
        GROUP BY o.org_id, o.name ORDER BY investigations DESC, o.name`
    ),
    one<{ rejected: Num; human: Num; policy: Num; denied: Num; injections: Num }>(
      `SELECT SUM(event = 'recommendation_rejected') AS rejected, SUM(event = 'action_approved') AS human,
              SUM(event = 'action_auto_approved') AS policy, SUM(event = 'action_denied') AS denied,
              (SELECT COALESCE(SUM(injection_detected), 0) FROM incidents) AS injections
         FROM audit_log`
    ),
    rows<RecentRow>(
      `SELECT r.run_id, r.agent, r.status, r.started_at, r.output_summary, i.ref, o.name AS org
         FROM agent_runs r JOIN incidents i ON i.incident_id = r.incident_id AND i.org_id = r.org_id
         JOIN organizations o ON o.org_id = r.org_id
        ORDER BY r.started_at DESC LIMIT 10`
    ),
  ]);

  const by = new Map(agents.map((a) => [a.role, a]));
  const soc = by.get("soc");
  const aiOk = n(soc?.ok);
  const aiFailed = n(soc?.failed);
  const rate = aiOk + aiFailed ? Math.round((aiOk / (aiOk + aiFailed)) * 100) : null;
  const investigations = orgs.reduce((t, o) => t + n(o.investigations), 0);

  const STATUS = {
    online: ["bg-ok-soft text-ok", "bg-ok", "Agent service online"],
    offline: ["bg-bad-soft text-bad", "bg-bad", "Agent service not answering: rule-based checks only"],
    not_configured: ["bg-raised text-muted", "bg-muted", "Agent service not configured"],
  }[status];

  return (
    <>
      <PageHeader title="AI agents" subtitle="How the AI analysts are doing across every client: what they worked on, how fast, and every time a guardrail stepped in.">
        <span className={`inline-flex items-center gap-2 rounded-md px-2.5 py-1 text-sm font-medium ${STATUS[0]}`}>
          <span className={`size-2 rounded-full ${STATUS[1]} ${status === "online" ? "animate-pulse" : ""}`} />
          {STATUS[2]}
        </span>
      </PageHeader>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        <StatTile tone="info" value={investigations} label="Incidents investigated, all clients" />
        <StatTile tone={rate == null || rate >= 90 ? "ok" : "high"} value={rate == null ? "None yet" : `${rate}%`} label="AI steps that passed validation" />
        <StatTile tone={n(guard?.injections) ? "lantern" : "quiet"} value={n(guard?.injections)} label="Attempts to trick the AI, caught" />
        <StatTile tone={aiFailed ? "high" : "quiet"} value={aiFailed} label="Fell back to rule-based checks" />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {(Object.keys(ROLE) as Role[]).map((r) => (
          <AgentRowCard key={r} role={r} a={by.get(r)} />
        ))}
      </div>

      <div className="mt-6 space-y-6">
        <Panel title="By client">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-muted">
                <tr className="border-b border-line">
                  <th className="px-5 py-2.5 font-medium">Client</th>
                  <th className="px-3 py-2.5 text-right font-medium">Investigated</th>
                  <th className="px-3 py-2.5 text-right font-medium">Passed</th>
                  <th className="px-3 py-2.5 text-right font-medium">Avg step</th>
                  <th className="px-3 py-2.5 text-right font-medium">Tricks caught</th>
                  <th className="px-5 py-2.5 text-right font-medium">Last active</th>
                </tr>
              </thead>
              <tbody>
                {orgs.map((o) => {
                  const done = n(o.ok) + n(o.failed);
                  return (
                    <tr key={o.org_id} className="border-b border-line last:border-0">
                      <td className="px-5 py-3 font-medium">{o.name}</td>
                      <td className="px-3 py-3 text-right tabular-nums">{n(o.investigations)}</td>
                      <td className={`px-3 py-3 text-right tabular-nums ${n(o.failed) ? "text-sev-high" : ""}`}>{done ? `${Math.round((n(o.ok) / done) * 100)}%` : "-"}</td>
                      <td className="px-3 py-3 text-right tabular-nums">{o.avg_ms == null ? "-" : seconds(o.avg_ms)}</td>
                      <td className={`px-3 py-3 text-right tabular-nums ${n(o.injections) ? "font-semibold text-lantern-deep" : ""}`}>{n(o.injections)}</td>
                      <td className="px-5 py-3 text-right whitespace-nowrap text-muted">{o.last_at ? timeAgo(iso(o.last_at)) : "Not yet"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Guardrails">
          <ul className="grid text-sm sm:grid-cols-2 xl:grid-cols-3 [&>li]:border-b [&>li]:border-line">
            <Guard title="Every claim is checked against the logs" detail="The AI must quote the exact log line for each piece of evidence. Anything it can't back up is thrown out." />
            <Guard title="Only blocks addresses it actually saw" detail="A block must target an address from the logs, and never the client's own network." />
            <Guard
              title="A person or the client's policy decides"
              detail={`${n(guard?.human)} approved by a person, ${n(guard?.policy)} by policy, ${n(guard?.denied)} denied.`}
            />
            <Guard title="Unsafe recommendations refused" detail={`${n(guard?.rejected)} so far. Refused recommendations never reach the client.`} />
            <Guard title="Logs are data, never instructions" detail={`${n(guard?.injections)} attempts to trick the AI caught and treated as evidence.`} />
            <Guard title="Client data stays private" detail="Only file fingerprints, public IP addresses and domains are sent to VirusTotal. Never patient files or logs." />
          </ul>
        </Panel>
      </div>

      <div className="mt-6">
        <Panel title="Latest work, all clients">
          {recent.length ? (
            <ol>
              {recent.map((r) => (
                <li key={r.run_id} className="grid gap-1 border-b border-line px-5 py-3 last:border-0 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:gap-4">
                  <span className="text-sm text-muted">{timeAgo(iso(r.started_at))}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium">
                      {AGENT_LABEL[r.agent] ?? capitalize(r.agent)} <span className="font-normal text-muted">for {r.org}</span>
                    </p>
                    {r.output_summary && <p className="text-sm text-muted">{r.output_summary}</p>}
                  </div>
                  <div className="flex items-center gap-3 text-sm sm:justify-end">
                    <span className={r.status === "succeeded" ? "text-ok" : r.status === "failed" ? "text-bad" : "text-muted"}>{capitalize(r.status)}</span>
                    <span className="text-muted">{r.ref}</span>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <EmptyState title="No investigations yet">When a client&apos;s alert comes in, the agents get to work and their steps show up here.</EmptyState>
          )}
        </Panel>
      </div>
    </>
  );
}

function AgentRowCard({ role, a }: { role: Role; a?: AgentRow }) {
  const p = ROLE[role];
  const model = role === "intel" ? "VirusTotal API, no AI model" : showModel(a?.model ?? null) ?? "Rule-based fallback";
  return (
    <section className="rounded-lg bg-panel p-5 ring-1 ring-line">
      <div className="flex items-center gap-4">
        <span
          aria-hidden
          className="flex size-12 shrink-0 items-center justify-center rounded-xl text-white shadow-lg"
          style={{ background: `linear-gradient(135deg, ${p.from}, ${p.to})` }}
        >
          <svg viewBox="0 0 24 24" className="size-6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d={p.icon} />
          </svg>
        </span>
        <div className="min-w-0">
          <h2 className="text-lg font-semibold tracking-tight">{p.name}</h2>
          <p className="text-sm text-muted">
            {p.job}. {model}
          </p>
        </div>
      </div>
      <dl className="mt-4 grid grid-cols-4 gap-3 border-t border-line pt-4 text-center">
        <Stat label="Steps run" value={String(n(a?.runs))} />
        <Stat label={role === "intel" ? "Looked up" : "Passed"} value={String(n(a?.ok))} />
        <Stat label={role === "intel" ? "Nothing to check" : "Fell back"} value={String(role === "intel" ? n(a?.skipped) : n(a?.failed))} />
        <Stat label="Average" value={seconds(a?.avg_ms ?? null)} />
      </dl>
      <p className="mt-3 text-center text-xs text-muted">Last active {a?.last_at ? timeAgo(iso(a.last_at)) : "never"}</p>
    </section>
  );
}

function Guard({ title, detail }: { title: string; detail: string }) {
  return (
    <li className="flex gap-3 px-5 py-3">
      <svg aria-hidden viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0 text-ok" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <path d="m5 12 5 5L20 7" />
      </svg>
      <div>
        <p className="font-medium">{title}</p>
        <p className="mt-0.5 text-muted">{detail}</p>
      </div>
    </li>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5 text-lg font-semibold tabular-nums">{value}</dd>
    </div>
  );
}
