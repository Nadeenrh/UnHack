import Link from "next/link";
import { AGENT_LABEL, capitalize, timeAgo } from "@/components/format";
import { EmptyState, PageHeader, Panel } from "@/components/ui/Panel";
import { iso, rows } from "@/lib/nightwatch/db";
import { requirePageOrg } from "@/lib/nightwatch/page-auth";

export const metadata = { title: "AI agents" };

type Role = "soc" | "intel";

// Who each agent is, what it reads, and what it is never allowed to do. The "never" lines
// match how the system is built: agents only recommend, policy and a person decide.
const PROFILES: Record<
  Role,
  { name: string; role: string; does: string; looksAt: string[]; never: string; icon: string; from: string; to: string }
> = {
  soc: {
    name: "SOC Analyst",
    role: "Investigates every alert",
    does: "Reads the alert and everything else that happened on that machine around it, works out what happened and how serious it is, and recommends what to do, in plain words.",
    looksAt: ["Wazuh alerts", "Windows sign-ins", "Sysmon process logs", "MITRE ATT&CK"],
    never: "Never blocks, isolates or changes anything itself. It recommends; your policy and a person decide.",
    icon: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z M9.5 11.5a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0 M14 14l2 2",
    from: "#2dd4bf",
    to: "#1e40af",
  },
  intel: {
    name: "Threat Intel",
    role: "Checks what's already known to be bad",
    does: "Takes the file fingerprints, internet addresses and websites in an incident and checks them against threat-intelligence reports, so the analyst knows if they're known to be malicious.",
    looksAt: ["VirusTotal", "File fingerprints", "Public IP addresses", "Web domains"],
    never: "Never sends patient files, logs or private addresses out. Only fingerprints, public IPs and domains leave your network.",
    icon: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-4-4 M8 11h6 M11 8v6",
    from: "#fb7185",
    to: "#7c3aed",
  },
};

type RoleStats = { role: Role; incidents: number; avg_ms: number | string | null; last_at: Date | null; model: string | null; samples: number | string };

export default async function AgentsPage({ params }: { params: Promise<{ orgId: string }> }) {
  const { orgId } = await params;
  await requirePageOrg(orgId);
  const connected = Boolean(process.env.AGENT_SERVICE_URL);

  const [stats, recent] = await Promise.all([
    rows<RoleStats>(
      `SELECT CASE WHEN r.agent = 'intel' THEN 'intel' ELSE 'soc' END AS role,
              COUNT(DISTINCT CASE WHEN r.status = 'succeeded' THEN r.incident_id END) AS incidents,
              AVG(CASE WHEN r.status = 'succeeded' THEN TIMESTAMPDIFF(MICROSECOND, r.started_at, r.finished_at) END) / 1000 AS avg_ms,
              MAX(CASE WHEN r.status = 'succeeded' THEN r.finished_at END) AS last_at,
              SUBSTRING_INDEX(GROUP_CONCAT(CASE WHEN r.status = 'succeeded' THEN r.model END ORDER BY r.finished_at DESC SEPARATOR '|'), '|', 1) AS model,
              SUM(r.status = 'succeeded' AND i.data_source = 'fixture') AS samples
         FROM agent_runs r JOIN incidents i ON i.incident_id = r.incident_id AND i.org_id = r.org_id
        WHERE r.org_id = ?
        GROUP BY role`,
      [orgId]
    ),
    rows<{ run_id: string; agent: string; status: string; started_at: Date; output_summary: string | null; ref: string; incident_id: string }>(
      `SELECT r.run_id, r.agent, r.status, r.started_at, r.output_summary, i.ref, i.incident_id
         FROM agent_runs r JOIN incidents i ON i.incident_id = r.incident_id AND i.org_id = r.org_id
        WHERE r.org_id = ? ORDER BY r.started_at DESC LIMIT 8`,
      [orgId]
    ),
  ]);
  const statOf = new Map(stats.map((s) => [s.role, s]));

  return (
    <>
      <PageHeader
        title="AI agents"
        subtitle="Two AI analysts work every incident on your network, day and night. They recommend; you decide. Everything they do is in the activity log."
      >
        <span
          className={`inline-flex items-center gap-2 rounded-md px-2.5 py-1 text-sm font-medium ${connected ? "bg-ok-soft text-ok" : "bg-raised text-muted"}`}
        >
          <span className={`size-2 rounded-full ${connected ? "bg-ok" : "bg-muted"}`} />
          {connected ? "Agents connected" : "Agents not connected: rule-based checks only"}
        </span>
      </PageHeader>

      <div className="grid gap-6 lg:grid-cols-2">
        {(Object.keys(PROFILES) as Role[]).map((role) => (
          <AgentCard key={role} role={role} s={statOf.get(role)} />
        ))}
      </div>

      <div className="mt-6">
        <Panel title="What they did recently">
          {recent.length ? (
            <ol>
              {recent.map((r) => (
                <li key={r.run_id} className="grid gap-1 border-b border-line px-5 py-3 last:border-0 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:gap-4">
                  <span className="text-sm text-muted">{timeAgo(iso(r.started_at))}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{AGENT_LABEL[r.agent] ?? capitalize(r.agent)}</p>
                    {r.output_summary && <p className="text-sm text-muted">{r.output_summary}</p>}
                  </div>
                  <div className="flex items-center gap-3 text-sm sm:justify-end">
                    <span className={r.status === "succeeded" ? "text-ok" : r.status === "failed" ? "text-bad" : "text-muted"}>{capitalize(r.status)}</span>
                    <Link href={`/app/${orgId}/incidents/${r.incident_id}`} className="font-medium text-info hover:underline">
                      {r.ref}
                    </Link>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <EmptyState title="No investigations yet">When an alert comes in, both agents get to work and their steps show up here.</EmptyState>
          )}
        </Panel>
      </div>
    </>
  );
}

function AgentCard({ role, s }: { role: Role; s?: RoleStats }) {
  const p = PROFILES[role];
  const incidents = Number(s?.incidents ?? 0);
  const avgMs = s?.avg_ms == null ? null : Number(s.avg_ms);
  const model = s?.model && !s.model.includes("fixture") ? s.model : null;
  const samples = Number(s?.samples ?? 0);

  return (
    <section className="flex flex-col rounded-lg bg-panel p-6 ring-1 ring-line">
      <div className="flex items-start gap-4">
        <span
          aria-hidden
          className="flex size-14 shrink-0 items-center justify-center rounded-xl text-white shadow-lg"
          style={{ background: `linear-gradient(135deg, ${p.from}, ${p.to})` }}
        >
          <svg viewBox="0 0 24 24" className="size-7" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d={p.icon} />
          </svg>
        </span>
        <div className="min-w-0">
          <h2 className="text-xl font-semibold tracking-tight">{p.name}</h2>
          <p className="text-sm text-muted">{p.role}</p>
          <p className="mt-1 text-xs text-muted">{model ? `Model: ${model}` : "Rule-based fallback when the AI is unavailable"}</p>
        </div>
      </div>

      <p className="mt-4 leading-relaxed">{p.does}</p>

      <div className="mt-4">
        <p className="text-xs font-semibold tracking-wider text-muted uppercase">Looks at</p>
        <ul className="mt-2 flex flex-wrap gap-2">
          {p.looksAt.map((x) => (
            <li key={x} className="rounded-md bg-canvas px-2 py-1 text-xs font-medium ring-1 ring-line">
              {x}
            </li>
          ))}
        </ul>
      </div>

      <p className="mt-4 mb-5 flex gap-2 rounded-md bg-canvas px-3 py-2.5 text-sm">
        <svg aria-hidden viewBox="0 0 24 24" className="mt-0.5 size-4 shrink-0 text-lantern" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 11V8a6 6 0 1 1 12 0v3 M5 11h14v10H5z" />
        </svg>
        <span>{p.never}</span>
      </p>

      <dl className="mt-auto grid grid-cols-3 gap-3 border-t border-line pt-4 text-center">
        <Stat label="Incidents worked" value={String(incidents)} />
        <Stat label="Average time" value={avgMs == null ? "None yet" : avgMs < 1000 ? "< 1 s" : `${(avgMs / 1000).toFixed(1)} s`} />
        <Stat label="Last active" value={s?.last_at ? timeAgo(iso(s.last_at)) : "Not yet"} />
      </dl>
      {samples > 0 && <p className="mt-2 text-center text-xs text-muted">Includes sample data</p>}
    </section>
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
