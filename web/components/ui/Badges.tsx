import type { ActionStatus, DataSource, IncidentStatus, OrgHealth, Severity } from "@/contracts/types";

function Pill({ className, children, title }: { className: string; children: React.ReactNode; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${className}`}>
      {children}
    </span>
  );
}

const SEVERITY: Record<Severity, string> = {
  critical: "bg-sev-critical text-night",
  high: "bg-sev-high text-night",
  medium: "bg-sev-medium text-night",
  low: "bg-sev-low text-night",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Pill className={SEVERITY[severity]}>{severity.charAt(0).toUpperCase() + severity.slice(1)}</Pill>;
}

const INCIDENT_STATUS: Record<IncidentStatus, [string, string]> = {
  open: ["Open", "bg-info-soft text-info"],
  investigating: ["Investigating", "bg-info-soft text-info"],
  awaiting_approval: ["Needs your decision", "bg-lantern-soft text-lantern-deep ring-1 ring-lantern"],
  contained: ["Contained", "bg-ok-soft text-ok"],
  resolved: ["Resolved", "bg-canvas text-muted"],
  false_positive: ["False positive", "bg-canvas text-muted"],
};

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  const [label, cls] = INCIDENT_STATUS[status];
  return <Pill className={cls}>{label}</Pill>;
}

// Every action state looks different on purpose: people must never confuse "approved" with "done".
const ACTION_STATUS: Record<ActionStatus, [string, string]> = {
  proposed: ["Do it yourself", "bg-canvas text-ink-soft ring-1 ring-line"],
  awaiting_approval: ["Waiting for approval", "bg-lantern-soft text-lantern-deep ring-1 ring-lantern"],
  approved: ["Approved, starting", "bg-info-soft text-info"],
  executing: ["Running now", "bg-info text-night"],
  succeeded: ["Done", "bg-ok text-night"],
  failed: ["Failed", "bg-bad text-night"],
  denied: ["Denied", "bg-bad-soft text-bad"],
  expired: ["Expired, no decision", "bg-canvas text-muted ring-1 ring-line"],
};

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const [label, cls] = ACTION_STATUS[status];
  return <Pill className={cls}>{label}</Pill>;
}

export function DataSourceBadge({ source }: { source: DataSource }) {
  if (source === "live") return null;
  return source === "fixture" ? (
    <Pill className="bg-canvas text-muted border border-dashed border-muted" title="Demo data, not from a real system">
      Sample data
    </Pill>
  ) : (
    <Pill className="bg-canvas text-muted ring-1 ring-line" title="Recorded alerts played back">
      Replay
    </Pill>
  );
}

const HEALTH: Record<OrgHealth, [string, string, string]> = {
  attention: ["Needs attention", "bg-lantern-soft text-lantern-deep", "bg-lantern"],
  watch: ["Watching", "bg-info-soft text-info", "bg-info"],
  healthy: ["All clear", "bg-ok-soft text-ok", "bg-ok"],
};

export function HealthBadge({ health }: { health: OrgHealth }) {
  const [label, cls, dot] = HEALTH[health];
  return (
    <Pill className={cls}>
      <span aria-hidden className={`size-2 rounded-full ${dot}`} />
      {label}
    </Pill>
  );
}
