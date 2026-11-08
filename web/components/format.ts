// Display helpers shared by server and client components.

const TZ = process.env.NEXT_PUBLIC_DISPLAY_TZ ?? "America/Toronto";

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(iso));
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en-CA", { timeZone: TZ, hour: "numeric", minute: "2-digit", second: "2-digit" }).format(
    new Date(iso)
  );
}

/** "3 min ago", "2 h ago", "Nov 6". Computed on the server at render time. */
export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Intl.DateTimeFormat("en-CA", { timeZone: TZ, month: "short", day: "numeric" }).format(new Date(iso));
}

export const ACTION_LABEL: Record<string, string> = {
  block_ip: "Block IP address",
  block_domain: "Block domain",
  isolate_host: "Isolate machine",
  quarantine_file: "Quarantine file",
  disable_account: "Disable account",
  notify_only: "Notify",
};

/** Verb for the approve button, so the button says exactly what happens. */
export const ACTION_VERB: Record<string, string> = {
  block_ip: "Approve block",
  block_domain: "Approve block",
  isolate_host: "Approve isolation",
  quarantine_file: "Approve quarantine",
  disable_account: "Approve",
  notify_only: "Approve",
};

/** The team's names for the AI agents. Contract values stay triage / intel / investigator. */
export const AGENT_LABEL: Record<string, string> = {
  triage: "SOC Analyst: triage",
  intel: "Threat Intel",
  investigator: "SOC Analyst: investigation",
};

export const SECTOR_LABEL: Record<string, string> = {
  small_business: "Small or medium business",
  healthcare: "Clinic or health practice",
  community_org: "Community organization",
  municipality: "Municipality",
  utility: "Utility",
  other: "Other",
};

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).replaceAll("_", " ");
}
