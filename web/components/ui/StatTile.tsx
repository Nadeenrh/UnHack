import Link from "next/link";

// Pi-hole-style solid tile: big number, plain label, link to the detail.
const TONES = {
  lantern: "bg-lantern text-night",
  high: "bg-sev-high text-night",
  info: "bg-info text-night",
  critical: "bg-sev-critical text-night",
  ok: "bg-ok text-night",
  quiet: "bg-panel text-ink ring-1 ring-line",
} as const;

export function StatTile({
  value,
  label,
  tone,
  href,
  linkText,
}: {
  value: React.ReactNode;
  label: string;
  tone: keyof typeof TONES;
  href?: string;
  linkText?: string;
}) {
  return (
    <div className={`flex flex-col justify-between rounded-lg ${TONES[tone]}`}>
      <div className="px-5 pt-4 pb-3">
        <div className="text-4xl font-semibold tabular-nums leading-none">{value}</div>
        <div className="mt-2 text-sm font-medium opacity-90">{label}</div>
      </div>
      {href && (
        <Link href={href} className="block rounded-b-lg bg-night/15 px-5 py-1.5 text-sm font-medium hover:bg-night/25">
          {linkText ?? "View"}
        </Link>
      )}
    </div>
  );
}
