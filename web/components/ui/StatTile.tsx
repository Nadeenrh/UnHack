import Link from "next/link";

// Calm stat tile: dark card, the number in the tone colour, a coloured stripe on the left.
// "quiet" means nothing needs attention, so it drops the colour entirely.
const TONES = {
  lantern: { stripe: "border-l-lantern", number: "text-lantern" },
  high: { stripe: "border-l-sev-high", number: "text-sev-high" },
  info: { stripe: "border-l-info", number: "text-info" },
  critical: { stripe: "border-l-sev-critical", number: "text-sev-critical" },
  ok: { stripe: "border-l-ok", number: "text-ok" },
  quiet: { stripe: "border-l-line", number: "text-ink" },
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
  const t = TONES[tone];
  return (
    <div className={`flex flex-col justify-between rounded-lg border-l-4 bg-panel ring-1 ring-line ${t.stripe}`}>
      <div className="px-5 pt-4 pb-3">
        <div className={`text-4xl leading-none font-semibold tabular-nums ${t.number}`}>{value}</div>
        <div className="mt-2 text-sm font-medium text-ink-soft">{label}</div>
      </div>
      {href && (
        <Link href={href} className="block rounded-br-lg border-t border-line px-5 py-2 text-sm font-medium text-muted hover:bg-raised hover:text-ink">
          {linkText ?? "View"} →
        </Link>
      )}
    </div>
  );
}
