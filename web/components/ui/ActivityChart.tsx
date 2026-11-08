import type { HourBucket } from "@/lib/nightwatch/snapshots";

const TZ = process.env.NEXT_PUBLIC_DISPLAY_TZ ?? "America/Toronto";
const hourLabel = (iso: string) =>
  new Intl.DateTimeFormat("en-CA", { timeZone: TZ, hour: "numeric" }).format(new Date(iso)).replace(/\s?([ap])\.?m\.?/i, "$1m");

/**
 * Pi-hole's "queries over last 24 hours", for alerts: one stacked bar per hour.
 * Routine = seen and logged. Flagged = became part of an incident. Plain CSS, no chart library.
 */
export function ActivityChart({ buckets }: { buckets: HourBucket[] }) {
  const max = Math.max(1, ...buckets.map((b) => b.flagged + b.routine));
  const total = buckets.reduce((n, b) => n + b.flagged + b.routine, 0);
  const flagged = buckets.reduce((n, b) => n + b.flagged, 0);

  return (
    <figure className="px-5 pt-4 pb-3">
      <figcaption className="mb-3 flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1 text-sm">
        <span>
          <span className="text-2xl font-semibold tabular-nums">{total}</span> <span className="text-muted">alerts seen</span>
          <span className="mx-2 text-line">|</span>
          <span className="text-2xl font-semibold tabular-nums text-sev-high">{flagged}</span>{" "}
          <span className="text-muted">needed a closer look</span>
        </span>
        <span className="flex gap-4 text-xs text-muted">
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="size-2.5 rounded-sm bg-info/45" /> Routine, logged
          </span>
          <span className="flex items-center gap-1.5">
            <span aria-hidden className="size-2.5 rounded-sm bg-sev-high" /> Part of an incident
          </span>
        </span>
      </figcaption>

      <div className="relative">
        <span className="absolute -top-1 left-0 text-[10px] text-muted tabular-nums">{max}</span>
        <div aria-hidden className="flex h-36 items-end gap-[3px] border-b border-line pl-6 sm:h-44">
          {buckets.map((b) => {
            const n = b.flagged + b.routine;
            return (
              <div
                key={b.hour}
                title={`${hourLabel(b.hour)}: ${n} alert${n === 1 ? "" : "s"}${b.flagged ? `, ${b.flagged} part of an incident` : ""}`}
                className="group flex h-full flex-1 flex-col justify-end"
              >
                <div className="flex flex-col justify-end overflow-hidden rounded-t-[3px] group-hover:brightness-125" style={{ height: `${(n / max) * 100}%` }}>
                  {b.flagged > 0 && <div className="bg-sev-high" style={{ height: `${(b.flagged / n) * 100}%`, minHeight: 3 }} />}
                  <div className="flex-1 bg-info/45" />
                </div>
              </div>
            );
          })}
        </div>
        <div aria-hidden className="mt-1.5 flex pl-6 text-[10px] text-muted">
          {buckets.map((b, i) => (
            <span key={b.hour} className="flex-1 text-center">
              {i % 6 === 0 ? hourLabel(b.hour) : ""}
            </span>
          ))}
        </div>
      </div>

      <table className="sr-only" aria-label="Alerts per hour, last 24 hours">
        <thead>
          <tr>
            <th>Hour</th>
            <th>Routine</th>
            <th>Part of an incident</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b) => (
            <tr key={b.hour}>
              <td>{hourLabel(b.hour)}</td>
              <td>{b.routine}</td>
              <td>{b.flagged}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
