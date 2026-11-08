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
        {/* Faint gridlines at quarter steps, labelled at half and full height. */}
        <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-36 sm:h-44">
          {[1, 0.75, 0.5, 0.25].map((f) => (
            <div key={f} className="absolute inset-x-0 flex translate-y-1/2 items-center" style={{ bottom: `${f * 100}%` }}>
              <span className="w-6 pr-1.5 text-right text-[10px] text-muted tabular-nums">{f === 1 || f === 0.5 ? Math.round(max * f) : ""}</span>
              <span className="flex-1 border-t border-dashed border-line" />
            </div>
          ))}
        </div>
        <div aria-hidden className="relative flex h-36 items-end gap-[3px] border-b border-line pl-6 sm:h-44">
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

      {/* Screen-reader copy of the chart. The wrapper does the hiding: tables ignore overflow, so a
          hidden table on its own still stretches the page. */}
      <div className="sr-only">
        <table aria-label="Alerts per hour, last 24 hours">
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
      </div>
    </figure>
  );
}
