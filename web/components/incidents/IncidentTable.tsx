import Link from "next/link";
import { Fragment } from "react";
import type { Incident } from "@/contracts/types";
import { formatDateTime } from "@/components/format";
import { DataSourceBadge, IncidentStatusBadge, SeverityBadge } from "@/components/ui/Badges";

export function IncidentTable({ incidents, orgId }: { incidents: Incident[]; orgId: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left text-muted">
            <th className="px-5 py-2 font-medium">Incident</th>
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="hidden px-3 py-2 font-medium md:table-cell">Machines</th>
            <th className="px-5 py-2 text-right font-medium">Detected</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((i) => (
            <tr key={i.id} className="border-b border-line last:border-0 hover:bg-canvas/60">
              <td className="px-5 py-3">
                <Link href={`/app/${orgId}/incidents/${i.id}`} className="font-medium hover:underline">
                  {i.title}
                </Link>
                <div className="mt-0.5 flex items-center gap-2 text-xs text-muted">
                  <span>{i.ref}</span>
                  <DataSourceBadge source={i.data_source} />
                </div>
              </td>
              <td className="px-3 py-3">
                <SeverityBadge severity={i.severity} />
              </td>
              <td className="px-3 py-3">
                <IncidentStatusBadge status={i.status} />
              </td>
              <td className="hidden px-3 py-3 font-mono text-xs md:table-cell">
                {/* Each machine name stays on one line (no split at the hyphen in RECEPTION-PC); the list can still wrap between names. */}
                {i.assets.map((a, n) => (
                  <Fragment key={a.id}>
                    <span className="whitespace-nowrap">
                      {a.hostname}
                      {n < i.assets.length - 1 ? "," : ""}
                    </span>{" "}
                  </Fragment>
                ))}
              </td>
              <td className="px-5 py-3 text-right whitespace-nowrap text-muted">{formatDateTime(i.detected_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
