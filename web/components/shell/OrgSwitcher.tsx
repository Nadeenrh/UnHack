"use client";

import { useRouter } from "next/navigation";

export function OrgSwitcher({ orgs, currentOrgId }: { orgs: { id: string; name: string }[]; currentOrgId: string }) {
  const router = useRouter();
  const current = orgs.find((o) => o.id === currentOrgId);
  if (orgs.length < 2) {
    return <span className="truncate text-sm font-semibold">{current?.name}</span>;
  }
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="sr-only">Organization</span>
      <select
        value={currentOrgId}
        onChange={(e) => router.push(`/app/${e.target.value}`)}
        className="rounded-md border border-line bg-panel px-2 py-1 font-semibold"
      >
        {orgs.map((o) => (
          <option key={o.id} value={o.id}>
            {o.name}
          </option>
        ))}
      </select>
    </label>
  );
}
