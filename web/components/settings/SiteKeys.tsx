"use client";

import { useState } from "react";
import { IntegrationSnippet } from "@/components/connect/IntegrationSnippet";

export interface SiteRow {
  id: string;
  name: string;
  ingest_key_prefix: string;
  active: boolean;
}

/** Ingest keys: only the first characters are ever shown; a new key is shown once. */
export function SiteKeys({ orgId, sites, editable, hookUrl }: { orgId: string; sites: SiteRow[]; editable: boolean; hookUrl: string }) {
  const [fresh, setFresh] = useState<{ siteId: string; key: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function rotate(siteId: string) {
    if (!confirm("Replace this key? Monitoring that uses the old key stops being accepted immediately.")) return;
    setBusy(siteId);
    setError(null);
    const res = await fetch(`/api/v1/orgs/${orgId}/sites/${siteId}/rotate-key`, { method: "POST" }).catch(() => null);
    const body = await res?.json().catch(() => ({}));
    if (res?.ok) setFresh({ siteId, key: body.data.ingest_key });
    else setError(body?.message ?? "Couldn't replace the key.");
    setBusy(null);
  }

  return (
    <ul>
      {error && (
        <li role="alert" className="mx-5 mt-4 rounded-md bg-bad-soft px-3 py-2 text-sm text-bad">
          {error}
        </li>
      )}
      {sites.map((s) => (
        <li key={s.id} className="border-b border-line px-5 py-4 last:border-0">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="font-medium">{s.name}</div>
              <div className="text-sm text-muted">
                Key starts with <span className="font-mono">{s.ingest_key_prefix}</span>
              </div>
            </div>
            {editable && (
              <button
                type="button"
                disabled={busy === s.id}
                onClick={() => rotate(s.id)}
                className="rounded-md px-3 py-1.5 text-sm font-medium ring-1 ring-line hover:bg-canvas disabled:opacity-60"
              >
                {busy === s.id ? "Replacing…" : "Replace key"}
              </button>
            )}
          </div>
          {fresh?.siteId === s.id && (
            <div className="mt-3 rounded-md border-2 border-lantern bg-lantern-soft p-3 text-sm">
              <p className="font-medium">New key. Copy it now: it won&apos;t be shown again.</p>
              <code className="mt-2 block font-mono break-all">{fresh.key}</code>
              <p className="mt-3">Update your Wazuh server&apos;s ossec.conf with it, then restart wazuh-manager:</p>
              <IntegrationSnippet hookUrl={hookUrl} ingestKey={fresh.key} />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
