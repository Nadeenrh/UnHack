"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { ACTION_LABEL } from "@/components/format";

export interface PolicyRow {
  action_type: string;
  risk: "low" | "high" | "critical";
  mode: "auto" | "ask" | "never";
  auto_allowed: boolean;
}

const MODES: { value: PolicyRow["mode"]; label: string; help: string }[] = [
  { value: "auto", label: "Automatic", help: "Nightwatch does it right away and tells you." },
  { value: "ask", label: "Ask me", help: "Nightwatch waits for an approver." },
  { value: "never", label: "I'll do it", help: "Nightwatch only recommends it." },
];

const RISK: Record<PolicyRow["risk"], string> = { low: "Low risk", high: "High risk", critical: "Critical" };

/** The autonomy dial. Owners can change it; everyone else sees it read-only. */
export function PolicyEditor({ orgId, policies, editable }: { orgId: string; policies: PolicyRow[]; editable: boolean }) {
  const router = useRouter();
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function change(actionType: string, mode: PolicyRow["mode"]) {
    setSaving(actionType);
    setError(null);
    const res = await fetch(`/api/v1/orgs/${orgId}/policies`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action_type: actionType, mode }),
    }).catch(() => null);
    if (!res?.ok) {
      const body = await res?.json().catch(() => ({}));
      setError(body?.message ?? "Couldn't save that change.");
    }
    setSaving(null);
    router.refresh();
  }

  return (
    <div>
      {error && (
        <p role="alert" className="mx-5 mt-4 rounded-md bg-bad-soft px-3 py-2 text-sm text-bad">
          {error}
        </p>
      )}
      <ul>
        {policies.map((p) => (
          <li key={p.action_type} className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4 last:border-0">
            <div>
              <div className="font-medium">{ACTION_LABEL[p.action_type] ?? p.action_type}</div>
              <div className="text-xs text-muted">
                {RISK[p.risk]}
                {!p.auto_allowed && ". Never automatic"}
              </div>
            </div>
            <fieldset disabled={!editable || saving === p.action_type} className="flex rounded-md ring-1 ring-line">
              <legend className="sr-only">{ACTION_LABEL[p.action_type]}</legend>
              {MODES.map((m) => {
                const disabled = m.value === "auto" && !p.auto_allowed;
                const selected = p.mode === m.value;
                return (
                  <label
                    key={m.value}
                    title={disabled ? "Too risky to run without a person" : m.help}
                    className={`cursor-pointer px-3 py-1.5 text-sm font-medium first:rounded-l-md last:rounded-r-md ${
                      selected ? "bg-ink text-night" : disabled ? "cursor-not-allowed text-muted/50" : "hover:bg-canvas"
                    }`}
                  >
                    <input
                      type="radio"
                      name={p.action_type}
                      value={m.value}
                      checked={selected}
                      disabled={disabled}
                      onChange={() => change(p.action_type, m.value)}
                      className="sr-only"
                    />
                    {m.label}
                  </label>
                );
              })}
            </fieldset>
          </li>
        ))}
      </ul>
    </div>
  );
}
