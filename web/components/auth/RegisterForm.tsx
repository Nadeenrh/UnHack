"use client";

import Link from "next/link";
import { useState } from "react";
import { SECTOR_LABEL } from "@/components/format";
import { PLANS, type PlanId } from "@/lib/nightwatch/plans";
import { Field, FormError, PrimaryButton } from "./Field";

interface Created {
  orgId: string;
  orgName: string;
  ingestKey: string;
}

export function RegisterForm() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<Created | null>(null);
  const [copied, setCopied] = useState(false);
  const [plan, setPlan] = useState<PlanId>("pilot");

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          organization: { name: f.get("org_name"), sector: f.get("sector"), phone: f.get("phone"), plan },
          user: {
            first_name: f.get("first_name"),
            last_name: f.get("last_name"),
            email: f.get("email"),
            password: f.get("password"),
          },
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.message ?? "Couldn't create your organization. Try again.");
        return;
      }
      setCreated({
        orgId: body.data.organization.id,
        orgName: String(f.get("org_name")),
        ingestKey: body.data.first_site.ingest_key,
      });
    } catch {
      setError("Couldn't reach Nightwatch. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  // The ingest key is shown exactly once. Make that impossible to miss.
  if (created) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">{created.orgName} is set up</h1>
        <p className="text-sm text-muted">
          This is your site&apos;s ingest key. Your monitoring sends alerts to Nightwatch with it. Copy it somewhere safe now:
          it won&apos;t be shown again. You can issue a new one later in Settings.
        </p>
        <div className="rounded-md border-2 border-lantern bg-lantern-soft p-3">
          <code className="block break-all font-mono text-sm">{created.ingestKey}</code>
        </div>
        <button
          type="button"
          onClick={async () => {
            await navigator.clipboard.writeText(created.ingestKey).catch(() => undefined);
            setCopied(true);
          }}
          className="w-full rounded-md border border-line px-4 py-2 font-medium hover:bg-canvas"
        >
          {copied ? "Copied" : "Copy key"}
        </button>
        <div className="rounded-md bg-canvas px-4 py-3 text-sm">
          <p className="font-semibold">What happens next</p>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-muted">
            <li>Send this key to your Nightwatch team.</li>
            <li>They connect your computers through Wazuh. Nothing to install on your side.</li>
            <li>Your computers appear under Machines on their own, and Nightwatch starts watching.</li>
          </ol>
        </div>
        <Link
          href={`/app/${created.orgId}`}
          className="block w-full rounded-md bg-ink px-4 py-2.5 text-center font-semibold text-night hover:bg-ink-soft"
        >
          I&apos;ve saved it, go to my dashboard
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h1 className="text-xl font-semibold">Set up your organization</h1>
      <FormError message={error} />
      <Field label="Organization name" name="org_name" required minLength={2} maxLength={150} placeholder="Maple Street Family Clinic" />
      <label className="block">
        <span className="text-sm font-medium">Type of organization</span>
        <select name="sector" required defaultValue="" className="mt-1 block w-full rounded-md border border-line bg-panel px-3 py-2">
          <option value="" disabled>
            Choose one
          </option>
          {Object.entries(SECTOR_LABEL).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <Field label="Phone number" name="phone" type="tel" autoComplete="tel" maxLength={32} placeholder="123-456-7890" hint="So your Nightwatch team can reach you." />
      <div className="grid grid-cols-2 gap-3">
        <Field label="First name" name="first_name" autoComplete="given-name" required />
        <Field label="Last name" name="last_name" autoComplete="family-name" required />
      </div>
      <Field label="Work email" name="email" type="email" autoComplete="email" required />
      <Field label="Password" name="password" type="password" autoComplete="new-password" required minLength={12} hint="At least 12 characters." />

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Choose a plan</legend>
        <p className="text-sm text-muted">Start free for 30 days. No card needed now, and you can change plan later.</p>
        <div className="space-y-2">
          {PLANS.map((p) => {
            const active = plan === p.id;
            return (
              <label
                key={p.id}
                className={`flex cursor-pointer items-start gap-3 rounded-md border px-4 py-3 ${
                  active ? "border-lantern bg-lantern-soft" : "border-line hover:bg-canvas"
                }`}
              >
                <input
                  type="radio"
                  name="plan"
                  value={p.id}
                  checked={active}
                  onChange={() => setPlan(p.id)}
                  className="mt-1 accent-lantern"
                />
                <span className="flex-1">
                  <span className="flex items-baseline justify-between gap-2">
                    <span className="font-semibold">{p.name}</span>
                    <span className="text-sm">
                      <span className="font-semibold">{p.price}</span> <span className="text-muted">{p.cadence}</span>
                    </span>
                  </span>
                  <span className="mt-0.5 block text-sm text-muted">
                    {p.machines} · {p.blurb}
                  </span>
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      <PrimaryButton type="submit" disabled={busy}>
        {busy ? "Setting up…" : "Create organization"}
      </PrimaryButton>
      <p className="text-center text-sm text-muted">
        Already using Nightwatch?{" "}
        <Link href="/login" className="font-medium text-info underline-offset-4 hover:underline">
          Sign in
        </Link>
      </p>
    </form>
  );
}
