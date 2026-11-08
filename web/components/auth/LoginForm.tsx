"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { PromiseIcon, PROMISES, TAGLINE } from "@/components/marketing/promises";
import { Logo } from "@/components/shell/Logo";
import { Field, FormError, PrimaryButton, safeNext } from "./Field";

export function LoginForm({ next }: { next?: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.message ?? "Sign-in failed. Try again.");
        return;
      }
      router.push(safeNext(next));
      router.refresh();
    } catch {
      setError("Couldn't reach Nightwatch. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  // data-brand: the logo lives inside this card, so the layout hides its own logo above.
  return (
    <div data-wide data-brand className="grid gap-8 lg:grid-cols-2">
      <section className="flex flex-col gap-6 rounded-md bg-sidebar p-6">
        <div className="flex items-center gap-3">
          <Logo size={40} />
          <span className="text-2xl font-semibold tracking-tight">Nightwatch</span>
        </div>
        <div>
          <p className="text-lg font-semibold">{TAGLINE}</p>
          <p className="mt-1 text-sm text-muted">AI analysts watch your network day and night, and your Nightwatch team is a call away.</p>
        </div>
        <ul className="space-y-5">
          {PROMISES.map((p) => (
            <li key={p.title} className="flex gap-3">
              <PromiseIcon name={p.icon} />
              <span>
                <span className="block font-semibold">{p.title}</span>
                <span className="text-sm text-muted">{p.body}</span>
              </span>
            </li>
          ))}
        </ul>
      </section>

      <form onSubmit={onSubmit} className="flex flex-col justify-center space-y-4">
        <div>
          <h1 className="text-xl font-semibold">Sign in</h1>
          <p className="mt-1 text-sm text-muted">Welcome back. See what Nightwatch caught while you were away.</p>
        </div>
        <FormError message={error} />
        <Field label="Email" name="email" type="email" autoComplete="email" required />
        <Field label="Password" name="password" type="password" autoComplete="current-password" required />
        <PrimaryButton type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </PrimaryButton>
        <p className="text-center text-sm text-muted">
          New to Nightwatch?{" "}
          <Link href="/register" className="font-medium text-info underline-offset-4 hover:underline">
            Set up your organization
          </Link>
        </p>
      </form>
    </div>
  );
}
