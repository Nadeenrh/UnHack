"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
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
        body: JSON.stringify({
          email: form.get("email"),
          password: form.get("password"),
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.message ?? "Sign-in failed. Try again.");
        return;
      }
      router.push(safeNext(next));
      router.refresh();
    } catch {
      setError(
        "Couldn't reach NightWatch. Check your connection and try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  // The layout above supplies the same brand header as sign-up (logo, tagline, promises in one row);
  // this is just the form inside its card.
  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="text-center">
        <h1 className="text-xl font-semibold">Sign in</h1>
        <p className="mt-1 text-sm text-muted">
          Welcome back. See what NightWatch caught while you were away.
        </p>
      </div>
      <FormError message={error} />
      <Field
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        required
      />
      <Field
        label="Password"
        name="password"
        type="password"
        autoComplete="current-password"
        required
      />
      <PrimaryButton type="submit" disabled={busy}>
        {busy ? "Signing in…" : "Sign in"}
      </PrimaryButton>
      <p className="text-center text-sm text-muted">
        New to NightWatch?{" "}
        <Link
          href="/register"
          className="font-medium text-info underline-offset-4 hover:underline"
        >
          Set up your organization
        </Link>
      </p>
    </form>
  );
}
