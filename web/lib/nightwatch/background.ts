// Run work after the HTTP response is sent (executor runs, investigations).
// Inside Next.js this uses after(); elsewhere (tests, scripts) it falls back to a tracked
// promise so callers can wait for it with settleBackground().

import { after } from "next/server";

const pending = new Set<Promise<void>>();

export function runLater(label: string, fn: () => Promise<void>): void {
  const wrapped = async () => {
    try {
      await fn();
    } catch (err) {
      console.error(`[nightwatch] background job "${label}" failed:`, err);
    }
  };
  try {
    after(wrapped);
  } catch {
    // Not inside a request (tests, CLI). Track it instead.
    const p = wrapped().finally(() => pending.delete(p));
    pending.add(p);
  }
}

/** Wait until every tracked background job has finished (tests). */
export async function settleBackground(): Promise<void> {
  while (pending.size) await Promise.all([...pending]);
}
