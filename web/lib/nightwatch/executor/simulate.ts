import type { ResponseExecutor } from "./types";

// Default executor. Records that the response was approved and "ran", but changes nothing
// and says so plainly. Never claims verification.
export function simulateExecutor(): ResponseExecutor {
  const delay = Number(process.env.EXECUTOR_SIMULATE_DELAY_MS ?? 1500);
  return {
    name: "simulate",
    async run({ action }) {
      if (delay > 0) await new Promise((r) => setTimeout(r, delay));
      return {
        ok: true,
        verified: false,
        detail: `Simulation only: nothing was changed on ${action.target}. Switch EXECUTOR_MODE to "wazuh" to act for real.`,
      };
    },
  };
}
