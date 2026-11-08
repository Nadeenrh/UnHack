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
        // Demo mode (NIGHTWATCH_DEMO=1) words and marks the result as a live response would read.
        verified: process.env.NIGHTWATCH_DEMO === "1",
        detail:
          process.env.NIGHTWATCH_DEMO === "1"
            ? demoDetail(action.type, action.target)
            : `Simulation only: nothing was changed on ${action.target}. Switch EXECUTOR_MODE to "wazuh" to act for real.`,
      };
    },
  };
}

function demoDetail(type: string, target: string): string {
  switch (type) {
    case "notify_only":
      return "Done: the clinic's contacts were notified by email and text.";
    case "block_domain":
      return `Done: ${target} is blocked for every machine in the clinic.`;
    case "isolate_host":
      return `Done: ${target} is cut off from the network until someone releases it.`;
    case "quarantine_file":
      return `Done: ${target} was moved to quarantine.`;
    case "disable_account":
      return `Done: the ${target} account is disabled.`;
    default:
      return `Done: ${target} is blocked by the firewall on the affected machine.`;
  }
}
