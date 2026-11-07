import type { ActionRow } from "../incidents";

export interface ExecutionContext {
  action: ActionRow;
  /** The incident's assets in the same org. */
  assets: {
    hostname: string;
    ip: string | null;
    os: string | null;
    kind: "endpoint" | "server" | "network" | "other";
    agent_ref: string | null;
    agent_status: "online" | "offline" | "never_connected";
  }[];
}

export interface ExecutionResult {
  ok: boolean;
  /** true only if we checked that the change actually took effect. */
  verified: boolean;
  /** Plain English, shown on the incident card. */
  detail: string;
}

export interface ResponseExecutor {
  name: string;
  run(ctx: ExecutionContext): Promise<ExecutionResult>;
}
