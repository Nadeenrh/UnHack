import { createHash, randomBytes, randomUUID } from "node:crypto";

export const newId = (): string => randomUUID();

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** URL-safe random secret (session tokens, ingest keys). 32 bytes = 256 bits. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
