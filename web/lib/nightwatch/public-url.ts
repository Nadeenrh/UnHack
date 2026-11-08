import { headers } from "next/headers";

/**
 * The address other machines use to reach this NightWatch server (for the Wazuh hook_url).
 * NIGHTWATCH_PUBLIC_URL wins, because the browser may be on "localhost" while the Wazuh
 * manager needs this machine's network address (e.g. http://192.168.8.50:3000).
 */
export async function publicBaseUrl(): Promise<string> {
  const fromEnv = process.env.NIGHTWATCH_PUBLIC_URL?.trim();
  if (fromEnv) return fromEnv.replace(/\/+$/, "");
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? "http";
  return `${proto}://${host}`;
}

export function ingestUrl(base: string): string {
  return `${base}/api/v1/ingest/wazuh`;
}

/** True when the URL only works on this machine, so a Wazuh manager elsewhere can't use it. */
export function isLoopback(base: string): boolean {
  try {
    const { hostname } = new URL(base);
    return hostname === "localhost" || hostname === "::1" || hostname === "[::1]" || hostname.startsWith("127.");
  } catch {
    return false;
  }
}
