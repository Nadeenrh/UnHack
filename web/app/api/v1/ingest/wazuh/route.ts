import { badRequest, HttpError } from "@/lib/nightwatch/http";
import { ingestWazuh } from "@/lib/nightwatch/ingest";
import { open } from "@/lib/nightwatch/route";

const MAX_BYTES = 5 * 1024 * 1024;

// POST /api/v1/ingest/wazuh
//   Authorization: Bearer <site ingest key>       (or X-Nightwatch-Key: <key>)
//   X-Nightwatch-Replay: 1                         optional; marks incidents as "replay"
//   Body: one Wazuh alert, an array of alerts, or { "alerts": [...] }  (max 500)
//
// Machine-to-machine: no cookies, so no Origin check. The key alone decides the organization.
// Returns { received, stored, duplicates, ignored, incidents: [{ id, ref, created }] }.
export const POST = open(
  async (req) => {
    const len = Number(req.headers.get("content-length") ?? 0);
    if (len > MAX_BYTES) throw new HttpError(413, "Payload too large (max 5 MB).", "too_large");

    const auth = req.headers.get("authorization");
    const key = auth?.startsWith("Bearer ") ? auth.slice(7).trim() : req.headers.get("x-nightwatch-key");

    let payload: unknown;
    try {
      payload = await req.json();
    } catch {
      throw badRequest("Body must be JSON.");
    }
    return ingestWazuh(key, payload, { replay: req.headers.get("x-nightwatch-replay") === "1" });
  },
  { checkOrigin: false }
);
