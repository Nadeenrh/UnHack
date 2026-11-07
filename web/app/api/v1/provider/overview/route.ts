import { requireProvider } from "@/lib/nightwatch/access";
import { authed } from "@/lib/nightwatch/route";
import { snapshots } from "@/lib/nightwatch/snapshots";

// GET /api/v1/provider/overview — one ProviderOrgSnapshot per client, for the provider portal's
// collapsible client cards. Status-level data only. Opening a client's full workspace
// (incident detail, evidence, audit) requires a support session.
export const GET = authed(async (_req, _params, session) => {
  requireProvider(session);
  return snapshots();
});
