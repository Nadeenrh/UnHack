// Creating client organizations and their first site.

import type { OrgSector } from "@/contracts/types";
import { isPlanId, type PlanId } from "./plans";
import { audit } from "./audit";
import { newId, randomToken, sha256 } from "./crypto";
import { exec, one, type Executor } from "./db";
import { badRequest } from "./http";
import { ensureDefaultPolicies } from "./policy";

export const SECTORS: OrgSector[] = ["small_business", "healthcare", "community_org", "municipality", "utility", "other"];

export function slugify(name: string): string {
  return (
    name
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "org"
  );
}

/** A new ingest key. Shown to the client once; only its hash is stored. */
export function newIngestKey(): { key: string; hash: string; prefix: string } {
  const key = `nwk_${randomToken(24)}`;
  return { key, hash: sha256(key), prefix: key.slice(0, 12) };
}

export async function createOrganization(
  input: { name: string; sector: OrgSector; ownerUserId: string; plan?: PlanId; phone?: string | null },
  conn: Executor
): Promise<{ orgId: string; slug: string; siteId: string; ingestKey: string }> {
  if (!SECTORS.includes(input.sector)) throw badRequest("Unknown sector.");
  const plan: PlanId = isPlanId(input.plan) ? input.plan : "pilot";
  const phone = input.phone?.trim() ? input.phone.trim().slice(0, 32) : null;

  const base = slugify(input.name);
  let slug = base;
  for (let i = 2; await one(`SELECT 1 FROM organizations WHERE slug = ?`, [slug], conn); i++) {
    slug = `${base}-${i}`;
  }

  const orgId = newId();
  await exec(
    `INSERT INTO organizations (org_id, name, slug, sector, plan, contact_phone) VALUES (?, ?, ?, ?, ?, ?)`,
    [orgId, input.name, slug, input.sector, plan, phone],
    conn
  );
  await exec(
    `INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, 'owner')`,
    [orgId, input.ownerUserId],
    conn
  );
  await ensureDefaultPolicies(orgId, conn);

  const siteId = newId();
  const ingest = newIngestKey();
  await exec(
    `INSERT INTO sites (site_id, org_id, name, ingest_key_hash, ingest_key_prefix) VALUES (?, ?, 'Main site', ?, ?)`,
    [siteId, orgId, ingest.hash, ingest.prefix],
    conn
  );

  await audit(
    { orgId, actorType: "user", actorId: input.ownerUserId, event: "organization_created", details: { slug } },
    conn
  );
  return { orgId, slug, siteId, ingestKey: ingest.key };
}
