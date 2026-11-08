// NightWatch plans. Prices are placeholders the team can change.
// The pitch: a security analyst is ~$80k/year and enterprise SOCs run thousands a month,
// so even "Plus" is a fraction of that. Picking a plan is all we do here, no card is taken.

export type PlanId = "pilot" | "standard" | "plus";

export interface Plan {
  id: PlanId;
  name: string;
  price: string;
  cadence: string;
  machines: string;
  blurb: string;
}

export const PLANS: Plan[] = [
  {
    id: "pilot",
    name: "Pilot",
    price: "Free",
    cadence: "for 30 days",
    machines: "Up to 5 machines",
    blurb: "Try NightWatch on a few computers. No card needed.",
  },
  {
    id: "standard",
    name: "Standard",
    price: "$199",
    cadence: "/month",
    machines: "Up to 15 machines",
    blurb: "For a small team or practice.",
  },
  {
    id: "plus",
    name: "Plus",
    price: "$399",
    cadence: "/month",
    machines: "Up to 40 machines",
    blurb: "For a growing business with more to protect.",
  },
];

export const PLAN_IDS: PlanId[] = PLANS.map((p) => p.id);

export function isPlanId(v: unknown): v is PlanId {
  return typeof v === "string" && (PLAN_IDS as string[]).includes(v);
}

export function planLabel(id: string): string {
  return PLANS.find((p) => p.id === id)?.name ?? id;
}
