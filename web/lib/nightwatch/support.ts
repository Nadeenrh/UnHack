// How a client reaches the Nightwatch team. Shown to clients; set per deployment in the env.
// Demo defaults are placeholders so the page looks complete before real details are set.
export interface SupportContact {
  email: string;
  phone: string;
  hours: string;
}

export function supportContact(): SupportContact {
  return {
    email: process.env.NIGHTWATCH_SUPPORT_EMAIL?.trim() || "team@nightwatch.example",
    phone: process.env.NIGHTWATCH_SUPPORT_PHONE?.trim() || "+1 (000) 000-0000",
    hours: process.env.NIGHTWATCH_SUPPORT_HOURS?.trim() || "Monitored 24/7",
  };
}
