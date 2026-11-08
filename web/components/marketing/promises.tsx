// The three promises Nightwatch makes. Shown on the homepage and the sign-in page,
// so the wording lives here once.

const ICONS = {
  shield: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z M9 12l2 2 4-4",
  chat: "M4 5h16v11H9l-5 4V5z M8 9h8 M8 12h5",
  check: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8 12l3 3 5-6",
} as const;

export const TAGLINE = "Your security team, without having to hire one.";

export const PROMISES: { icon: keyof typeof ICONS; title: string; body: string }[] = [
  {
    icon: "shield",
    title: "Threats caught early",
    body: "Password guessing, phishing links and ransomware are flagged the moment they start, before they become a breach.",
  },
  {
    icon: "chat",
    title: "Explained in plain words",
    body: "AI analysts read every alert and tell you what happened and what to do, in a sentence or two.",
  },
  {
    icon: "check",
    title: "Nothing happens without you",
    body: "You approve every action on your network, unless you choose to let Nightwatch act on its own.",
  },
];

/** A small amber tile with a line icon. */
export function PromiseIcon({ name }: { name: keyof typeof ICONS }) {
  return (
    <span aria-hidden className="flex size-9 shrink-0 items-center justify-center rounded-md bg-lantern/15 text-lantern">
      <svg viewBox="0 0 24 24" className="size-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d={ICONS[name]} />
      </svg>
    </span>
  );
}
