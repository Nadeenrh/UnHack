// The promises Nightwatch makes. Shown on the homepage, the sign-in page and (as pills) the
// sign-up page, so the wording lives here once.

const ICONS = {
  shield: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z M9 12l2 2 4-4",
  chat: "M4 5h16v11H9l-5 4V5z M8 9h8 M8 12h5",
  check: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M8 12l3 3 5-6",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
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
  {
    icon: "eye",
    title: "Full transparency",
    body: "Every alert, every AI step and every approval goes into a log you can read and nobody can edit.",
  },
];

/** A small amber tile with a line icon. */
export function PromiseIcon({ name, small = false }: { name: keyof typeof ICONS; small?: boolean }) {
  return (
    <span
      aria-hidden
      className={`flex shrink-0 items-center justify-center rounded-md bg-lantern/15 text-lantern ${small ? "size-7" : "size-9"}`}
    >
      <svg viewBox="0 0 24 24" className={small ? "size-4" : "size-5"} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        <path d={ICONS[name]} />
      </svg>
    </span>
  );
}

/** The promises as short pills, staggered so they read as a loose cluster rather than a grid. */
export function PromisePills() {
  return (
    <ul className="flex max-w-lg flex-wrap justify-center gap-x-3 gap-y-3 sm:[&>li:nth-child(even)]:translate-y-2">
      {PROMISES.map((p) => (
        <li key={p.title} className="flex items-center gap-2 rounded-md bg-night py-1.5 pr-3 pl-1.5 text-sm font-semibold ring-1 ring-line">
          <PromiseIcon name={p.icon} small />
          {p.title}
        </li>
      ))}
    </ul>
  );
}
