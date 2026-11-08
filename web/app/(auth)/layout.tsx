import Link from "next/link";
import { PromisePills, TAGLINE } from "@/components/marketing/promises";
import { Logo } from "@/components/shell/Logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  // group: if the page puts its own logo in the card (data-brand, sign-in does), hide this one and centre the card.
  return (
    <div className="group flex min-h-screen flex-col items-center bg-sidebar px-4 py-8 text-ink has-[[data-brand]]:justify-center">
      {/* Compact brand header for pages without their own (sign-up): logo and wordmark, the tagline, then the promises in one row. */}
      <header className="mb-6 flex flex-col items-center text-center group-has-[[data-brand]]:hidden">
        <Link href="/" className="flex items-center gap-2.5">
          <Logo size={40} />
          <span className="text-2xl font-semibold tracking-tight">NightWatch</span>
        </Link>
        <p className="mt-1 text-sm text-muted">{TAGLINE}</p>
        <div className="mt-4">
          <PromisePills />
        </div>
      </header>
      {/* Narrow by default (sign-in); a page can ask for a wide card by putting data-wide on its content (sign-up does). */}
      <div className="w-full max-w-md rounded-lg bg-panel p-6 text-ink ring-1 ring-line shadow-xl has-[[data-wide]]:max-w-4xl sm:p-8">
        {children}
      </div>
    </div>
  );
}
