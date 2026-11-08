import Link from "next/link";
import { PromisePills, TAGLINE } from "@/components/marketing/promises";
import { Logo } from "@/components/shell/Logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  // group: if the page puts its own logo in the card (data-brand, sign-in does), hide this one and centre the card.
  return (
    <div className="group flex min-h-screen flex-col items-center bg-sidebar px-4 py-10 text-ink has-[[data-brand]]:justify-center">
      {/* Brand header for pages without their own (sign-up): shield over the wordmark, the tagline, then the promises. */}
      <header className="mb-8 flex flex-col items-center text-center group-has-[[data-brand]]:hidden">
        <Link href="/" className="flex flex-col items-center gap-2">
          <Logo size={56} />
          <span className="text-3xl font-semibold tracking-tight">Nightwatch</span>
        </Link>
        <p className="mt-2 text-muted">{TAGLINE}</p>
        <div className="mt-5">
          <PromisePills />
        </div>
      </header>
      {/* Narrow by default; a page can ask for a wide card by putting data-wide on its content (sign-up does). */}
      <div className="w-full max-w-md rounded-lg bg-panel p-6 text-ink ring-1 ring-line shadow-xl has-[[data-wide]]:max-w-4xl sm:p-8">
        {children}
      </div>
    </div>
  );
}
