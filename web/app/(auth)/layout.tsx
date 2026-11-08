import Link from "next/link";
import { Logo } from "@/components/shell/Logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col items-center bg-sidebar px-4 py-12 text-ink">
      <Link href="/" className="mb-8 flex items-center gap-2.5">
        <Logo size={34} />
        <span className="text-2xl font-semibold tracking-tight">Nightwatch</span>
      </Link>
      {/* Narrow by default; a page can ask for a wide card by putting data-wide on its content (sign-up does). */}
      <div className="w-full max-w-md rounded-lg bg-panel p-6 text-ink ring-1 ring-line shadow-xl has-[[data-wide]]:max-w-4xl sm:p-8">
        {children}
      </div>
    </div>
  );
}
