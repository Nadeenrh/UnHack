import Link from "next/link";
import { Logo } from "./Logo";
import { MobileNav, SidebarNav, type NavItem } from "./Nav";
import { OrgSwitcher } from "./OrgSwitcher";
import { SignOutButton } from "./SignOutButton";

export interface ShellProps {
  nav: NavItem[];
  user: { name: string; email: string };
  orgs?: { id: string; name: string }[];
  currentOrgId?: string;
  providerLink?: boolean;
  banner?: React.ReactNode;
  children: React.ReactNode;
}

// Pi-hole's "Status: Active" block, told honestly: watching is always on; whether approved
// responses really change anything depends on EXECUTOR_MODE.
function StatusBlock() {
  const live = process.env.EXECUTOR_MODE === "wazuh";
  return (
    <div className="mx-5 mb-4 space-y-1.5 rounded-md bg-panel/60 px-3 py-2.5 text-xs ring-1 ring-line">
      <div className="flex items-center gap-2">
        <span aria-hidden className="size-2 rounded-full bg-ok shadow-[0_0_6px] shadow-ok" />
        <span className="text-ink-soft">Watching:</span> <span className="font-medium text-ok">On</span>
      </div>
      <div className="flex items-center gap-2">
        <span aria-hidden className={`size-2 rounded-full ${live ? "bg-ok" : "bg-muted"}`} />
        <span className="text-ink-soft">Responses:</span>{" "}
        <span className={`font-medium ${live ? "text-ok" : "text-muted"}`}>{live ? "Live" : "Simulated"}</span>
      </div>
    </div>
  );
}

// Pi-hole-like frame: fixed navy sidebar on desktop, compact top bar with a menu on phones.
export function Shell({ nav, user, orgs, currentOrgId, providerLink, banner, children }: ShellProps) {
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15rem_1fr]">
      {/* The column carries the colour so it reaches the bottom of long pages; the sidebar inside stays put while you scroll. */}
      <div className="hidden border-r border-line bg-sidebar lg:block">
        <aside className="text-ink lg:sticky lg:top-0 lg:flex lg:h-screen lg:flex-col">
          <Link href="/" className="flex items-center gap-2.5 px-5 py-5">
            <Logo />
            <span className="text-lg font-semibold tracking-tight">NightWatch</span>
          </Link>
          <StatusBlock />
          <SidebarNav items={nav} />
          <div className="mt-auto border-t border-white/10 px-5 py-4 text-sm">
            <div className="truncate font-medium">{user.name}</div>
            <div className="truncate text-white/60">{user.email}</div>
            <div className="mt-3 flex gap-4">
              {providerLink && (
                <Link href="/provider" className="text-white/80 underline-offset-4 hover:underline">
                  Provider view
                </Link>
              )}
              <SignOutButton className="text-white/80 underline-offset-4 hover:underline" />
            </div>
          </div>
        </aside>
      </div>

      <div className="min-w-0">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-line bg-sidebar px-4 py-2.5 lg:px-8">
          <div className="flex items-center gap-2 lg:hidden">
            <MobileNav items={nav} user={user} providerLink={providerLink} />
            <Logo />
          </div>
          {orgs && orgs.length > 0 && currentOrgId ? (
            <OrgSwitcher orgs={orgs} currentOrgId={currentOrgId} />
          ) : (
            <span className="text-sm font-medium text-muted">Provider console</span>
          )}
        </header>
        {banner}
        <main className="mx-auto max-w-6xl px-4 py-6 lg:px-8 lg:py-8">{children}</main>
      </div>
    </div>
  );
}
