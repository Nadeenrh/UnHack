"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { SignOutButton } from "./SignOutButton";

export interface NavItem {
  href: string;
  label: string;
  /** Small count shown next to the label (e.g. pending approvals). */
  count?: number;
  /** Match only the exact path (for the dashboard / overview item). */
  exact?: boolean;
}

function isActive(pathname: string, item: NavItem) {
  return item.exact ? pathname === item.href : pathname === item.href || pathname.startsWith(item.href + "/");
}

function Count({ n }: { n?: number }) {
  if (!n) return null;
  return <span className="ml-auto rounded-full bg-lantern px-2 text-xs font-semibold text-night">{n}</span>;
}

export function SidebarNav({ items }: { items: NavItem[] }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Main" className="px-3">
      <ul className="space-y-0.5">
        {items.map((item) => {
          const active = isActive(pathname, item);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center rounded-md px-3 py-2 text-sm font-medium ${
                  active ? "bg-raised text-white shadow-[inset_3px_0_0] shadow-info" : "text-white/70 hover:bg-white/6 hover:text-white"
                }`}
              >
                {item.label}
                <Count n={item.count} />
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function MobileNav({
  items,
  user,
  providerLink,
}: {
  items: NavItem[];
  user: { name: string; email: string };
  providerLink?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  useEffect(() => setOpen(false), [pathname]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls="mobile-nav"
        className="rounded-md px-2 py-1.5 text-sm font-medium ring-1 ring-line"
      >
        {open ? "Close" : "Menu"}
      </button>
      {open && (
        <div id="mobile-nav" className="fixed inset-x-0 top-[3.25rem] z-30 border-b border-line bg-sidebar pb-4 text-ink shadow-lg">
          <div className="pt-3">
            <SidebarNav items={items} />
          </div>
          <div className="mt-3 border-t border-white/10 px-6 pt-3 text-sm">
            <div className="font-medium">{user.name}</div>
            <div className="text-white/60">{user.email}</div>
            <div className="mt-3 flex gap-4">
              {providerLink && <Link href="/provider" className="text-white/80 underline">Provider view</Link>}
              <SignOutButton className="text-white/80 underline" />
            </div>
          </div>
        </div>
      )}
    </>
  );
}
