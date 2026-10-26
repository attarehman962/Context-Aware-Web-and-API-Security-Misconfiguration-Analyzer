"use client";

import { History, ScanSearch } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

export const NAV_ITEMS = [
  { href: "/", label: "New scan", icon: ScanSearch },
  { href: "/history", label: "History", icon: History },
] as const;

/** Top-nav links; the current page is marked with aria-current. */
export function NavLinks() {
  return <NavList pathname={usePathname()} />;
}

/** Same links without an active item (Suspense fallback while prerendering). */
export function NavList({ pathname }: { pathname?: string | null }) {
  return (
    <ul className="flex items-center gap-1">
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
        const active = pathname === href;
        return (
          <li key={href}>
            <Link
              href={href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-sm font-medium transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50",
                active
                  ? "bg-muted text-foreground"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon aria-hidden className="size-4" />
              {label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
