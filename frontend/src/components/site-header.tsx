import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { NavLinks, NavList } from "@/components/nav-links";
import { ThemeToggle } from "@/components/theme-toggle";

export function SiteHeader() {
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center gap-4 px-4 sm:px-6">
        <Link
          href="/"
          className="flex items-center gap-2 font-heading font-semibold tracking-tight"
        >
          <ShieldCheck aria-hidden className="size-5" />
          CAWASMA
        </Link>
        <nav aria-label="Main" className="flex-1">
          {/* usePathname suspends on routes with unknown dynamic params. */}
          <Suspense fallback={<NavList />}>
            <NavLinks />
          </Suspense>
        </nav>
        <ThemeToggle />
      </div>
    </header>
  );
}
