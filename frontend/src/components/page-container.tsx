import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** The page's <main> landmark at the shared width and padding. */
export function PageContainer({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <main
      id="main"
      tabIndex={-1}
      className={cn(
        "mx-auto flex w-full max-w-6xl flex-1 flex-col gap-6 px-4 py-8 outline-none sm:px-6",
        className,
      )}
    >
      {children}
    </main>
  );
}
