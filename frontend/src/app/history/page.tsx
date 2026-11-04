import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanHistory } from "@/components/history/scan-history";
import { LoadingSkeleton } from "@/components/loading-skeleton";

export const metadata: Metadata = { title: "History · CAWASMA" };

export default function HistoryPage() {
  return (
    <>
      <h1 className="font-heading text-2xl font-semibold tracking-tight">
        Scan history
      </h1>
      {/* The search and page come from the URL query. */}
      <Suspense fallback={<LoadingSkeleton variant="table" rows={8} />}>
        <ScanHistory />
      </Suspense>
    </>
  );
}
