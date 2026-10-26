import type { Metadata } from "next";
import { Suspense } from "react";

import { LoadingSkeleton } from "@/components/loading-skeleton";
import { ScanResultsView } from "@/components/scan-results-view";

export const metadata: Metadata = { title: "Scan · CAWASMA" };

// The id is only known at request time, so reading it needs a Suspense
// boundary under Cache Components.
export default function ScanPage({ params }: PageProps<"/scans/[id]">) {
  return (
    <Suspense fallback={<LoadingSkeleton variant="card" />}>
      {params.then(({ id }) => (
        <ScanResultsView scanId={id} />
      ))}
    </Suspense>
  );
}
