/**
 * Test harness for FindingsPanel (used by the *.test.tsx files next to it).
 * The panel is controlled; this holds the view like the URL hook does, and
 * provides a query client for the finding-detail requests.
 */

import { QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

import type { Finding } from "@/lib/api-types";
import { NO_FILTERS, type FindingsView } from "@/lib/findings";
import { makeQueryClient } from "@/lib/query-client";
import { DONE_SCAN_ID, resultsDone } from "@/mocks/fixtures";

import { FindingsPanel } from "./findings-panel";

export const DEFAULT_VIEW: FindingsView = {
  rankBy: "final",
  filters: NO_FILTERS,
};

export function Harness({
  findings = resultsDone.findings,
  initial = DEFAULT_VIEW,
  onViewChange,
  virtualize,
}: {
  findings?: Finding[];
  initial?: FindingsView;
  onViewChange?: (view: FindingsView) => void;
  virtualize?: boolean;
}) {
  const [view, setView] = useState(initial);
  const [queryClient] = useState(makeQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      <FindingsPanel
        findings={findings}
        chains={resultsDone.chains}
        targetUrl={resultsDone.scan.url}
        scanId={DONE_SCAN_ID}
        view={view}
        onViewChange={(next) => {
          setView(next);
          onViewChange?.(next);
        }}
        virtualize={virtualize}
      />
    </QueryClientProvider>
  );
}
