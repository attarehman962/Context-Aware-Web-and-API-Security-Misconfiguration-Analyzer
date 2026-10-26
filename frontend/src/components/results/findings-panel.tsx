"use client";

import { FilterX, ShieldCheck } from "lucide-react";
import { useMemo } from "react";

import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import type { Chain, Finding } from "@/lib/api-types";
import {
  NO_FILTERS,
  applyFilters,
  filterOptions,
  rankFindings,
  type FindingsView,
} from "@/lib/findings";

import { FindingsFilters } from "./findings-filters";
import { FindingsList } from "./findings-list";

export interface FindingsPanelProps {
  findings: Finding[];
  chains: Chain[];
  targetUrl: string;
  view: FindingsView;
  onViewChange: (view: FindingsView) => void;
  /** Passed to FindingsList (tests force it on or off). */
  virtualize?: boolean;
}

/** Ranking toggle, filters and the ranked list, with their empty states. */
export function FindingsPanel({
  findings,
  chains,
  targetUrl,
  view,
  onViewChange,
  virtualize,
}: FindingsPanelProps) {
  const ranked = useMemo(
    () => rankFindings(findings, view.rankBy),
    [findings, view.rankBy],
  );
  const shown = useMemo(
    () => applyFilters(ranked, view.filters),
    [ranked, view.filters],
  );
  const options = useMemo(() => filterOptions(findings), [findings]);

  if (findings.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No misconfigurations found"
        description="None of the checks fired on the endpoints this scan discovered."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <FindingsFilters
        filters={view.filters}
        onFiltersChange={(filters) => onViewChange({ ...view, filters })}
        rankBy={view.rankBy}
        onRankByChange={(rankBy) => onViewChange({ ...view, rankBy })}
        options={options}
        shown={shown.length}
        total={findings.length}
      />
      {shown.length > 0 ? (
        <FindingsList
          ranked={shown}
          total={findings.length}
          rankBy={view.rankBy}
          chains={chains}
          targetUrl={targetUrl}
          virtualize={virtualize}
        />
      ) : (
        <EmptyState
          icon={FilterX}
          title="No findings match these filters"
          description={`All ${findings.length} findings are hidden by the current filters.`}
          action={
            <Button
              variant="outline"
              onClick={() => onViewChange({ ...view, filters: NO_FILTERS })}
            >
              Clear filters
            </Button>
          }
        />
      )}
    </div>
  );
}
