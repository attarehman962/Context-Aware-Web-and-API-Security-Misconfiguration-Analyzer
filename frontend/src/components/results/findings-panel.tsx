"use client";

import { FilterX, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

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
  scanId: string;
}

/**
 * Ranking toggle, filters and the ranked list, with their empty states.
 * Each row expands into the finding detail; chain links in a detail open
 * the linked finding (clearing filters that hide it) and move focus there.
 */
export function FindingsPanel({
  findings,
  chains,
  targetUrl,
  view,
  onViewChange,
  virtualize,
  scanId,
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
  const findingsById = useMemo(
    () => new Map(findings.map((f) => [f.id, f])),
    [findings],
  );

  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [scrollTo, setScrollTo] = useState<{
    id: string;
    nonce: number;
  } | null>(null);

  function toggle(findingId: string) {
    setExpanded((open) => {
      const next = new Set(open);
      if (!next.delete(findingId)) next.add(findingId);
      return next;
    });
  }

  function showFinding(findingId: string) {
    if (!findingsById.has(findingId)) return;
    setExpanded((open) => new Set(open).add(findingId));
    if (!shown.some((r) => r.finding.id === findingId)) {
      onViewChange({ ...view, filters: NO_FILTERS });
    }
    setScrollTo((last) => ({ id: findingId, nonce: (last?.nonce ?? 0) + 1 }));
  }

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
          scanId={scanId}
          findingsById={findingsById}
          expanded={expanded}
          onToggle={toggle}
          onShowFinding={showFinding}
          scrollTo={scrollTo}
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
