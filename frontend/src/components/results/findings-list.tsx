"use client";

import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, Link2 } from "lucide-react";
import { useLayoutEffect, useRef, useState } from "react";

import { ScoreDisplay } from "@/components/score-display";
import { SeverityBadge } from "@/components/severity-badge";
import type { Chain } from "@/lib/api-types";
import {
  categoryLabel,
  displayEndpoint,
  type RankBy,
  type RankedFinding,
} from "@/lib/findings";
import { SEVERITY } from "@/lib/severity";
import { cn } from "@/lib/utils";

/** Lists longer than this render only the rows in view. */
export const VIRTUALIZE_AFTER = 60;
const ESTIMATED_ROW_PX = 92;

export interface FindingsListProps {
  ranked: RankedFinding[];
  rankBy: RankBy;
  chains: Chain[];
  targetUrl: string;
  /** Findings in the scan (ranks are out of this, not the filtered list). */
  total?: number;
  /** Force (or turn off) virtualisation; defaults to the list length. */
  virtualize?: boolean;
}

/**
 * Ranked findings with a severity colour band. Each row shows its rank in
 * the current order and how far the other order would move it, so the
 * effect of context on the ranking is visible row by row.
 */
export function FindingsList({
  ranked,
  rankBy,
  chains,
  targetUrl,
  total = ranked.length,
  virtualize = ranked.length > VIRTUALIZE_AFTER,
}: FindingsListProps) {
  const chainCode = new Map(chains.map((c) => [c.id, c.chain_code]));
  const row = (r: RankedFinding) => (
    <FindingRow
      ranked={r}
      total={total}
      rankBy={rankBy}
      chainCodes={r.finding.chain_ids.map((id) => chainCode.get(id) ?? "chain")}
      targetUrl={targetUrl}
    />
  );

  return virtualize ? (
    <VirtualRows ranked={ranked} renderRow={row} />
  ) : (
    <ol aria-label="Findings" className="flex flex-col gap-2">
      {ranked.map((r) => (
        <li key={r.finding.id}>{row(r)}</li>
      ))}
    </ol>
  );
}

function VirtualRows({
  ranked,
  renderRow,
}: {
  ranked: RankedFinding[];
  renderRow: (r: RankedFinding) => React.ReactNode;
}) {
  const listRef = useRef<HTMLOListElement>(null);
  const [offset, setOffset] = useState(0);
  useLayoutEffect(() => {
    setOffset(listRef.current?.offsetTop ?? 0);
  }, []);

  const virtualizer = useWindowVirtualizer({
    count: ranked.length,
    estimateSize: () => ESTIMATED_ROW_PX,
    overscan: 8,
    scrollMargin: offset,
    getItemKey: (i) => ranked[i].finding.id,
  });

  return (
    <ol
      ref={listRef}
      aria-label="Findings"
      data-virtualized
      className="relative"
      style={{ height: virtualizer.getTotalSize() }}
    >
      {virtualizer.getVirtualItems().map((item) => (
        <li
          key={item.key}
          data-index={item.index}
          ref={virtualizer.measureElement}
          aria-setsize={ranked.length}
          aria-posinset={item.index + 1}
          className="absolute top-0 left-0 w-full pb-2"
          style={{ transform: `translateY(${item.start - offset}px)` }}
        >
          {renderRow(ranked[item.index])}
        </li>
      ))}
    </ol>
  );
}

function FindingRow({
  ranked,
  total,
  rankBy,
  chainCodes,
  targetUrl,
}: {
  ranked: RankedFinding;
  total: number;
  rankBy: RankBy;
  chainCodes: string[];
  targetUrl: string;
}) {
  const {
    finding: f,
    finalRank,
    baseRank,
    baseSeverity,
    severityShift,
  } = ranked;
  // The band and badge follow the score being ranked by.
  const shown = rankBy === "final" ? f.severity_bucket : baseSeverity;
  const rank = rankBy === "final" ? finalRank : baseRank;
  const otherRank = rankBy === "final" ? baseRank : finalRank;

  return (
    <article
      data-finding-id={f.id}
      data-check-id={f.check_id}
      data-rank={rank}
      aria-label={`${rank} of ${total}: ${f.title}`}
      className="flex overflow-hidden rounded-xl border bg-card"
    >
      <span
        aria-hidden
        data-band={shown}
        className={cn("w-1.5 shrink-0", SEVERITY[shown].fill)}
      />
      <div className="grid flex-1 gap-x-4 gap-y-2 p-3 sm:grid-cols-[3.5rem_7rem_1fr_auto] sm:items-start">
        <div className="flex items-baseline gap-2 sm:flex-col sm:gap-0.5">
          <span className="font-heading text-lg font-semibold tabular-nums">
            #{rank}
          </span>
          <RankDelta rank={rank} otherRank={otherRank} rankBy={rankBy} />
        </div>

        <div className="flex flex-col items-start gap-1.5">
          <SeverityBadge severity={shown} size="sm" />
          <ScoreDisplay
            base={f.base_score}
            final={f.final_score}
            severity={f.severity_bucket}
            compact
          />
        </div>

        <div className="flex min-w-0 flex-col gap-1">
          <p className="font-medium">
            <span className="mr-2 font-mono text-xs text-muted-foreground">
              {f.check_id}
            </span>
            {f.title}
          </p>
          <p className="font-mono text-xs break-all text-muted-foreground">
            {f.endpoint_url ? (
              <span title={f.endpoint_url}>
                {displayEndpoint(f.endpoint_url, targetUrl)}
              </span>
            ) : (
              "Whole host"
            )}
          </p>
          {rankBy === "final" && severityShift !== 0 && (
            <p className="text-xs text-muted-foreground">
              {severityShift > 0 ? "Raised" : "Lowered"} from{" "}
              {SEVERITY[baseSeverity].label} by context
            </p>
          )}
        </div>

        <div className="flex flex-wrap gap-1.5 sm:justify-end">
          <span className="rounded-md bg-muted px-1.5 py-0.5 text-xs">
            {categoryLabel(f.category)}
          </span>
          {chainCodes.map((code) => (
            <span
              key={code}
              className="inline-flex items-center gap-1 rounded-md border border-sev-critical-solid px-1.5 py-0.5 text-xs text-sev-critical"
            >
              <Link2 aria-hidden className="size-3" />
              In chain {code}
            </span>
          ))}
        </div>
      </div>
    </article>
  );
}

/** "↑3 by context" in final order; "↓3 without context" in base order. */
function RankDelta({
  rank,
  otherRank,
  rankBy,
}: {
  rank: number;
  otherRank: number;
  rankBy: RankBy;
}) {
  const moved = otherRank - rank; // > 0: higher in this order than the other
  if (moved === 0) {
    return <span className="text-xs text-muted-foreground">same rank</span>;
  }
  const Icon = moved > 0 ? ArrowUp : ArrowDown;
  const other = rankBy === "final" ? "base score" : "context-aware score";
  return (
    <span
      data-rank-delta={moved}
      title={`#${otherRank} by ${other}`}
      className="inline-flex items-center gap-0.5 text-xs text-muted-foreground"
    >
      <Icon aria-hidden className="size-3" />
      {Math.abs(moved)}
      <span className="sr-only">
        {" "}
        place{Math.abs(moved) === 1 ? "" : "s"} {moved > 0 ? "higher" : "lower"}{" "}
        than by {other} (#{otherRank})
      </span>
    </span>
  );
}
