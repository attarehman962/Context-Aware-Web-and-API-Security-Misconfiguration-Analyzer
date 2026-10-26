import { ArrowRight } from "lucide-react";

import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/api-types";
import { SEVERITY, severityFromScore } from "@/lib/severity";

export interface ScoreDisplayProps {
  /** Official CVSS v3.1 base score of the check (`base_score`). */
  base: number;
  /** CAWASMA context-aware score (`final_score`); not an official CVSS score. */
  final: number;
  /** The finding's `severity_bucket`; defaults to the CVSS rating of `final`. */
  severity?: Severity;
  /** Hide the captions under the numbers (tables). */
  compact?: boolean;
  className?: string;
}

export function formatScore(score: number): string {
  return score.toFixed(1);
}

/**
 * Base score -> context-aware score, with an arrow when context changed it.
 * Each number is coloured by its own severity and the change is spelled out
 * for screen readers.
 */
export function ScoreDisplay({
  base,
  final,
  severity,
  compact = false,
  className,
}: ScoreDisplayProps) {
  const finalSeverity = severity ?? severityFromScore(final);
  const changed = formatScore(base) !== formatScore(final);
  const direction = final > base ? "raised" : "lowered";

  const summary = changed
    ? `CVSS base score ${formatScore(base)}, ${direction} by context to ${formatScore(final)} (${SEVERITY[finalSeverity].label})`
    : `Score ${formatScore(final)} (${SEVERITY[finalSeverity].label}); context did not change the CVSS base score`;

  return (
    <span
      data-changed={changed}
      className={cn("inline-flex items-start gap-1.5 tabular-nums", className)}
    >
      <span className="sr-only">{summary}</span>
      {changed && (
        <>
          <Score
            value={base}
            severity={severityFromScore(base)}
            caption="CVSS base"
            compact={compact}
            muted
          />
          <ArrowRight
            aria-hidden
            className="mt-1 size-4 shrink-0 text-muted-foreground"
          />
        </>
      )}
      <Score
        value={final}
        severity={finalSeverity}
        caption={changed ? "Context-aware" : "Score"}
        compact={compact}
      />
    </span>
  );
}

function Score({
  value,
  severity,
  caption,
  compact,
  muted = false,
}: {
  value: number;
  severity: Severity;
  caption: string;
  compact: boolean;
  muted?: boolean;
}) {
  return (
    <span
      aria-hidden
      className="inline-flex flex-col items-center leading-none"
    >
      <span
        className={cn(
          "font-semibold",
          muted ? "text-base text-muted-foreground" : "text-lg",
          !muted && SEVERITY[severity].text,
        )}
      >
        {formatScore(value)}
      </span>
      {!compact && (
        <span className="mt-1 text-[0.7rem] text-muted-foreground">
          {caption}
        </span>
      )}
    </span>
  );
}
