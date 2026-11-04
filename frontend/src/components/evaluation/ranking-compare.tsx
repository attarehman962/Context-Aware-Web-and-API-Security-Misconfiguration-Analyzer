import { ArrowDown, ArrowUp, Minus } from "lucide-react";

import type { RankedFinding } from "@/lib/evaluation";
import { cn } from "@/lib/utils";

function Movement({ moved }: { moved: number }) {
  if (moved === 0)
    return (
      <span className="inline-flex items-center gap-0.5 text-xs text-muted-foreground">
        <Minus aria-hidden className="size-3" />
        <span className="sr-only">no change</span>
      </span>
    );
  const up = moved > 0;
  const Icon = up ? ArrowUp : ArrowDown;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 text-xs font-semibold tabular-nums",
        up ? "text-sev-low" : "text-muted-foreground",
      )}
    >
      <Icon aria-hidden className="size-3" />
      <span className="sr-only">{up ? "up" : "down"} </span>
      {Math.abs(moved)}
    </span>
  );
}

function ClassTag({ cls }: { cls: RankedFinding["endpointClass"] }) {
  return (
    <span
      className={cn(
        "rounded px-1 py-px text-[0.7rem] font-medium",
        cls === "CRITICAL"
          ? "bg-sev-critical-bg text-sev-critical"
          : "bg-sev-none-bg text-sev-none",
      )}
    >
      {cls.toLowerCase()} endpoint
    </span>
  );
}

function Column({
  title,
  findings,
  scoreOf,
  rankOf,
  showMovement,
}: {
  title: string;
  findings: RankedFinding[];
  scoreOf: (f: RankedFinding) => number;
  rankOf: (f: RankedFinding) => number;
  showMovement: boolean;
}) {
  const ordered = [...findings].sort(
    (a, b) => rankOf(a) - rankOf(b) || a.id.localeCompare(b.id),
  );
  return (
    <section aria-label={title} className="flex min-w-0 flex-col gap-2">
      <h4 className="text-sm font-medium">{title}</h4>
      <ol className="flex flex-col gap-1">
        {ordered.map((f) => (
          <li
            key={f.id}
            data-finding={f.id}
            data-moved={f.moved}
            className={cn(
              "grid grid-cols-[2rem_1fr_auto] items-center gap-2 rounded-md border px-2 py-1.5",
              showMovement && f.moved > 0 && "border-viz-1 ring-1 ring-viz-1",
              showMovement && f.moved < 0 && "border-dashed",
            )}
          >
            <span className="text-xs text-muted-foreground tabular-nums">
              #{rankOf(f)}
            </span>
            <span className="flex min-w-0 flex-col">
              <span className="truncate text-sm" title={f.title}>
                {f.title}
              </span>
              <span className="flex items-center gap-1.5">
                <span className="font-mono text-[0.7rem] text-muted-foreground">
                  {f.checkId}
                </span>
                <ClassTag cls={f.endpointClass} />
              </span>
            </span>
            <span className="flex flex-col items-end">
              <span className="text-sm font-semibold tabular-nums">
                {scoreOf(f).toFixed(1)}
              </span>
              {showMovement ? <Movement moved={f.moved} /> : null}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** The same findings ranked by base score (left) and context-aware score
 * (right); rows that climbed are highlighted, drops get a dashed border. */
export function RankingCompare({ findings }: { findings: RankedFinding[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <Column
        title="Before: ranked by CVSS base score"
        findings={findings}
        scoreOf={(f) => f.base}
        rankOf={(f) => f.baseRank}
        showMovement={false}
      />
      <Column
        title="After: ranked by context-aware score"
        findings={findings}
        scoreOf={(f) => f.final}
        rankOf={(f) => f.finalRank}
        showMovement
      />
    </div>
  );
}
