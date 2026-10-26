import { ArrowDown, ArrowUp } from "lucide-react";

import { SeverityBadge } from "@/components/severity-badge";
import { StatusPill } from "@/components/status-pill";
import type { ScanStatus, Severity } from "@/lib/api-types";
import type { RankedFinding } from "@/lib/findings";
import { severityShifts } from "@/lib/findings";
import { SEVERITY_ORDER } from "@/lib/severity";

/**
 * Target, scan time, findings per severity and how many findings context
 * moved to a different severity than their CVSS base score gives them.
 */
export function ScanSummary({
  scan,
  ranked,
}: {
  scan: ScanStatus;
  /** Present once the scan is DONE. */
  ranked?: RankedFinding[];
}) {
  const shifts = ranked ? severityShifts(ranked) : null;
  return (
    <section aria-label="Scan summary" className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <p className="text-sm text-muted-foreground">Target</p>
        <h1 className="font-heading text-2xl font-semibold tracking-tight break-all">
          {scan.url}
        </h1>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
          <StatusPill status={scan.status} progress={scan.progress} />
          <span>{scanTime(scan)}</span>
          <span>
            Depth {scan.options.crawl_depth}
            {scan.options.passive_only ? " · passive only" : ""}
            {scan.options.use_wordlist ? "" : " · no wordlist"}
          </span>
        </div>
      </div>

      {scan.status === "DONE" && ranked && shifts && (
        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <ul
            aria-label="Findings per severity"
            className="grid grid-cols-2 gap-2 sm:grid-cols-5"
          >
            {SEVERITY_ORDER.map((severity) => (
              <SeverityCount
                key={severity}
                severity={severity}
                count={countOf(scan, severity)}
              />
            ))}
          </ul>
          <div
            data-testid="context-shift"
            className="flex flex-col justify-center gap-1 rounded-xl border px-4 py-3 text-sm"
          >
            <p className="flex items-center gap-1.5 font-medium">
              <ArrowUp aria-hidden className="size-4 text-sev-critical" />
              {plural(shifts.up, "finding")} moved up a severity
            </p>
            {shifts.down > 0 && (
              <p className="flex items-center gap-1.5 text-muted-foreground">
                <ArrowDown aria-hidden className="size-4" />
                {plural(shifts.down, "finding")} moved down
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              because of context (final vs CVSS base severity)
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

function SeverityCount({
  severity,
  count,
}: {
  severity: Severity;
  count: number;
}) {
  return (
    <li
      data-severity-count={severity}
      className="flex items-center justify-between gap-2 rounded-xl border px-3 py-2"
    >
      <SeverityBadge severity={severity} size="sm" />
      <span className="text-lg font-semibold tabular-nums">{count}</span>
    </li>
  );
}

function countOf(scan: ScanStatus, severity: Severity): number {
  return scan.severity_counts[
    severity.toLowerCase() as keyof ScanStatus["severity_counts"]
  ];
}

function scanTime(scan: ScanStatus): string {
  const start = scan.started_at ?? scan.created_at;
  const when = new Date(start).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  if (!scan.completed_at || !scan.started_at) return `Started ${when}`;
  const seconds =
    (Date.parse(scan.completed_at) - Date.parse(scan.started_at)) / 1000;
  return `Scanned ${when} · took ${formatDuration(seconds)}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 1) return "under 1 s";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s ? `${m} min ${s} s` : `${m} min`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
