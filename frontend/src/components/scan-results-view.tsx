"use client";

import { ErrorState } from "@/components/error-state";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusPill } from "@/components/status-pill";
import { useScanResults } from "@/lib/queries";
import { SEVERITY_ORDER } from "@/lib/severity";

/**
 * Live status of one scan (polls until DONE or FAILED). The full results
 * view replaces the DONE summary later.
 */
export function ScanStatusView({ scanId }: { scanId: string }) {
  const results = useScanResults(scanId);

  if (results.isPending) return <LoadingSkeleton variant="card" />;
  if (results.isError) {
    return (
      <ErrorState error={results.error} onRetry={() => results.refetch()} />
    );
  }

  const { scan, findings } = results.data;
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h1 className="font-heading text-2xl font-semibold tracking-tight break-all">
          {scan.url}
        </h1>
        <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
          <StatusPill status={scan.status} progress={scan.progress} />
          {scan.stage && scan.status === "RUNNING" && (
            <span>Stage: {scan.stage}</span>
          )}
        </div>
      </div>

      {(scan.status === "QUEUED" || scan.status === "RUNNING") && (
        <div className="flex flex-col gap-2" aria-live="polite">
          <div
            role="progressbar"
            aria-label="Scan progress"
            aria-valuenow={scan.progress}
            aria-valuemin={0}
            aria-valuemax={100}
            className="h-2 w-full overflow-hidden rounded-full bg-muted"
          >
            <div
              className="h-full rounded-full bg-sev-low-solid transition-[width] motion-reduce:transition-none"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <p className="text-sm text-muted-foreground">
            {scan.status === "QUEUED"
              ? "Waiting for a worker to pick up the scan…"
              : `${scan.progress}% done. This page updates by itself.`}
          </p>
        </div>
      )}

      {scan.status === "FAILED" && (
        <div
          role="alert"
          className="rounded-xl border border-sev-critical-solid bg-sev-critical-bg p-4 text-sev-critical"
        >
          <p className="font-medium">The scan failed</p>
          <p className="text-sm">{scan.error ?? "No reason was given."}</p>
        </div>
      )}

      {scan.status === "DONE" && (
        <div className="flex flex-col gap-3">
          <p className="font-medium">
            {findings.length} finding{findings.length === 1 ? "" : "s"}
          </p>
          <ul className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.map((severity) => (
              <li key={severity} className="flex items-center gap-1.5">
                <SeverityBadge severity={severity} size="sm" />
                <span className="tabular-nums">
                  {scan.severity_counts[
                    severity.toLowerCase() as keyof typeof scan.severity_counts
                  ] ?? 0}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
