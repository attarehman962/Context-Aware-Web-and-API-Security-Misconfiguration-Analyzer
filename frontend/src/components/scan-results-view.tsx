"use client";

import { RotateCw, ShieldCheck, WifiOff } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { FindingsTable } from "@/components/findings-table";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusPill } from "@/components/status-pill";
import { Button } from "@/components/ui/button";
import type { ScanStatus } from "@/lib/api-types";
import { useScanResults } from "@/lib/queries";
import { ApiRequestError, MAX_RETRIES } from "@/lib/query-client";
import { SEVERITY_ORDER } from "@/lib/severity";

/**
 * One scan: polls GET /api/results/{id} every 2 s while it is queued or
 * running, then shows the findings. Unknown ids, failed scans and an
 * unreachable API each get their own message.
 */
export function ScanResultsView({ scanId }: { scanId: string }) {
  const results = useScanResults(scanId);
  const retrying = results.isFetching && results.failureCount > 0;
  const retryNote = retrying
    ? `Can't reach the API. Retrying (attempt ${results.failureCount} of ${MAX_RETRIES})…`
    : null;

  if (results.isPending) {
    return (
      <div className="flex flex-col gap-3">
        {retryNote && <RetryNote text={retryNote} />}
        <LoadingSkeleton variant="card" label="Loading scan…" />
      </div>
    );
  }

  if (results.isError && !results.data) {
    if (isNotFound(results.error)) {
      return (
        <ErrorState
          error={results.error}
          title="Scan not found"
          message="There is no scan with this id. The link may be wrong, or the scan was deleted."
          action={
            <Button nativeButton={false} render={<Link href="/" />}>
              Start a new scan
            </Button>
          }
        />
      );
    }
    return (
      <ErrorState
        error={results.error}
        message={`${results.error.message} Tried ${MAX_RETRIES + 1} times; check that the API is running, then try again.`}
        onRetry={() => results.refetch()}
      />
    );
  }

  const { scan, findings } = results.data;
  const lostConnection = results.isError;

  return (
    <div className="flex flex-col gap-6">
      <ScanHeader scan={scan} />

      {retryNote && <RetryNote text={retryNote} />}
      {lostConnection && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-sev-critical-solid bg-sev-critical-bg p-4 text-sm text-sev-critical"
        >
          <p>
            <span className="font-medium">Lost connection to the API.</span>{" "}
            Showing the last update from{" "}
            {new Date(results.dataUpdatedAt).toLocaleTimeString()}.
          </p>
          <Button variant="outline" size="sm" onClick={() => results.refetch()}>
            <RotateCw aria-hidden />
            Try again
          </Button>
        </div>
      )}

      {(scan.status === "QUEUED" || scan.status === "RUNNING") && (
        <Progress scan={scan} />
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
        <section
          aria-labelledby="findings-heading"
          className="flex flex-col gap-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2
              id="findings-heading"
              className="font-heading text-lg font-semibold"
            >
              {findings.length} finding{findings.length === 1 ? "" : "s"}
            </h2>
            <SeverityCounts scan={scan} />
          </div>
          {findings.length > 0 ? (
            <FindingsTable findings={findings} targetUrl={scan.url} />
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="No misconfigurations found"
              description="None of the checks fired on the endpoints this scan discovered."
            />
          )}
        </section>
      )}
    </div>
  );
}

function isNotFound(error: unknown): boolean {
  return (
    error instanceof ApiRequestError &&
    error.error.kind === "client" &&
    (error.error.code === "NOT_FOUND" ||
      error.error.code === "VALIDATION_ERROR")
  );
}

function ScanHeader({ scan }: { scan: ScanStatus }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">Target</p>
      <h1 className="font-heading text-2xl font-semibold tracking-tight break-all">
        {scan.url}
      </h1>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted-foreground">
        <StatusPill status={scan.status} progress={scan.progress} />
        <span>Started {formatTime(scan.started_at ?? scan.created_at)}</span>
        {scan.completed_at && (
          <span>Finished {formatTime(scan.completed_at)}</span>
        )}
        <span>
          Depth {scan.options.crawl_depth}
          {scan.options.passive_only ? " · passive only" : ""}
          {scan.options.use_wordlist ? "" : " · no wordlist"}
        </span>
      </div>
    </div>
  );
}

function Progress({ scan }: { scan: ScanStatus }) {
  return (
    <div className="flex flex-col gap-2">
      <div
        role="progressbar"
        aria-label="Scan progress"
        aria-valuenow={scan.progress}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={`${scan.progress}%${scan.stage ? `, ${scan.stage}` : ""}`}
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        <div
          className="h-full rounded-full bg-sev-low-solid transition-[width] motion-reduce:transition-none"
          style={{ width: `${scan.progress}%` }}
        />
      </div>
      <p className="text-sm text-muted-foreground" aria-live="polite">
        {scan.status === "QUEUED"
          ? "Queued, waiting to start…"
          : `${scan.progress}% done${scan.stage ? ` (${scan.stage})` : ""}. This page updates by itself.`}
      </p>
    </div>
  );
}

function SeverityCounts({ scan }: { scan: ScanStatus }) {
  return (
    <ul className="flex flex-wrap gap-3" aria-label="Findings per severity">
      {SEVERITY_ORDER.map((severity) => (
        <li key={severity} className="flex items-center gap-1.5 text-sm">
          <SeverityBadge severity={severity} size="sm" />
          <span className="tabular-nums">
            {
              scan.severity_counts[
                severity.toLowerCase() as keyof ScanStatus["severity_counts"]
              ]
            }
          </span>
        </li>
      ))}
    </ul>
  );
}

function RetryNote({ text }: { text: string }) {
  return (
    <p
      role="status"
      className="flex items-center gap-2 text-sm text-sev-medium"
    >
      <WifiOff aria-hidden className="size-4" />
      {text}
    </p>
  );
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}
