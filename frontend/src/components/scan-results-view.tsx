"use client";

import { RotateCw, WifiOff } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

import { ErrorState } from "@/components/error-state";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { FindingsPanel } from "@/components/results/findings-panel";
import { ScanSummary } from "@/components/results/scan-summary";
import { Button } from "@/components/ui/button";
import type { ScanStatus } from "@/lib/api-types";
import { rankFindings } from "@/lib/findings";
import { useScanResults } from "@/lib/queries";
import { ApiRequestError, MAX_RETRIES } from "@/lib/query-client";
import { useFindingsView } from "@/lib/use-findings-view";

/**
 * One scan: polls GET /api/results/{id} every 2 s while it is queued or
 * running, then shows the summary and the ranked, filterable findings.
 * Unknown ids, failed scans and an unreachable API each get their own
 * message; every part has a loading and an empty state.
 */
export function ScanResultsView({ scanId }: { scanId: string }) {
  const results = useScanResults(scanId);
  const [view, setView] = useFindingsView();
  const findings = results.data?.findings;
  const ranked = useMemo(
    () => (findings ? rankFindings(findings) : undefined),
    [findings],
  );

  const retrying = results.isFetching && results.failureCount > 0;
  const retryNote = retrying
    ? `Can't reach the API. Retrying (attempt ${results.failureCount} of ${MAX_RETRIES})…`
    : null;

  if (results.isPending) {
    return (
      <div className="flex flex-col gap-6">
        {retryNote && <RetryNote text={retryNote} />}
        <LoadingSkeleton variant="card" label="Loading scan summary…" />
        <LoadingSkeleton variant="table" rows={6} label="Loading findings…" />
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

  const { scan, chains } = results.data;

  return (
    <div className="flex flex-col gap-6">
      <ScanSummary
        scan={scan}
        ranked={scan.status === "DONE" ? ranked : undefined}
      />

      {retryNote && <RetryNote text={retryNote} />}
      {results.isError && (
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
        <>
          <Progress scan={scan} />
          <section aria-label="Findings" className="flex flex-col gap-2">
            <p className="text-sm text-muted-foreground">
              Findings appear here when the scan is done.
            </p>
            <LoadingSkeleton
              variant="table"
              rows={4}
              label="Waiting for findings…"
            />
          </section>
        </>
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

      {scan.status === "DONE" && findings && (
        <section
          aria-labelledby="findings-heading"
          className="flex flex-col gap-4"
        >
          <h2
            id="findings-heading"
            className="font-heading text-lg font-semibold"
          >
            Findings
          </h2>
          <FindingsPanel
            findings={findings}
            chains={chains}
            targetUrl={scan.url}
            view={view}
            onViewChange={setView}
          />
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
