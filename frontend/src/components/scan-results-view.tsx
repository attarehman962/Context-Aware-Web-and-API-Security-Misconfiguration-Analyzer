"use client";

import { RotateCcw, RotateCw, WifiOff } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef } from "react";

import { ErrorState } from "@/components/error-state";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { ExportMenu } from "@/components/results/export-menu";
import { FindingsPanel } from "@/components/results/findings-panel";
import { LiveScanProgress } from "@/components/results/live-progress";
import { ScanSummary } from "@/components/results/scan-summary";
import { Button } from "@/components/ui/button";
import { rankFindings } from "@/lib/findings";
import { rescanHref } from "@/lib/history";
import {
  LIVE_SAFETY_POLL_MS,
  POLL_INTERVAL_MS,
  isFinished,
  useScanResults,
} from "@/lib/queries";
import { ApiRequestError, MAX_RETRIES } from "@/lib/query-client";
import { useFindingsView } from "@/lib/use-findings-view";
import { wasCancelled } from "@/lib/live-status";
import { useLiveScan } from "@/lib/use-live-scan";

/**
 * One scan: follows it live over the SSE stream while it is queued or
 * running (polling every 2 s whenever the stream is down), then shows the
 * summary and the ranked, filterable findings.
 * Unknown ids, failed scans and an unreachable API each get their own
 * message; every part has a loading and an empty state.
 */
export function ScanResultsView({ scanId }: { scanId: string }) {
  // Poll every 2 s, or only as a safety net while live updates arrive.
  const liveRef = useRef(false);
  const results = useScanResults(scanId, {
    pollIntervalMs: () =>
      liveRef.current ? LIVE_SAFETY_POLL_MS : POLL_INTERVAL_MS,
  });
  const scanRunning = !!results.data && !isFinished(results.data.scan);
  const live = useLiveScan(scanId, {
    enabled: scanRunning,
    onTerminal: () => void results.refetch(),
  });
  const { refetch } = results;
  useEffect(() => {
    liveRef.current = live.mode === "live";
    // Dropped to polling: fetch now, which restarts the 2 s cadence.
    if (live.mode === "polling") void refetch();
  }, [live.mode, refetch]);
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

  const { chains } = results.data;
  // A live event is newer than the last poll (up to 15 s old while live),
  // until the final results arrive.
  const polled = results.data.scan;
  const scan =
    live.latest && !isFinished(polled) && live.mode !== "off"
      ? { ...polled, ...live.latest }
      : polled;

  return (
    <div className="flex flex-col gap-6">
      <ScanSummary
        scan={scan}
        ranked={scan.status === "DONE" ? ranked : undefined}
      />
      <div className="flex flex-wrap items-start gap-3">
        <ExportMenu scan={scan} />
        {isFinished(scan) && (
          <Button
            variant="outline"
            nativeButton={false}
            render={<Link href={rescanHref(scan)} />}
          >
            <RotateCcw aria-hidden />
            Re-scan this target
          </Button>
        )}
      </div>

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
          <LiveScanProgress scan={scan} mode={live.mode} />
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

      {wasCancelled(scan) ? (
        <div
          role="status"
          className="rounded-xl border bg-muted/50 p-4 text-sm"
        >
          <p className="font-medium">Scan cancelled</p>
          <p className="text-muted-foreground">
            It was stopped before it finished, so there are no results. Re-scan
            to run it again.
          </p>
        </div>
      ) : (
        scan.status === "FAILED" && (
          <div
            role="alert"
            className="rounded-xl border border-sev-critical-solid bg-sev-critical-bg p-4 text-sev-critical"
          >
            <p className="font-medium">The scan failed</p>
            <p className="text-sm">{scan.error ?? "No reason was given."}</p>
          </div>
        )
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
            scanId={scanId}
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
