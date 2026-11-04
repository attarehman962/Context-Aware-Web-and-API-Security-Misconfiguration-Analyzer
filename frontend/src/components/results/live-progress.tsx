"use client";

import { Check, CircleStop, Radio, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import type { ScanStatus } from "@/lib/api-types";
import { STEPS, stepIndex } from "@/lib/live-status";
import { useCancelScan } from "@/lib/queries";
import { ApiRequestError } from "@/lib/query-client";
import type { LiveMode } from "@/lib/use-live-scan";
import { cn } from "@/lib/utils";

import { formatDuration } from "./scan-summary";

/**
 * Progress of a queued or running scan: the three steps, a progress bar,
 * elapsed time, the counts so far (`progress_detail`, contract 1.3), how the
 * page is being updated, and a Cancel button.
 */
export function LiveScanProgress({
  scan,
  mode,
}: {
  /** The newest status: from the live stream when it is up, else polled. */
  scan: ScanStatus;
  mode: LiveMode;
}) {
  const queued = scan.status === "QUEUED";
  const current = queued ? -1 : stepIndex(scan.stage);
  const detail = scan.progress_detail ?? {};
  const elapsed = useElapsed(scan.started_at ?? scan.created_at);
  const count = (n: number | undefined) => (n === undefined ? "—" : String(n));

  return (
    <section
      aria-label="Scan progress"
      className="flex flex-col gap-4 rounded-xl border p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <ol
          className="flex flex-wrap items-center gap-2 text-sm"
          aria-label="Steps"
        >
          {STEPS.map((step, i) => {
            const done = current > i;
            const active = current === i;
            return (
              <li
                key={step.id}
                data-step={step.id}
                data-state={done ? "done" : active ? "active" : "todo"}
                aria-current={active ? "step" : undefined}
                className={cn(
                  "flex items-center gap-1.5 rounded-full border px-2.5 py-0.5",
                  done &&
                    "border-sev-success-solid bg-sev-success-bg text-sev-success",
                  active &&
                    "border-sev-low-solid bg-sev-low-bg font-medium text-sev-low",
                  !done && !active && "text-muted-foreground",
                )}
              >
                {done ? (
                  <Check aria-hidden className="size-3.5" />
                ) : (
                  <span aria-hidden className="tabular-nums">
                    {i + 1}
                  </span>
                )}
                {step.label}
                <span className="sr-only">
                  {done ? " (done)" : active ? " (in progress)" : ""}
                </span>
              </li>
            );
          })}
        </ol>
        <ConnectionBadge mode={mode} />
      </div>

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

      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
        <Stat label="Progress" value={`${scan.progress}%`} />
        <Stat label="Elapsed" value={elapsed} testId="elapsed" />
        <Stat
          label="Endpoints found"
          value={count(detail.endpoints_found)}
          testId="endpoints-found"
        />
        <Stat
          label="Endpoints checked"
          value={count(detail.endpoints_checked)}
          testId="endpoints-checked"
        />
        <Stat
          label="Findings so far"
          value={count(detail.findings)}
          testId="findings-so-far"
        />
      </dl>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground" aria-live="polite">
          {queued
            ? "Queued, waiting for a worker…"
            : `${scan.progress}% done${scan.stage ? ` (${scan.stage})` : ""}.`}
        </p>
        <CancelScan scanId={scan.scan_id} />
      </div>
    </section>
  );
}

/** Two-step cancel, so one stray click does not throw away a scan. */
function CancelScan({ scanId }: { scanId: string }) {
  const cancel = useCancelScan(scanId);
  const [confirming, setConfirming] = useState(false);

  if (cancel.isSuccess) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        Cancelling: the scan stops at its next step.
      </p>
    );
  }
  const finished =
    cancel.error instanceof ApiRequestError &&
    cancel.error.error.kind !== "network" &&
    cancel.error.error.code === "SCAN_FINISHED";

  return (
    <div className="flex flex-wrap items-center gap-2">
      {cancel.isError && !finished && (
        <p role="alert" className="text-sm text-sev-critical">
          Could not cancel: {cancel.error.message}
        </p>
      )}
      {confirming ? (
        <>
          <span className="text-sm">
            Stop this scan? Partial results are not kept.
          </span>
          <Button
            variant="destructive"
            size="sm"
            disabled={cancel.isPending}
            onClick={() => cancel.mutate()}
          >
            {cancel.isPending ? "Cancelling…" : "Yes, cancel scan"}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setConfirming(false)}
          >
            Keep scanning
          </Button>
        </>
      ) : (
        <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
          <CircleStop aria-hidden />
          Cancel scan
        </Button>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  testId,
}: {
  label: string;
  value: string;
  testId?: string;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd data-testid={testId} className="font-medium tabular-nums">
        {value}
      </dd>
    </div>
  );
}

function ConnectionBadge({ mode }: { mode: LiveMode }) {
  if (mode === "off") return null;
  const live = mode === "live";
  return (
    <span
      data-live-mode={mode}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium",
        live
          ? "border-sev-success-solid bg-sev-success-bg text-sev-success"
          : "border-sev-medium-solid bg-sev-medium-bg text-sev-medium",
      )}
    >
      {live ? (
        <Radio aria-hidden className="size-3.5" />
      ) : (
        <RefreshCw aria-hidden className="size-3.5" />
      )}
      {mode === "live"
        ? "Live"
        : mode === "connecting"
          ? "Connecting…"
          : "Live updates interrupted: checking every 2 s"}
    </span>
  );
}

/** "12 s", "1 min 5 s" since `since`, ticking every second. */
function useElapsed(since: string): string {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const seconds = Math.max(0, (now - Date.parse(since)) / 1000);
  return seconds < 1 ? "0 s" : formatDuration(seconds);
}
