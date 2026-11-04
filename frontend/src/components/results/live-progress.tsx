"use client";

import { Check, Radio, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import type { ScanStatus } from "@/lib/api-types";
import { STEPS, stepIndex, type LiveProgress } from "@/lib/live-status";
import type { LiveMode } from "@/lib/use-live-scan";
import { cn } from "@/lib/utils";

import { formatDuration } from "./scan-summary";

/**
 * Progress of a queued or running scan: the three steps, a progress bar,
 * elapsed time, endpoints checked so far and the current activity. Live
 * events win over the polled status when they are newer.
 */
export function LiveScanProgress({
  scan,
  live,
}: {
  scan: ScanStatus;
  live: { mode: LiveMode; progress: LiveProgress };
}) {
  const { progress, mode } = live;
  const useLive = mode === "live" && progress.status !== null;
  const percent = useLive
    ? Math.max(progress.percent, scan.progress)
    : scan.progress;
  const stage = (useLive ? progress.stage : null) ?? scan.stage;
  const queued =
    scan.status === "QUEUED" && !(useLive && progress.status === "RUNNING");
  const current = queued ? -1 : stepIndex(stage);
  const elapsed = useElapsed(scan.started_at ?? scan.created_at);

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
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={`${percent}%${stage ? `, ${stage}` : ""}`}
        className="h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        <div
          className="h-full rounded-full bg-sev-low-solid transition-[width] motion-reduce:transition-none"
          style={{ width: `${percent}%` }}
        />
      </div>

      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <Stat label="Progress" value={`${percent}%`} />
        <Stat label="Elapsed" value={elapsed} testId="elapsed" />
        <Stat
          label="Endpoints checked"
          value={
            useLive && progress.endpointsChecked > 0
              ? `${progress.endpointsChecked}${progress.joinedLate ? "+" : ""}`
              : "—"
          }
          testId="endpoints-checked"
        />
        <Stat label="Findings" value="when done" />
      </dl>

      <p className="text-sm text-muted-foreground" aria-live="polite">
        {queued
          ? "Queued, waiting to start…"
          : (useLive && progress.activity) ||
            `${percent}% done${stage ? ` (${stage})` : ""}.`}
      </p>
    </section>
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
          : "Live updates unavailable: checking every 2 s"}
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
