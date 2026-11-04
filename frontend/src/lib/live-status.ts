/**
 * Live scan status (contract 1.3): the Server-Sent Events stream
 * `GET /api/scan/{scan_id}/events`. Every `status` event's data is the
 * scan's `ScanStatus`; the stream ends after DONE or FAILED. Pure parts
 * live here; the hook that owns the EventSource is in use-live-scan.ts.
 */

import type { ScanStatus } from "./api-types";

export function liveStatusUrl(apiBaseUrl: string, scanId: string): string {
  return `${apiBaseUrl}/api/scan/${encodeURIComponent(scanId)}/events`;
}

const STATES = new Set(["QUEUED", "RUNNING", "DONE", "FAILED"]);

/** A `status` event's data, or null when it is not a ScanStatus. */
export function parseStatusEvent(data: string): ScanStatus | null {
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const scan = value as Partial<ScanStatus>;
  if (typeof scan.scan_id !== "string" || !STATES.has(String(scan.status))) {
    return null;
  }
  return {
    ...(scan as ScanStatus),
    progress_detail: scan.progress_detail ?? null,
  };
}

export function isTerminal(scan: Pick<ScanStatus, "status">): boolean {
  return scan.status === "DONE" || scan.status === "FAILED";
}

/** The three steps shown to users and the pipeline stages in each. */
export const STEPS = [
  { id: "crawling", label: "Crawling", stages: ["initializing", "crawling"] },
  { id: "checking", label: "Checking", stages: ["checking"] },
  { id: "scoring", label: "Scoring", stages: ["scoring"] },
] as const;

/** Index into STEPS for a stage; STEPS.length once completed; -1 if unknown. */
export function stepIndex(stage: string | null | undefined): number {
  if (stage === "completed") return STEPS.length;
  return STEPS.findIndex((step) =>
    (step.stages as readonly string[]).includes(stage ?? ""),
  );
}

/** The cancel route ends a scan FAILED with this exact error. */
export const CANCELLED_ERROR = "Cancelled by the user.";

export function wasCancelled(scan: Pick<ScanStatus, "status" | "error">) {
  return scan.status === "FAILED" && scan.error === CANCELLED_ERROR;
}
