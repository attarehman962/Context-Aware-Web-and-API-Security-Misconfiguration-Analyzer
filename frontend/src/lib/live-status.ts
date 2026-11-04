/**
 * Live scan progress over the API's WebSocket `/ws/scans/{scan_id}`
 * (backend app/api/routes/ws.py). Pure parts: the URL, the message format
 * and how events fold into what the page shows. The hook that owns the
 * socket is in use-live-scan.ts.
 *
 * The socket is a pre-contract route (marked deprecated in openapi.json; it
 * is not in docs/api-contract.md). Keep every detail of it in this file so a
 * contract live-status mechanism can replace it in one place.
 *
 * Messages, as the backend sends them:
 *   {"type":"snapshot","scan_id","status","percent","stage","terminal"}
 *   {"scan_id","stage","percent","message"}         (progress, from Redis)
 *   {"type":"error","message"}
 * The snapshot's status uses the old public name COMPLETED for DONE.
 */

import type { ScanState } from "./api-types";

export function liveStatusUrl(apiBaseUrl: string, scanId: string): string {
  const url = new URL(`/ws/scans/${encodeURIComponent(scanId)}`, apiBaseUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export type LiveMessage =
  | {
      kind: "snapshot";
      status: ScanState;
      percent: number;
      stage: string | null;
      terminal: boolean;
    }
  | { kind: "progress"; stage: string; percent: number; message: string }
  | { kind: "error"; message: string };

const STATES: Record<string, ScanState> = {
  QUEUED: "QUEUED",
  RUNNING: "RUNNING",
  DONE: "DONE",
  COMPLETED: "DONE",
  FAILED: "FAILED",
};

/** One socket message, or null when it is not a message we understand. */
export function parseLiveMessage(text: string): LiveMessage | null {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null) return null;
  const m = data as Record<string, unknown>;
  const percent = typeof m.percent === "number" ? m.percent : 0;

  if (m.type === "error") {
    return {
      kind: "error",
      message: String(m.message ?? "Live updates failed."),
    };
  }
  if (m.type === "snapshot") {
    const status = STATES[String(m.status)];
    if (!status) return null;
    return {
      kind: "snapshot",
      status,
      percent,
      stage: typeof m.stage === "string" ? m.stage : null,
      terminal: Boolean(m.terminal),
    };
  }
  if (typeof m.stage === "string") {
    return {
      kind: "progress",
      stage: m.stage,
      percent,
      message: typeof m.message === "string" ? m.message : "",
    };
  }
  return null;
}

/** The three steps shown to users, and the pipeline stages in each. */
export const STEPS = [
  { id: "crawling", label: "Crawling", stages: ["initializing", "crawling"] },
  { id: "checking", label: "Checking", stages: ["tls", "analyzing"] },
  { id: "scoring", label: "Scoring", stages: ["correlating"] },
] as const;

export type StepId = (typeof STEPS)[number]["id"];

/** Index into STEPS for a pipeline stage; 3 once completed; -1 if unknown. */
export function stepIndex(stage: string | null): number {
  if (stage === "completed") return STEPS.length;
  return STEPS.findIndex((step) =>
    (step.stages as readonly string[]).includes(stage ?? ""),
  );
}

export interface LiveProgress {
  status: ScanState | null;
  stage: string | null;
  percent: number;
  /** Latest human-readable activity, e.g. "Analyzing /api/users". */
  activity: string | null;
  /** Endpoints the scanner has started checking (from "Analyzing" events). */
  endpointsChecked: number;
  /** True when we joined mid-scan, so earlier endpoints were not counted. */
  joinedLate: boolean;
  /** The scan reached DONE or FAILED. */
  terminal: boolean;
  checkedPaths: string[];
}

export const INITIAL_PROGRESS: LiveProgress = {
  status: null,
  stage: null,
  percent: 0,
  activity: null,
  endpointsChecked: 0,
  joinedLate: false,
  terminal: false,
  checkedPaths: [],
};

const ANALYZING = /^Analyzing (.+)$/;

export function applyLiveMessage(
  state: LiveProgress,
  message: LiveMessage,
): LiveProgress {
  switch (message.kind) {
    case "snapshot":
      return {
        ...state,
        status: message.status,
        stage: message.stage,
        percent: Math.max(state.percent, message.percent),
        terminal: message.terminal,
        joinedLate:
          message.stage === "analyzing" || stepIndex(message.stage) > 1,
      };
    case "progress": {
      const path = ANALYZING.exec(message.message)?.[1];
      const checkedPaths =
        path && !state.checkedPaths.includes(path)
          ? [...state.checkedPaths, path]
          : state.checkedPaths;
      const terminal =
        message.percent >= 100 ||
        message.stage === "completed" ||
        message.stage === "failed";
      return {
        ...state,
        status: terminal
          ? message.stage === "failed"
            ? "FAILED"
            : "DONE"
          : "RUNNING",
        stage: message.stage,
        percent: Math.max(state.percent, message.percent),
        activity: message.message || state.activity,
        checkedPaths,
        endpointsChecked: checkedPaths.length,
        terminal,
      };
    }
    case "error":
      return state;
  }
}
