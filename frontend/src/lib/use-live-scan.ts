"use client";

import { useEffect, useRef, useState } from "react";

import { apiBaseUrl } from "./api";
import type { ScanStatus } from "./api-types";
import { isTerminal, liveStatusUrl, parseStatusEvent } from "./live-status";

/**
 * - `connecting`: stream opening
 * - `live`: status events arrive as the scan changes
 * - `polling`: the stream is down (reconnecting, or gave up); results poll
 *   every 2 s until it is back
 * - `off`: not connected (scan finished, or EventSource unavailable)
 */
export type LiveMode = "connecting" | "live" | "polling" | "off";

export interface UseLiveScanOptions {
  /** Connect only while the scan is queued or running. */
  enabled: boolean;
  /** Called once when an event reports DONE or FAILED. */
  onTerminal?: () => void;
  /** Tests may pass their own EventSource factory. */
  createSource?: (url: string) => EventSource;
}

/**
 * Follows a scan over `GET /api/scan/{id}/events` (contract 1.3). The
 * browser's EventSource reconnects by itself after a drop (the stream sends
 * `retry: 3000`); while it is down the page polls instead, and switches back
 * to live as soon as an event arrives again.
 */
export function useLiveScan(
  scanId: string,
  { enabled, onTerminal, createSource }: UseLiveScanOptions,
): { mode: LiveMode; latest: ScanStatus | null } {
  const supported = typeof window !== "undefined" && "EventSource" in window;
  const [latest, setLatest] = useState<ScanStatus | null>(null);
  const [streamMode, setStreamMode] = useState<
    "connecting" | "live" | "polling"
  >("connecting");
  const terminalCallback = useRef(onTerminal);
  useEffect(() => {
    terminalCallback.current = onTerminal;
  });

  useEffect(() => {
    if (!enabled || !supported) return;
    let finished = false;
    let source: EventSource;
    try {
      const url = liveStatusUrl(apiBaseUrl(), scanId);
      source = createSource ? createSource(url) : new EventSource(url);
    } catch {
      queueMicrotask(() => setStreamMode("polling"));
      return;
    }

    source.addEventListener("status", (event) => {
      const scan = parseStatusEvent(String((event as MessageEvent).data));
      if (!scan || finished) return;
      setLatest(scan);
      setStreamMode("live");
      if (isTerminal(scan)) {
        finished = true;
        // The server ends the stream; close so EventSource does not reconnect.
        source.close();
        terminalCallback.current?.();
      }
    });
    // Covers both a drop (EventSource will retry: CONNECTING) and a refusal
    // such as a 404 (CLOSED). Either way, poll until events flow again.
    source.addEventListener("error", () => {
      if (!finished) setStreamMode("polling");
    });

    return () => {
      finished = true;
      source.close();
      setLatest(null);
      setStreamMode("connecting");
    };
  }, [enabled, supported, scanId, createSource]);

  const mode: LiveMode = !enabled || !supported ? "off" : streamMode;
  return { mode, latest };
}
