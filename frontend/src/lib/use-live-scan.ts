"use client";

import { useEffect, useReducer, useRef, useState } from "react";

import { apiBaseUrl } from "./api";
import {
  INITIAL_PROGRESS,
  applyLiveMessage,
  liveStatusUrl,
  parseLiveMessage,
  type LiveMessage,
  type LiveProgress,
} from "./live-status";

/**
 * - `connecting`: socket opening (results still come from polling)
 * - `live`: events arrive as the scanner works
 * - `polling`: the socket failed or dropped before the scan finished; the
 *   results query polls instead
 * - `off`: not connected (scan finished, or WebSockets unavailable)
 */
export type LiveMode = "connecting" | "live" | "polling" | "off";

export interface UseLiveScanOptions {
  /** Connect only while the scan is queued or running. */
  enabled: boolean;
  /** Called once when the socket reports DONE or FAILED. */
  onTerminal?: () => void;
  /** Tests may pass their own socket factory. */
  createSocket?: (url: string) => WebSocket;
}

function reducer(state: LiveProgress, message: LiveMessage | "reset") {
  return message === "reset"
    ? INITIAL_PROGRESS
    : applyLiveMessage(state, message);
}

export function useLiveScan(
  scanId: string,
  { enabled, onTerminal, createSocket }: UseLiveScanOptions,
): { mode: LiveMode; progress: LiveProgress } {
  const supported = typeof window !== "undefined" && "WebSocket" in window;
  const [progress, dispatch] = useReducer(reducer, INITIAL_PROGRESS);
  const [socketMode, setSocketMode] = useState<
    "connecting" | "live" | "polling"
  >("connecting");
  const terminalCallback = useRef(onTerminal);
  useEffect(() => {
    terminalCallback.current = onTerminal;
  });

  useEffect(() => {
    if (!enabled || !supported) return;
    let finished = false;
    let fellBack = false;
    const fallBack = () => {
      if (finished || fellBack) return;
      fellBack = true;
      setSocketMode("polling");
    };

    let socket: WebSocket;
    try {
      const url = liveStatusUrl(apiBaseUrl(), scanId);
      socket = createSocket ? createSocket(url) : new WebSocket(url);
    } catch {
      queueMicrotask(fallBack);
      return;
    }

    socket.addEventListener("open", () => {
      if (!fellBack) setSocketMode("live");
    });
    socket.addEventListener("message", (event) => {
      const message = parseLiveMessage(String(event.data));
      if (!message) return;
      if (message.kind === "error") {
        fallBack();
        socket.close();
        return;
      }
      dispatch(message);
      const terminal =
        message.kind === "snapshot"
          ? message.terminal
          : message.percent >= 100 ||
            message.stage === "completed" ||
            message.stage === "failed";
      if (terminal && !finished) {
        finished = true;
        terminalCallback.current?.();
      }
    });
    socket.addEventListener("close", fallBack);
    socket.addEventListener("error", fallBack);

    return () => {
      finished = true;
      socket.close();
      dispatch("reset");
      setSocketMode("connecting");
    };
  }, [enabled, supported, scanId, createSocket]);

  const mode: LiveMode = !enabled || !supported ? "off" : socketMode;
  return { mode, progress };
}
