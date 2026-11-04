import { describe, expect, it } from "vitest";

import {
  INITIAL_PROGRESS,
  applyLiveMessage,
  liveStatusUrl,
  parseLiveMessage,
  stepIndex,
  type LiveMessage,
} from "./live-status";

describe("liveStatusUrl", () => {
  it("uses ws:// for an http API and wss:// for https", () => {
    expect(liveStatusUrl("http://localhost:8000", "abc")).toBe(
      "ws://localhost:8000/ws/scans/abc",
    );
    expect(liveStatusUrl("https://cawasma.example", "abc")).toBe(
      "wss://cawasma.example/ws/scans/abc",
    );
  });
});

describe("parseLiveMessage", () => {
  it("reads a snapshot and maps COMPLETED to DONE", () => {
    expect(
      parseLiveMessage(
        '{"type":"snapshot","scan_id":"x","status":"COMPLETED","percent":100,"stage":"completed","terminal":true}',
      ),
    ).toEqual({
      kind: "snapshot",
      status: "DONE",
      percent: 100,
      stage: "completed",
      terminal: true,
    });
  });

  it("reads a progress event", () => {
    expect(
      parseLiveMessage(
        '{"scan_id":"x","stage":"analyzing","percent":40,"message":"Analyzing /login"}',
      ),
    ).toEqual({
      kind: "progress",
      stage: "analyzing",
      percent: 40,
      message: "Analyzing /login",
    });
  });

  it("reads an error", () => {
    expect(
      parseLiveMessage('{"type":"error","message":"scan not found"}'),
    ).toEqual({
      kind: "error",
      message: "scan not found",
    });
  });

  it.each([
    "not json",
    "42",
    "null",
    '{"type":"snapshot","status":"WEIRD"}',
    "{}",
  ])("ignores %j", (text) => {
    expect(parseLiveMessage(text)).toBeNull();
  });
});

describe("stepIndex", () => {
  it("groups pipeline stages into crawling, checking and scoring", () => {
    expect(
      ["initializing", "crawling", "tls", "analyzing", "correlating"].map(
        stepIndex,
      ),
    ).toEqual([0, 0, 1, 1, 2]);
    expect(stepIndex("completed")).toBe(3);
    expect(stepIndex(null)).toBe(-1);
  });
});

describe("applyLiveMessage", () => {
  const progress = (
    stage: string,
    percent: number,
    message = "",
  ): LiveMessage => ({
    kind: "progress",
    stage,
    percent,
    message,
  });

  it("follows a scan to the end and counts endpoints checked", () => {
    const events: LiveMessage[] = [
      {
        kind: "snapshot",
        status: "RUNNING",
        percent: 2,
        stage: "initializing",
        terminal: false,
      },
      progress("crawling", 8, "Discovering endpoints"),
      progress("analyzing", 15, "Analyzing /"),
      progress("analyzing", 30, "Analyzing /login"),
      progress("analyzing", 30, "Analyzing /login"),
      progress("analyzing", 45, "Analyzing /api/users"),
      progress("correlating", 92, "Correlating attack chains"),
    ];
    const state = events.reduce(applyLiveMessage, INITIAL_PROGRESS);
    expect(state).toMatchObject({
      status: "RUNNING",
      stage: "correlating",
      percent: 92,
      activity: "Correlating attack chains",
      endpointsChecked: 3,
      joinedLate: false,
      terminal: false,
    });

    const done = applyLiveMessage(
      state,
      progress("completed", 100, "Scan complete"),
    );
    expect(done).toMatchObject({
      status: "DONE",
      terminal: true,
      percent: 100,
    });
  });

  it("marks the count partial when it joins mid-scan", () => {
    const state = applyLiveMessage(INITIAL_PROGRESS, {
      kind: "snapshot",
      status: "RUNNING",
      percent: 45,
      stage: "analyzing",
      terminal: false,
    });
    expect(state.joinedLate).toBe(true);
  });

  it("never moves progress backwards", () => {
    const state = [progress("analyzing", 50), progress("analyzing", 40)].reduce(
      applyLiveMessage,
      INITIAL_PROGRESS,
    );
    expect(state.percent).toBe(50);
  });

  it("treats a failed stage as terminal", () => {
    expect(
      applyLiveMessage(INITIAL_PROGRESS, progress("failed", 30)),
    ).toMatchObject({
      status: "FAILED",
      terminal: true,
    });
  });
});
