import { describe, expect, it } from "vitest";

import { resultsDone, resultsRunning } from "@/mocks/fixtures";

import {
  isTerminal,
  liveStatusUrl,
  parseStatusEvent,
  stepIndex,
  wasCancelled,
} from "./live-status";

describe("liveStatusUrl", () => {
  it("is the contract's SSE route", () => {
    expect(liveStatusUrl("http://localhost:8000", "abc")).toBe(
      "http://localhost:8000/api/scan/abc/events",
    );
  });
});

describe("parseStatusEvent", () => {
  it("reads a ScanStatus with its progress counts", () => {
    const scan = parseStatusEvent(JSON.stringify(resultsRunning.scan));
    expect(scan).toMatchObject({
      status: "RUNNING",
      stage: "checking",
      progress_detail: {
        endpoints_found: 38,
        endpoints_checked: 17,
        findings: 29,
      },
    });
  });

  it("fills a missing progress_detail with null", () => {
    // JSON.stringify drops the undefined key, as an older API would omit it.
    const withoutDetail = { ...resultsDone.scan, progress_detail: undefined };
    expect(
      parseStatusEvent(JSON.stringify(withoutDetail))?.progress_detail,
    ).toBeNull();
  });

  it.each([
    "not json",
    "null",
    "42",
    '{"status":"RUNNING"}',
    '{"scan_id":"x","status":"COMPLETED"}',
  ])("ignores %j", (text) => {
    expect(parseStatusEvent(text)).toBeNull();
  });
});

describe("stages", () => {
  it("groups the pipeline stages into crawling, checking and scoring", () => {
    expect(
      ["initializing", "crawling", "checking", "scoring"].map(stepIndex),
    ).toEqual([0, 0, 1, 2]);
    expect(stepIndex("completed")).toBe(3);
    expect(stepIndex(null)).toBe(-1);
  });

  it("knows the final states and a cancelled scan", () => {
    expect(isTerminal({ status: "DONE" })).toBe(true);
    expect(isTerminal({ status: "RUNNING" })).toBe(false);
    expect(
      wasCancelled({ status: "FAILED", error: "Cancelled by the user." }),
    ).toBe(true);
    expect(wasCancelled({ status: "FAILED", error: "Timed out." })).toBe(false);
  });
});
