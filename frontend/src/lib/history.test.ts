import { describe, expect, it } from "vitest";

import { scanList } from "@/mocks/fixtures";

import type { ScanStatus } from "./api-types";
import {
  isRescan,
  paginate,
  parseHistoryView,
  prefillFromParams,
  rescanHref,
  scanDuration,
  searchScans,
  serializeHistoryView,
} from "./history";

const scans = scanList.items;
const fake = (i: number): ScanStatus => ({
  ...scans[0],
  scan_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
  created_at: new Date(Date.UTC(2026, 9, 1) + i * 60_000).toISOString(),
});

describe("history view in the URL", () => {
  it("round-trips search and page, omitting defaults", () => {
    expect(serializeHistoryView({ query: " shop ", page: 3 })).toBe(
      "?q=shop&page=3",
    );
    expect(serializeHistoryView({ query: "", page: 1 })).toBe("");
    expect(parseHistoryView(new URLSearchParams("q=shop&page=3"))).toEqual({
      query: "shop",
      page: 3,
    });
  });

  it("ignores a bad page number", () => {
    expect(parseHistoryView(new URLSearchParams("page=-2")).page).toBe(1);
    expect(parseHistoryView(new URLSearchParams("page=abc")).page).toBe(1);
  });
});

describe("searchScans", () => {
  it("keeps newest first", () => {
    const shuffled = [scans[3], scans[0], scans[2], scans[1]];
    expect(searchScans(shuffled, "").map((s) => s.created_at)).toEqual(
      scans.map((s) => s.created_at),
    );
  });

  it("matches the target case-insensitively", () => {
    expect(searchScans(scans, "  SHOP.example ").map((s) => s.url)).toEqual([
      "https://shop.example.com",
      "https://shop.example.com",
    ]);
    expect(searchScans(scans, "nothing-like-this")).toEqual([]);
  });
});

describe("paginate", () => {
  const many = Array.from({ length: 45 }, (_, i) => fake(i));

  it("splits into pages of 20", () => {
    expect(paginate(many, 1)).toMatchObject({
      page: 1,
      pages: 3,
      total: 45,
      from: 1,
      to: 20,
    });
    expect(paginate(many, 3)).toMatchObject({ page: 3, from: 41, to: 45 });
    expect(paginate(many, 3).items).toHaveLength(5);
  });

  it("clamps to the pages that exist", () => {
    expect(paginate(many, 99).page).toBe(3);
    expect(paginate([], 1)).toMatchObject({
      page: 1,
      pages: 1,
      total: 0,
      from: 0,
      to: 0,
    });
  });
});

describe("scanDuration", () => {
  it("measures start to finish, or null while running", () => {
    const done = scans.find((s) => s.status === "DONE")!;
    expect(scanDuration(done)).toBe(72);
    expect(scanDuration(scans.find((s) => s.status === "RUNNING")!)).toBeNull();
  });
});

describe("re-scan link", () => {
  it("carries the target and options, never the authorisation", () => {
    const failed = scans.find((s) => s.status === "FAILED")!;
    const href = rescanHref(failed);
    expect(href).toBe(
      "/?url=https%3A%2F%2Flegacy.example.net&crawl_depth=2&use_wordlist=1&passive_only=1",
    );
    const params = new URLSearchParams(href.slice(2));
    expect(isRescan(params)).toBe(true);
    expect(prefillFromParams(params)).toEqual({
      url: "https://legacy.example.net",
      authorisation_confirmed: false,
      crawl_depth: 2,
      use_wordlist: true,
      passive_only: true,
    });
  });

  it("falls back to defaults for missing or invalid options", () => {
    expect(
      prefillFromParams(
        new URLSearchParams(
          "url=https://a.example&crawl_depth=7&use_wordlist=maybe",
        ),
      ),
    ).toEqual({
      url: "https://a.example",
      authorisation_confirmed: false,
      crawl_depth: 2,
      use_wordlist: true,
      passive_only: false,
    });
    expect(isRescan(new URLSearchParams(""))).toBe(false);
  });
});
