import {
  act,
  render,
  renderHook,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NO_FILTERS, rankFindings } from "@/lib/findings";
import { useFindingsView } from "@/lib/use-findings-view";
import { resultsDone, resultsRunning } from "@/mocks/fixtures";

import { ScanSummary, formatDuration } from "./scan-summary";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(window.location.search),
}));

describe("ScanSummary", () => {
  it("shows target, time, counts and the context shift", () => {
    render(
      <ScanSummary
        scan={resultsDone.scan}
        ranked={rankFindings(resultsDone.findings)}
      />,
    );
    expect(
      screen.getByRole("heading", {
        level: 1,
        name: "https://shop.example.com",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/took 1 min 12 s/)).toBeInTheDocument();

    const counts = screen.getByRole("list", { name: "Findings per severity" });
    const critical = within(counts)
      .getAllByRole("listitem")
      .find((li) => li.getAttribute("data-severity-count") === "CRITICAL")!;
    expect(critical).toHaveTextContent("3");

    const shift = screen.getByTestId("context-shift");
    expect(shift).toHaveTextContent("4 findings moved up a severity");
    expect(shift).toHaveTextContent("2 findings moved down");
  });

  it("leaves out counts until the scan is done", () => {
    render(<ScanSummary scan={resultsRunning.scan} />);
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.queryByTestId("context-shift")).not.toBeInTheDocument();
    expect(screen.getByText(/^Started /)).toBeInTheDocument();
  });

  it("formats durations", () => {
    expect(formatDuration(0.4)).toBe("under 1 s");
    expect(formatDuration(42)).toBe("42 s");
    expect(formatDuration(120)).toBe("2 min");
  });
});

describe("useFindingsView", () => {
  afterEach(() => window.history.replaceState(null, "", "/"));

  it("reads the view from the URL", () => {
    window.history.replaceState(
      null,
      "",
      "/scans/x?rank=base&severity=HIGH&chains=1",
    );
    const { result } = renderHook(() => useFindingsView());
    expect(result.current[0]).toEqual({
      rankBy: "base",
      filters: { ...NO_FILTERS, severities: ["HIGH"], chainsOnly: true },
    });
  });

  it("writes changes to the URL and updates at once", () => {
    window.history.replaceState(null, "", "/scans/x?tab=chains");
    const { result } = renderHook(() => useFindingsView());
    act(() =>
      result.current[1]({
        rankBy: "base",
        filters: { ...NO_FILTERS, category: "HEADERS", endpoint: "/admin" },
      }),
    );
    expect(window.location.pathname).toBe("/scans/x");
    expect(window.location.search).toBe(
      "?tab=chains&rank=base&category=HEADERS&endpoint=%2Fadmin",
    );
    expect(result.current[0].rankBy).toBe("base");
    expect(result.current[0].filters.category).toBe("HEADERS");
  });
});
