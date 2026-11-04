/**
 * The scan page's live status against the MSW mock: the SSE stream
 * (GET /api/scan/{id}/events, contract 1.3) replaces 2 s polling while it
 * works, polling takes over when it drops, and a scan can be cancelled.
 * The mock clock runs fast (20x: a 10 s scan takes half a second; the live
 * test uses 2x so its progress stays on screen long enough to read).
 */

import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { createScan } from "@/lib/api";
import { makeQueryClient } from "@/lib/query-client";
import type { LiveStreamBehaviour } from "@/mocks/handlers";
import { createMockServer } from "@/mocks/node";

import { ScanResultsView } from "./scan-results-view";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(window.location.search),
}));

let speed = 20;
let started = Date.now();
const clock = () => started + (Date.now() - started) * speed;
let behaviour: LiveStreamBehaviour = "normal";
const server = createMockServer({ now: clock, liveStream: () => behaviour });

/** GET /api/results/{id} calls, to tell polling from live updates. */
let resultsCalls = 0;
let streamCalls = 0;

beforeAll(async () => {
  // The page lazy-loads its progress panel; load it once up front so the
  // first test is not racing Vitest's on-demand transform of that module.
  await import("./results/live-progress");
  server.listen({ onUnhandledRequest: "error" });
  server.events.on("request:start", ({ request }) => {
    const path = new URL(request.url).pathname;
    if (/\/api\/results\/[^/]+$/.test(path)) resultsCalls += 1;
    if (/\/api\/scan\/[^/]+\/events$/.test(path)) streamCalls += 1;
  });
});
beforeEach(() => {
  resultsCalls = 0;
  streamCalls = 0;
});
afterEach(() => {
  server.resetHandlers();
  behaviour = "normal";
  speed = 20;
});
afterAll(() => server.close());

async function startScan(): Promise<string> {
  started = Date.now();
  resultsCalls = 0;
  streamCalls = 0;
  const result = await createScan({
    url: "https://shop.example.com",
    authorisation_confirmed: true,
  });
  if (!result.ok) throw new Error(result.error.message);
  return result.data.scan_id;
}

function renderScan(scanId: string) {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <ScanResultsView scanId={scanId} />
    </QueryClientProvider>,
  );
}

const badge = () => document.querySelector("[data-live-mode]");
const findingsHeading = (timeout = 5000) =>
  screen.findByRole("heading", { name: "Findings" }, { timeout });

describe("scan page: live status over SSE", () => {
  it("shows steps and counts as events arrive, then the results", async () => {
    // 2x: the 10 s simulated scan runs 5 s, long enough to read its progress
    // after the lazy-loaded panel appears.
    speed = 2;
    const scanId = await startScan();
    renderScan(scanId);

    await waitFor(
      () => expect(badge()).toHaveAttribute("data-live-mode", "live"),
      { timeout: 5000 },
    );
    // The progress panel is lazy-loaded; give it and the first counts time.
    await waitFor(
      () =>
        expect(
          Number(screen.getByTestId("endpoints-checked").textContent),
        ).toBeGreaterThan(0),
      { timeout: 5000 },
    );
    expect(
      Number(screen.getByTestId("endpoints-found").textContent),
    ).toBeGreaterThan(0);
    expect(screen.getByTestId("findings-so-far").textContent).toMatch(/^\d+$/);
    // The summary follows the stream, not the (less frequent) poll.
    expect(
      screen
        .getByRole("region", { name: "Scan summary" })
        .querySelector("[data-status]"),
    ).toHaveAttribute("data-status", "RUNNING");
    const steps = screen.getByRole("list", { name: "Steps" });
    expect(within(steps).getAllByRole("listitem")).toHaveLength(3);
    expect(steps.querySelector('[data-step="crawling"]')).toHaveAttribute(
      "data-state",
      "done",
    );
    expect(screen.getByTestId("elapsed")).toHaveTextContent(/s$/);

    expect(await findingsHeading()).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    // Initial load + the fetch after the final event; no 2 s polling.
    expect(resultsCalls).toBeLessThanOrEqual(3);
    expect(streamCalls).toBe(1);
  }, 15_000);

  it("does not open a stream for a finished scan", async () => {
    renderScan("11111111-1111-4111-8111-111111111111");
    expect(await findingsHeading()).toBeInTheDocument();
    expect(streamCalls).toBe(0);
  });
});

describe("scan page: fallback to polling", () => {
  it("polls while the stream is down", async () => {
    behaviour = "drop";
    const scanId = await startScan();
    renderScan(scanId);

    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "polling"),
    );
    expect(badge()).toHaveTextContent("checking every 2 s");
    expect(await findingsHeading(8000)).toBeInTheDocument();
    expect(resultsCalls).toBeGreaterThanOrEqual(2);
  }, 12_000);

  it("polls when the stream is refused", async () => {
    behaviour = "refuse";
    const scanId = await startScan();
    renderScan(scanId);
    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "polling"),
    );
    expect(await findingsHeading(8000)).toBeInTheDocument();
  }, 12_000);
});

describe("scan page: cancel", () => {
  it("asks for confirmation, then shows the scan as cancelled", async () => {
    speed = 1;
    const user = userEvent.setup();
    const scanId = await startScan();
    renderScan(scanId);

    await user.click(
      await screen.findByRole("button", { name: /Cancel scan/ }),
    );
    expect(
      screen.getByText(/Partial results are not kept/),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Keep scanning" }));
    await user.click(screen.getByRole("button", { name: /Cancel scan/ }));
    await user.click(screen.getByRole("button", { name: "Yes, cancel scan" }));

    expect(
      await screen.findByText("Scan cancelled", {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Re-scan this target/ }),
    ).toBeInTheDocument();
  });
});
