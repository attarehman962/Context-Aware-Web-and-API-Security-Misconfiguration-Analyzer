/**
 * The scan page's live updates against the MSW mock: the WebSocket replaces
 * 2 s polling while it works, and polling takes over when it drops. The mock
 * clock runs fast (20x: a simulated 10 s scan takes half a second; the live
 * test uses 4x so its progress stays on screen long enough to read).
 */

import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import { http, ws } from "msw";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { createScan } from "@/lib/api";
import { makeQueryClient } from "@/lib/query-client";
import type { LiveSocketBehaviour } from "@/mocks/handlers";
import { createMockServer } from "@/mocks/node";

import { ScanResultsView } from "./scan-results-view";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(window.location.search),
}));

let speed = 20;
let started = Date.now();
const clock = () => started + (Date.now() - started) * speed;
let behaviour: LiveSocketBehaviour = "normal";
const server = createMockServer({ now: clock, liveSocket: () => behaviour });
const socket = ws.link(/\/ws\/scans\/[^/?#]+$/);

/** GET /api/results/{id} calls, to tell polling from live updates. */
let resultsCalls = 0;

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  server.events.on("request:start", ({ request }) => {
    if (/\/api\/results\/[^/]+$/.test(new URL(request.url).pathname)) {
      resultsCalls += 1;
    }
  });
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

describe("scan page: live updates", () => {
  it("shows steps, progress and endpoints as events arrive, then the results", async () => {
    speed = 4;
    const scanId = await startScan();
    renderScan(scanId);

    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "live"),
    );
    await waitFor(() =>
      expect(
        Number(screen.getByTestId("endpoints-checked").textContent),
      ).toBeGreaterThan(0),
    );
    // The summary follows the socket, not the (less frequent) poll.
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

    // The final event makes the page load the results.
    expect(
      await screen.findByRole(
        "heading",
        { name: "Findings" },
        { timeout: 5000 },
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    // Initial load + the refetch on the final event; no 2 s polling.
    expect(resultsCalls).toBeLessThanOrEqual(3);
  });

  it("does not open a socket for a finished scan", async () => {
    const connections = vi.fn();
    server.use(socket.addEventListener("connection", connections));
    renderScan("11111111-1111-4111-8111-111111111111");
    expect(
      await screen.findByRole("heading", { name: "Findings" }),
    ).toBeInTheDocument();
    expect(connections).not.toHaveBeenCalled();
  });
});

describe("scan page: fallback to polling", () => {
  it("polls when the live connection drops", async () => {
    behaviour = "drop";
    const scanId = await startScan();
    renderScan(scanId);

    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "polling"),
    );
    expect(badge()).toHaveTextContent("checking every 2 s");
    expect(
      await screen.findByRole(
        "heading",
        { name: "Findings" },
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
    expect(resultsCalls).toBeGreaterThanOrEqual(2);
  }, 12_000);

  it("polls when the socket reports an error", async () => {
    behaviour = "error";
    const scanId = await startScan();
    renderScan(scanId);
    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "polling"),
    );
    expect(
      await screen.findByRole(
        "heading",
        { name: "Findings" },
        { timeout: 8000 },
      ),
    ).toBeInTheDocument();
  }, 12_000);

  it("keeps the last results when the API also fails", async () => {
    behaviour = "drop";
    const scanId = await startScan();
    renderScan(scanId);
    await waitFor(() =>
      expect(badge()).toHaveAttribute("data-live-mode", "polling"),
    );
    server.use(http.get("*/api/results/:scanId", () => Response.error()));
    // Progress stays on screen while retries run.
    expect(screen.getByRole("progressbar")).toBeInTheDocument();
  });
});
