import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
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

import type { ScanStatus } from "@/lib/api-types";
import { makeQueryClient } from "@/lib/query-client";
import { scanList } from "@/mocks/fixtures";
import { createMockServer } from "@/mocks/node";

import { ScanHistory } from "./scan-history";

const push = vi.fn();
const replace = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace }),
  useSearchParams: () => new URLSearchParams(window.location.search),
}));

const server = createMockServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  push.mockClear();
  replace.mockClear();
  window.history.replaceState(null, "", "/history");
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderHistory(url = "/history") {
  window.history.replaceState(null, "", url);
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <ScanHistory />
    </QueryClientProvider>,
  );
}

const rows = () => screen.getAllByRole("row").slice(1); // skip the header

/** A history of `count` scans served in API pages of `limit`. */
function serveScans(count: number) {
  const all: ScanStatus[] = Array.from({ length: count }, (_, i) => ({
    ...scanList.items[2], // a DONE scan
    scan_id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    url: `https://site-${i}.example.com`,
    created_at: new Date(
      Date.UTC(2026, 9, 1) + (count - i) * 60_000,
    ).toISOString(),
  }));
  const pagesServed: number[] = [];
  server.use(
    http.get("*/api/scans", ({ request }) => {
      const query = new URL(request.url).searchParams;
      const page = Number(query.get("page"));
      const limit = Number(query.get("limit"));
      pagesServed.push(page);
      return HttpResponse.json({
        items: all.slice((page - 1) * limit, page * limit),
        meta: { page, limit, total: count, pages: Math.ceil(count / limit) },
      });
    }),
  );
  return pagesServed;
}

describe("history table", () => {
  it("lists past scans newest first with status, counts and duration", async () => {
    renderHistory();
    await waitFor(() => expect(rows()).toHaveLength(4));
    expect(rows().map((r) => r.getAttribute("data-scan-id"))).toEqual(
      scanList.items.map((s) => s.scan_id),
    );
    const done = rows().find(
      (r) =>
        r.getAttribute("data-scan-id") ===
        "11111111-1111-4111-8111-111111111111",
    )!;
    expect(within(done).getByText("Done")).toBeInTheDocument();
    expect(
      done.querySelector('[data-severity-count="CRITICAL"]'),
    ).toHaveTextContent("2");
    expect(within(done).getByText("1 min 12 s")).toBeInTheDocument();
    const running = rows().find((r) => within(r).queryByText("Running"))!;
    expect(within(running).getByText("running")).toBeInTheDocument();
  });

  it("loads every API page so search covers the whole history", async () => {
    const pagesServed = serveScans(150);
    renderHistory();
    expect(
      await screen.findByText("Showing 1–20 of 150 scans"),
    ).toBeInTheDocument();
    expect(pagesServed).toEqual([1, 2]);
  });
});

describe("history navigation", () => {
  it("opens the stored results from a row or its link", async () => {
    const user = userEvent.setup();
    renderHistory();
    await waitFor(() => expect(rows()).toHaveLength(4));
    const failed = rows().find((r) => within(r).queryByText("Failed"))!;

    await user.click(within(failed).getByText("Failed"));
    expect(push).toHaveBeenCalledWith(
      "/scans/44444444-4444-4444-8444-444444444444",
    );

    expect(
      within(failed).getByRole("link", { name: "https://legacy.example.net" }),
    ).toHaveAttribute("href", "/scans/44444444-4444-4444-8444-444444444444");
  });

  it("re-scans with the scan's target and options", async () => {
    const user = userEvent.setup();
    renderHistory();
    await waitFor(() => expect(rows()).toHaveLength(4));
    const rescan = screen.getByRole("button", {
      name: "Re-scan https://legacy.example.net",
    });
    expect(rescan).toHaveAttribute(
      "href",
      "/?url=https%3A%2F%2Flegacy.example.net&crawl_depth=2&use_wordlist=1&passive_only=1",
    );
    // The re-scan link does not also open the row.
    await user.click(rescan);
    expect(push).not.toHaveBeenCalled();
  });

  it("searches by target and puts the search in the URL", async () => {
    const user = userEvent.setup();
    renderHistory();
    await waitFor(() => expect(rows()).toHaveLength(4));
    await user.type(screen.getByLabelText("Search by target"), "legacy");
    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith("/history?q=legacy", {
        scroll: false,
      }),
    );
  });

  it("shows the search and page taken from the URL", async () => {
    serveScans(45);
    renderHistory("/history?q=site-&page=3");
    expect(
      await screen.findByText("Showing 41–45 of 45 scans"),
    ).toBeInTheDocument();
    expect(screen.getByText("Page 3 of 3")).toBeInTheDocument();
    expect(screen.getByLabelText("Search by target")).toHaveValue("site-");
    expect(screen.getByRole("button", { name: /Next/ })).toBeDisabled();
  });

  it("pages forward and back through the URL", async () => {
    const user = userEvent.setup();
    serveScans(45);
    renderHistory("/history?page=2");
    expect(
      await screen.findByText("Showing 21–40 of 45 scans"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Next/ }));
    expect(replace).toHaveBeenLastCalledWith("/history?page=3", {
      scroll: false,
    });
    await user.click(screen.getByRole("button", { name: /Previous/ }));
    expect(replace).toHaveBeenLastCalledWith("/history", { scroll: false });
  });

  it("says when nothing matches and clears the search", async () => {
    const user = userEvent.setup();
    renderHistory("/history?q=nowhere");
    expect(
      await screen.findByText("No scans match this search"),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect(replace).toHaveBeenCalledWith("/history", { scroll: false });
  });
});

describe("history states", () => {
  it("shows an empty state without scans", async () => {
    serveScans(0);
    renderHistory();
    expect(await screen.findByText("No scans yet")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Start a new scan" }),
    ).toHaveAttribute("href", "/");
  });

  it("shows an error with retry when the API fails", async () => {
    server.use(
      http.get("*/api/scans", () =>
        HttpResponse.json(
          {
            success: false,
            error: { code: "INTERNAL_ERROR", message: "Boom." },
          },
          { status: 500 },
        ),
      ),
    );
    renderHistory();
    expect(
      await screen.findByRole(
        "button",
        { name: "Try again" },
        { timeout: 15_000 },
      ),
    ).toBeInTheDocument();
  }, 20_000);
});
