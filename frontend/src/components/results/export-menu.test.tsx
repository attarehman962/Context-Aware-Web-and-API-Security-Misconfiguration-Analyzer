import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
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

import { exportFileName } from "@/lib/export";
import { resultsDone, resultsRunning } from "@/mocks/fixtures";
import { createMockServer } from "@/mocks/node";

import { ExportMenu } from "./export-menu";

const server = createMockServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Files the page hands to the browser: [name, blob type]. */
let saved: [string, string][] = [];
beforeEach(() => {
  saved = [];
  let last: Blob | undefined;
  vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
    last = blob as Blob;
    return "blob:test";
  });
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    saved.push([this.download, last?.type ?? ""]);
  });
});
afterEach(() => vi.restoreAllMocks());

async function choose(label: RegExp) {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /Export/ }));
  await user.click(await screen.findByRole("menuitem", { name: label }));
  return user;
}

describe("exportFileName", () => {
  it("names the file after the target host and the scan date", () => {
    expect(exportFileName(resultsDone.scan, "pdf")).toBe(
      "cawasma-shop.example.com-2026-10-20.pdf",
    );
    expect(
      exportFileName(
        {
          url: "https://Demo-Target:8443/app?x=1",
          completed_at: null,
          created_at: "2026-11-04T09:00:00Z",
        },
        "csv",
      ),
    ).toBe("cawasma-demo-target-8443-2026-11-04.csv");
  });
});

describe("ExportMenu", () => {
  it("is disabled until the scan is done", () => {
    render(<ExportMenu scan={resultsRunning.scan} />);
    expect(screen.getByRole("button", { name: /Export/ })).toBeDisabled();
    expect(
      screen.getByText("Export is available when the scan is done."),
    ).toBeInTheDocument();
  });

  it("offers PDF, HTML, JSON and CSV and works from the keyboard", async () => {
    const user = userEvent.setup();
    render(<ExportMenu scan={resultsDone.scan} />);
    screen.getByRole("button", { name: /Export/ }).focus();
    await user.keyboard("{Enter}");
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual([
      "PDF reportPrintable report",
      "HTML reportSame report, in a browser",
      "JSONFull results, for tools",
      "CSVOne row per finding",
    ]);
    await user.keyboard("{ArrowDown}{ArrowDown}{Enter}");
    await waitFor(() =>
      expect(saved).toEqual([
        ["cawasma-shop.example.com-2026-10-20.json", "application/json"],
      ]),
    );
  });

  it("shows progress while the PDF is generated, then saves it", async () => {
    server.use(
      http.get("*/api/results/:id/export", async () => {
        await delay(300);
        return new HttpResponse("%PDF-1.4", {
          headers: { "Content-Type": "application/pdf" },
        });
      }),
    );
    render(<ExportMenu scan={resultsDone.scan} />);
    await choose(/PDF report/);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Generating the PDF report",
    );
    expect(screen.getByRole("button", { name: /Export/ })).toBeDisabled();
    expect(
      await screen.findByText("Saved cawasma-shop.example.com-2026-10-20.pdf"),
    ).toBeInTheDocument();
    expect(saved).toEqual([
      ["cawasma-shop.example.com-2026-10-20.pdf", "application/pdf"],
    ]);
  });

  it("explains a failed export and retries", async () => {
    server.use(
      http.get("*/api/results/:id/export", () =>
        HttpResponse.json(
          {
            success: false,
            error: {
              code: "FORMAT_UNAVAILABLE",
              message: "PDF export is not available on this server.",
            },
          },
          { status: 501 },
        ),
      ),
    );
    render(<ExportMenu scan={resultsDone.scan} />);
    const user = await choose(/PDF report/);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "PDF report export failed: PDF export is not available on this server.",
    );
    expect(saved).toEqual([]);

    server.resetHandlers();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("can cancel a slow export", async () => {
    server.use(
      http.get("*/api/results/:id/export", async () => {
        await delay("infinite");
        return new HttpResponse("never");
      }),
    );
    render(<ExportMenu scan={resultsDone.scan} />);
    const user = await choose(/PDF report/);
    await screen.findByText(/Generating the PDF report/);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText(/Generating/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Export/ })).toBeEnabled();
    expect(saved).toEqual([]);
  });
});
