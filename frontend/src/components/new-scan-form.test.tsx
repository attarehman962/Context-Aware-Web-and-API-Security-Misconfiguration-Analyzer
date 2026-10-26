import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
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

import { makeQueryClient } from "@/lib/query-client";
import { createMockServer } from "@/mocks/node";

import { NewScanForm } from "./new-scan-form";

const push = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
}));

const server = createMockServer();
const requests: unknown[] = [];

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  server.events.on("request:start", async ({ request }) => {
    if (request.method === "POST") requests.push(await request.clone().json());
  });
});
beforeEach(() => {
  push.mockClear();
  requests.length = 0;
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function setup() {
  const user = userEvent.setup();
  render(
    <QueryClientProvider client={makeQueryClient()}>
      <NewScanForm />
    </QueryClientProvider>,
  );
  return {
    user,
    url: screen.getByLabelText("Target URL"),
    authorise: screen.getByRole("checkbox", { name: /I own this target/ }),
    start: screen.getByRole("button", { name: /Start scan/ }),
  };
}

describe("NewScanForm: authorisation", () => {
  it("keeps Start disabled until authorisation is confirmed", async () => {
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://shop.example.com");
    expect(start).toBeDisabled();
    expect(screen.getByText("Confirm authorisation to start.")).toBeVisible();

    await user.click(authorise);
    expect(start).toBeEnabled();

    await user.click(authorise);
    expect(start).toBeDisabled();
  });

  it("uses the exact wording for the checkbox", () => {
    setup();
    expect(
      screen.getByRole("checkbox", {
        name: "I own this target or have written permission to test it.",
      }),
    ).toBeRequired();
  });
});

describe("NewScanForm: URL validation", () => {
  it.each([
    ["", "Enter the URL of the site or API to scan."],
    [
      "shop.example.com",
      "Include the scheme, for example https://shop.example.com",
    ],
    [
      "http://shop.example.com",
      "Only HTTPS targets can be scanned. Try https://shop.example.com",
    ],
    [
      "ftp://files.example.com",
      "Only web addresses (https://...) can be scanned.",
    ],
  ])("shows a clear error for %j and sends nothing", async (input, message) => {
    const { user, url, authorise, start } = setup();
    if (input) await user.type(url, input);
    await user.click(authorise);
    await user.click(start);

    expect(screen.getByText(message)).toBeInTheDocument();
    expect(url).toHaveAttribute("aria-invalid", "true");
    expect(url).toHaveAccessibleDescription(message);
    expect(url).toHaveFocus();
    expect(requests).toEqual([]);
  });

  it("validates when the field loses focus and clears once fixed", async () => {
    const { user, url } = setup();
    await user.type(url, "http://shop.example.com");
    await user.tab();
    expect(screen.getByText(/Only HTTPS targets/)).toBeInTheDocument();

    await user.clear(url);
    await user.type(url, "https://shop.example.com");
    expect(screen.queryByText(/Only HTTPS targets/)).not.toBeInTheDocument();
    expect(url).not.toHaveAttribute("aria-invalid");
  });
});

describe("NewScanForm: advanced options", () => {
  it("is collapsed by default and explains each option", async () => {
    const { user } = setup();
    const summary = screen.getByText("Advanced options");
    const details = summary.closest("details")!;
    expect(details).not.toHaveAttribute("open");

    await user.click(summary);
    expect(details).toHaveAttribute("open");
    expect(screen.getByRole("radio", { name: /^2:/ })).toBeChecked();
    expect(screen.getByRole("switch", { name: /Use wordlist/ })).toBeChecked();
    expect(
      screen.getByRole("switch", { name: /Passive-only mode/ }),
    ).not.toBeChecked();
    expect(screen.getByText(/probe common hidden paths/)).toBeInTheDocument();
    expect(screen.getByText(/No active probes/)).toBeInTheDocument();
  });
});

describe("NewScanForm: submit", () => {
  it("posts the scan, shows it queued and redirects to /scans/[id]", async () => {
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://shop.example.com");
    await user.click(authorise);
    await user.click(screen.getByText("Advanced options"));
    await user.click(screen.getByRole("radio", { name: /^1:/ }));
    await user.click(screen.getByRole("switch", { name: /Passive-only mode/ }));
    await user.click(start);

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Queued");
    expect(status).toHaveTextContent(
      "Scan queued for https://shop.example.com",
    );

    expect(requests).toEqual([
      {
        url: "https://shop.example.com",
        authorisation_confirmed: true,
        crawl_depth: 1,
        use_wordlist: true,
        passive_only: true,
      },
    ]);
    expect(push).toHaveBeenCalledTimes(1);
    expect(push.mock.calls[0][0]).toMatch(/^\/scans\/[0-9a-f-]{36}$/);
  });

  it("shows a target the API rejects on the URL field", async () => {
    server.use(
      http.post("*/api/scan", () =>
        HttpResponse.json(
          {
            success: false,
            error: {
              code: "INVALID_TARGET",
              message: "Target resolves to a private address.",
            },
          },
          { status: 400 },
        ),
      ),
    );
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://intranet.example.com");
    await user.click(authorise);
    await user.click(start);

    expect(
      await screen.findByText("Target resolves to a private address."),
    ).toBeInTheDocument();
    expect(url).toHaveAttribute("aria-invalid", "true");
    expect(push).not.toHaveBeenCalled();
  });

  it("shows an inline error when the API is down", async () => {
    server.use(http.post("*/api/scan", () => HttpResponse.error()));
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://shop.example.com");
    await user.click(authorise);
    await user.click(start);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Can't reach the CAWASMA API");
    expect(alert).toHaveTextContent("Your scan was not started.");
    expect(start).toBeEnabled();
    expect(push).not.toHaveBeenCalled();
  });

  it("shows an inline error when the API fails (5xx)", async () => {
    server.use(
      http.post("*/api/scan", () =>
        HttpResponse.json(
          {
            success: false,
            error: {
              code: "INTERNAL_ERROR",
              message: "An internal error occurred.",
            },
          },
          { status: 500 },
        ),
      ),
    );
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://shop.example.com");
    await user.click(authorise);
    await user.click(start);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The API could not start the scan",
    );
    expect(push).not.toHaveBeenCalled();
  });

  it("clears the API error when the user edits the form", async () => {
    server.use(http.post("*/api/scan", () => HttpResponse.error()));
    const { user, url, authorise, start } = setup();
    await user.type(url, "https://shop.example.com");
    await user.click(authorise);
    await user.click(start);
    await screen.findByRole("alert");

    await user.type(url, "/");
    await waitFor(() =>
      expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
    );
  });
});
