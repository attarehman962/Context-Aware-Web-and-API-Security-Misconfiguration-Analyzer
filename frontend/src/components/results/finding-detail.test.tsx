import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { NO_FILTERS } from "@/lib/findings";
import { resultsDone } from "@/mocks/fixtures";
import { createMockServer } from "@/mocks/node";

import { Harness } from "./findings-panel.harness";

const server = createMockServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const row = (checkId: string) =>
  screen
    .getAllByRole("article")
    .find((r) => r.getAttribute("data-check-id") === checkId)!;

async function open(user: ReturnType<typeof userEvent.setup>, checkId: string) {
  await user.click(
    within(row(checkId)).getByRole("button", { name: /Why this score\?/ }),
  );
  return row(checkId);
}

describe("finding detail: expanding", () => {
  it("opens and closes from the keyboard", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const button = within(row("CKI-003")).getByRole("button", {
      name: /Why this score\?.*CKI-003/,
    });
    expect(button).toHaveAttribute("aria-expanded", "false");

    button.focus();
    await user.keyboard("{Enter}");
    expect(button).toHaveAttribute("aria-expanded", "true");
    const detail = document.getElementById(
      button.getAttribute("aria-controls")!,
    );
    expect(detail).not.toBeNull();

    await user.keyboard(" ");
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(
      document.getElementById(button.getAttribute("aria-controls")!),
    ).toBeNull();
  });

  it("tells the score story at once and loads the endpoint details", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "CKI-003");
    expect(within(article).getByTestId("score-story")).toHaveTextContent(
      "Raised from 7.1 to 8.6 because the endpoint is classified as Admin / payment.",
    );
    expect(
      await within(article).findByText(
        /Classifier: Contains identity\/privilege tokens/,
      ),
    ).toBeInTheDocument();
    const snippet = within(article).getByRole("region", {
      name: "Request and response",
    });
    expect(snippet).toHaveTextContent("GET /admin/login HTTP/1.1");
    expect(snippet).toHaveTextContent(
      "Set-Cookie: admin_session=<value not stored>; Path=/; Secure; HttpOnly; SameSite=UNSET",
    );
    expect(snippet).toHaveAttribute("tabindex", "0");
  });

  it("highlights the requirements context set and links the FIRST calculator", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "HDR-002");
    const changed = [...article.querySelectorAll("tr[data-changed]")].map((r) =>
      r.getAttribute("data-metric"),
    );
    expect(changed).toEqual(["CR", "IR", "AR"]);
    expect(
      within(article).getByRole("link", {
        name: /Verify the context-aware score/,
      }),
    ).toHaveAttribute(
      "href",
      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N/CR:H/IR:H/AR:H",
    );
  });

  it("links OWASP and CWE ids to their official pages", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "INF-007");
    expect(
      within(article).getByRole("link", {
        name: /A05:2021 Security Misconfiguration/,
      }),
    ).toHaveAttribute(
      "href",
      "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    );
    expect(
      within(article).getByRole("link", { name: /CWE-209/ }),
    ).toHaveAttribute(
      "href",
      "https://cwe.mitre.org/data/definitions/209.html",
    );
  });

  it("explains a malformed vector instead of a table", async () => {
    const user = userEvent.setup();
    const broken = resultsDone.findings.map((f) =>
      f.check_id === "HDR-001"
        ? { ...f, cvss_vector: "CVSS:3.1/AV:N/AC:Q" }
        : f,
    );
    render(<Harness findings={broken} />);
    const article = await open(user, "HDR-001");
    expect(
      within(article).getByText(
        /This vector could not be read: "Q" is not a valid value/,
      ),
    ).toBeInTheDocument();
    expect(
      within(article).queryByRole("link", { name: /Verify the base score/ }),
    ).not.toBeInTheDocument();
  });

  it("keeps the score story when the details fail to load", async () => {
    server.use(
      http.get("*/api/results/:scanId/findings/:findingId", () =>
        HttpResponse.error(),
      ),
    );
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "HDR-001");
    expect(within(article).getByTestId("score-story")).toBeInTheDocument();
    expect(
      await within(article).findByText(
        "Could not load the full details",
        {},
        { timeout: 15_000 },
      ),
    ).toBeInTheDocument();
  }, 20_000);
});

describe("finding detail: chain links", () => {
  it("links to the other members of the chain", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "INF-007");
    const chain = article.querySelector('[data-chain="C002"]') as HTMLElement;
    expect(chain).toHaveTextContent(
      "Error disclosure plus version banner enables targeted exploitation",
    );
    const link = within(chain).getByRole("link", {
      name: "HDR-007 Server version disclosure on /",
    });
    expect(link).toHaveAttribute(
      "href",
      "#finding-f0000000-0000-4000-8000-000000000006",
    );
    // No link to the finding itself.
    expect(within(chain).getAllByRole("link")).toHaveLength(1);
  });

  it("opens and focuses the linked finding", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "INF-007");
    await user.click(within(article).getByRole("link", { name: /HDR-007/ }));

    const banner = row("HDR-007");
    expect(banner).toHaveAttribute("data-open", "true");
    await waitFor(() => expect(banner).toHaveFocus());
    // Its own detail links back.
    expect(
      within(banner).getByRole("link", {
        name: /INF-007 Verbose Error Response/,
      }),
    ).toBeInTheDocument();
  });

  it("clears filters that hide the linked finding", async () => {
    const user = userEvent.setup();
    render(
      <Harness
        initial={{
          rankBy: "final",
          filters: { ...NO_FILTERS, category: "INFO_DISCLOSURE" },
        }}
      />,
    );
    expect(
      screen.queryByText("Server version disclosure"),
    ).not.toBeInTheDocument();
    const article = await open(user, "INF-007");
    await user.click(within(article).getByRole("link", { name: /HDR-007/ }));

    expect(screen.getByLabelText("Category")).toHaveValue("");
    await waitFor(() => expect(row("HDR-007")).toHaveFocus());
  });

  it("says when a finding is the chain's only member", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "INF-003");
    const chain = article.querySelector('[data-chain="C005"]') as HTMLElement;
    expect(chain).toHaveTextContent(
      "This finding is the only member; the chain fires because the response also contains credentials.",
    );
    expect(within(chain).queryByRole("link")).not.toBeInTheDocument();
  });

  it("says when a finding is in no chain", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const article = await open(user, "CKI-003");
    expect(
      within(article).getByText("Not part of an attack chain."),
    ).toBeInTheDocument();
  });
});
