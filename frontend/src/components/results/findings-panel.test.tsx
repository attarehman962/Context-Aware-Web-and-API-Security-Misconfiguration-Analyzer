import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import type { Finding } from "@/lib/api-types";
import { NO_FILTERS, type FindingsView } from "@/lib/findings";
import { resultsDone } from "@/mocks/fixtures";
import { LARGE_SCAN_SIZE, largeScanResults } from "@/mocks/large-scan";

import { FindingsPanel } from "./findings-panel";

const DEFAULT_VIEW: FindingsView = { rankBy: "final", filters: NO_FILTERS };

/** The panel is controlled; this holds the view like the URL hook does. */
function Harness({
  findings = resultsDone.findings,
  initial = DEFAULT_VIEW,
  onViewChange,
  virtualize,
}: {
  findings?: Finding[];
  initial?: FindingsView;
  onViewChange?: (view: FindingsView) => void;
  virtualize?: boolean;
}) {
  const [view, setView] = useState(initial);
  return (
    <FindingsPanel
      findings={findings}
      chains={resultsDone.chains}
      targetUrl={resultsDone.scan.url}
      view={view}
      onViewChange={(next) => {
        setView(next);
        onViewChange?.(next);
      }}
      virtualize={virtualize}
    />
  );
}

function rows() {
  return screen.queryAllByRole("article");
}

function order() {
  return rows().map((row) => row.getAttribute("data-check-id"));
}

function row(checkId: string) {
  return rows().find((r) => r.getAttribute("data-check-id") === checkId)!;
}

describe("FindingsPanel: sorting and the base/final toggle", () => {
  it("ranks by context-aware score by default", () => {
    render(<Harness />);
    expect(
      screen.getByRole("radio", { name: "Context-aware score" }),
    ).toBeChecked();
    expect(order()).toEqual([
      "API-003",
      "HDR-002",
      "INF-003",
      "CKI-003",
      "TLS-001",
      "HDR-001",
      "HDR-007",
      "HDR-012",
    ]);
  });

  it("re-ranks by base score and back", async () => {
    const user = userEvent.setup();
    const onViewChange = vi.fn();
    render(<Harness onViewChange={onViewChange} />);

    await user.click(screen.getByRole("radio", { name: "Base score" }));
    expect(onViewChange).toHaveBeenLastCalledWith({
      rankBy: "base",
      filters: NO_FILTERS,
    });
    expect(order()).toEqual([
      "API-003",
      "INF-003",
      "TLS-001",
      "HDR-002",
      "HDR-001",
      "HDR-007",
      "CKI-003",
      "HDR-012",
    ]);
    expect(
      screen.getByText(/official CVSS v3.1 base score alone/),
    ).toBeVisible();

    await user.click(
      screen.getByRole("radio", { name: "Context-aware score" }),
    );
    expect(order()[1]).toBe("HDR-002");
  });

  it("shows each row's rank and how far the other ranking moves it", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const cookie = row("CKI-003");
    expect(cookie).toHaveAttribute("data-rank", "4");
    expect(within(cookie).getByText("#4")).toBeInTheDocument();
    expect(
      within(cookie).getByText(/places higher than by base score \(#7\)/),
    ).toBeInTheDocument();
    expect(
      within(cookie).getByText("Raised from Medium by context"),
    ).toBeVisible();

    await user.click(screen.getByRole("radio", { name: "Base score" }));
    const cookieBase = row("CKI-003");
    expect(cookieBase).toHaveAttribute("data-rank", "7");
    expect(
      within(cookieBase).getByText(
        /places lower than by context-aware score \(#4\)/,
      ),
    ).toBeInTheDocument();
  });

  it("colours the band and badge by the score being ranked by", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const band = () => row("HDR-002").querySelector("[data-band]");
    expect(band()).toHaveAttribute("data-band", "CRITICAL");
    expect(within(row("HDR-002")).getByText("Critical")).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: "Base score" }));
    expect(band()).toHaveAttribute("data-band", "MEDIUM");
    expect(within(row("HDR-002")).getByText("Medium")).toBeInTheDocument();
  });
});

describe("FindingsPanel: filters", () => {
  it("filters by several severities", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole("checkbox", { name: /Critical/ }));
    await user.click(screen.getByRole("checkbox", { name: /Low/ }));
    expect(order()).toEqual(["API-003", "HDR-002", "INF-003", "HDR-007"]);
    expect(screen.getByText("Showing 4 of 8 findings")).toBeInTheDocument();

    await user.click(screen.getByRole("checkbox", { name: /Critical/ }));
    expect(order()).toEqual(["HDR-007"]);
  });

  it("filters by category and OWASP id", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.selectOptions(screen.getByLabelText("Category"), "TLS");
    expect(order()).toEqual(["TLS-001"]);

    await user.selectOptions(screen.getByLabelText("Category"), "");
    await user.selectOptions(screen.getByLabelText("OWASP"), "API2:2023");
    expect(order()).toEqual(["API-003"]);
  });

  it("shows only findings in attack chains", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(
      screen.getByRole("checkbox", { name: "Only findings in attack chains" }),
    );
    expect(order()).toEqual(["INF-003", "HDR-007"]);
    expect(
      within(row("INF-003")).getByText("In chain C005"),
    ).toBeInTheDocument();
  });

  it("searches endpoints after a short pause", async () => {
    const user = userEvent.setup();
    const onViewChange = vi.fn();
    render(<Harness onViewChange={onViewChange} />);
    await user.type(screen.getByLabelText("Endpoint contains"), "/api/");
    await waitFor(() => expect(order()).toEqual(["API-003", "HDR-002"]));
    // One update for the whole word, not one per keystroke.
    expect(onViewChange).toHaveBeenCalledTimes(1);
  });

  it("keeps the ranking order while filtered", async () => {
    const user = userEvent.setup();
    render(
      <Harness
        initial={{
          rankBy: "base",
          filters: { ...NO_FILTERS, severities: ["CRITICAL"] },
        }}
      />,
    );
    expect(order()).toEqual(["API-003", "INF-003", "HDR-002"]);
    await user.click(
      screen.getByRole("radio", { name: "Context-aware score" }),
    );
    expect(order()).toEqual(["API-003", "HDR-002", "INF-003"]);
  });

  it("starts from a view taken from the URL", () => {
    render(
      <Harness
        initial={{
          rankBy: "final",
          filters: { ...NO_FILTERS, category: "HEADERS", endpoint: "/" },
        }}
      />,
    );
    expect(screen.getByLabelText("Category")).toHaveValue("HEADERS");
    expect(screen.getByLabelText("Endpoint contains")).toHaveValue("/");
    expect(order()).toEqual(["HDR-002", "HDR-001", "HDR-007", "HDR-012"]);
  });

  it("shows an empty state when nothing matches, and clears", async () => {
    const user = userEvent.setup();
    render(
      <Harness
        initial={{
          rankBy: "final",
          filters: { ...NO_FILTERS, category: "TLS", chainsOnly: true },
        }}
      />,
    );
    expect(rows()).toHaveLength(0);
    expect(
      screen.getByText("No findings match these filters"),
    ).toBeInTheDocument();

    const clear = screen.getAllByRole("button", { name: "Clear filters" });
    await user.click(clear[clear.length - 1]);
    expect(rows()).toHaveLength(8);
    expect(screen.getByLabelText("Category")).toHaveValue("");
  });
});

describe("FindingsPanel: states and scale", () => {
  it("shows an empty state for a scan without findings", () => {
    render(<Harness findings={[]} />);
    expect(screen.getByText("No misconfigurations found")).toBeInTheDocument();
    expect(screen.queryByText("Rank by")).not.toBeInTheDocument();
  });

  it(`renders only the visible rows of ${LARGE_SCAN_SIZE} findings`, () => {
    const { findings } = largeScanResults();
    render(<Harness findings={findings} />);
    const list = screen.getByRole("list", { name: "Findings" });
    expect(list).toHaveAttribute("data-virtualized");
    expect(rows().length).toBeGreaterThan(0);
    expect(rows().length).toBeLessThan(40);
    expect(within(list).getAllByRole("listitem")[0]).toHaveAttribute(
      "aria-setsize",
      String(LARGE_SCAN_SIZE),
    );
    expect(
      screen.getByText(
        `Showing ${LARGE_SCAN_SIZE} of ${LARGE_SCAN_SIZE} findings`,
      ),
    ).toBeInTheDocument();
  });

  it("filters the large scan without rendering it all", async () => {
    const user = userEvent.setup();
    const { findings } = largeScanResults();
    render(<Harness findings={findings} />);
    await user.click(
      screen.getByRole("checkbox", { name: "Only findings in attack chains" }),
    );
    // Every 25th finding is in a chain: 24 of 600, few enough to list.
    expect(
      screen.getByText(`Showing 24 of ${LARGE_SCAN_SIZE} findings`),
    ).toBeInTheDocument();
    expect(rows()).toHaveLength(24);
  });
});
