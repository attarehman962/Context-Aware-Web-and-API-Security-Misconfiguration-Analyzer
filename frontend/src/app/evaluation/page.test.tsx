import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { evaluation, overallByTool } from "@/lib/evaluation";

import EvaluationPage from "./page";

describe("/evaluation", () => {
  it("has the charts, each with a takeaway", () => {
    const { container } = render(<EvaluationPage />);
    const charts = [...container.querySelectorAll("[data-chart]")].map((el) =>
      el.getAttribute("data-chart"),
    );
    expect(charts).toEqual([
      "tool-quality",
      "tool-time",
      "ranking-movement",
      "ranking-first-critical",
      "ranking-ndcg",
      "classifier-accuracy",
      "classifier-confusion",
    ]);
    for (const takeaway of screen.getAllByTestId("takeaway"))
      expect(takeaway.textContent?.length).toBeGreaterThan(20);
  });

  it("draws the values from the CSV copy", () => {
    render(<EvaluationPage />);
    const quality = screen.getByRole("figure", {
      name: "Detection quality, all targets",
    });
    const recall = overallByTool().cawasma.recall!.toFixed(2);
    expect(
      within(quality).getAllByTitle(`Recall · CAWASMA: ${recall}`),
    ).toHaveLength(1);

    const matrix = screen.getByRole("figure", { name: /Confusion matrix/ });
    const low = evaluation.confusion.find(
      (r) => r["true \\ predicted"] === "LOW",
    )!;
    expect(
      within(matrix).getByTitle(`LOW classed LOW: ${low.LOW}`),
    ).toHaveTextContent(`${low.LOW}`);
  });

  it("highlights findings that climbed after context-aware scoring", () => {
    const { container } = render(<EvaluationPage />);
    const after = within(
      screen.getByRole("region", {
        name: "After: ranked by context-aware score",
      }),
    );
    expect(after.getAllByRole("listitem").length).toBe(
      evaluation.mapping.length * 2,
    );
    expect(
      container.querySelector('[data-moved]:not([data-moved="0"])'),
    ).not.toBeNull();
  });
});
