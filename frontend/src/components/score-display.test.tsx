import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScoreDisplay } from "./score-display";

function root(container: HTMLElement) {
  return container.firstElementChild as HTMLElement;
}

describe("ScoreDisplay", () => {
  it("shows base -> final with an arrow when context raised the score", () => {
    const { container } = render(
      <ScoreDisplay base={4.3} final={8.6} severity="HIGH" />,
    );
    expect(root(container)).toHaveAttribute("data-changed", "true");
    expect(container.querySelectorAll("svg")).toHaveLength(1);
    expect(screen.getByText("4.3")).toBeInTheDocument();
    expect(screen.getByText("8.6")).toBeInTheDocument();
    expect(screen.getByText("CVSS base")).toBeInTheDocument();
    expect(screen.getByText("Context-aware")).toBeInTheDocument();
    expect(
      screen.getByText("CVSS base score 4.3, raised by context to 8.6 (High)"),
    ).toBeInTheDocument();
  });

  it("says 'lowered' when context reduced the score", () => {
    render(<ScoreDisplay base={5.3} final={3.2} severity="LOW" />);
    expect(
      screen.getByText("CVSS base score 5.3, lowered by context to 3.2 (Low)"),
    ).toBeInTheDocument();
  });

  it("shows a single score and no arrow when they are equal", () => {
    const { container } = render(<ScoreDisplay base={5.3} final={5.3} />);
    expect(root(container)).toHaveAttribute("data-changed", "false");
    expect(container.querySelector("svg")).toBeNull();
    expect(screen.getAllByText("5.3")).toHaveLength(1);
    expect(screen.queryByText("CVSS base")).not.toBeInTheDocument();
    expect(
      screen.getByText(/context did not change the CVSS base score/),
    ).toBeInTheDocument();
  });

  it("treats scores equal to one decimal as unchanged", () => {
    const { container } = render(<ScoreDisplay base={7.5} final={7.54} />);
    expect(root(container)).toHaveAttribute("data-changed", "false");
  });

  it("always shows one decimal", () => {
    render(<ScoreDisplay base={7} final={10} severity="CRITICAL" />);
    expect(screen.getByText("7.0")).toBeInTheDocument();
    expect(screen.getByText("10.0")).toBeInTheDocument();
  });

  it("colours the final score by the finding's severity bucket", () => {
    // Forced bucket: 5.3 alone would be MEDIUM.
    render(<ScoreDisplay base={5.3} final={5.3} severity="CRITICAL" />);
    expect(screen.getByText("5.3")).toHaveClass("text-sev-critical");
    expect(screen.getByText(/\(Critical\)/)).toBeInTheDocument();
  });

  it("derives the severity from the final score when none is given", () => {
    render(<ScoreDisplay base={3.1} final={0} />);
    expect(screen.getByText("0.0")).toHaveClass("text-sev-none");
  });

  it("hides the captions in compact mode", () => {
    render(<ScoreDisplay base={4.3} final={8.6} compact />);
    expect(screen.queryByText("CVSS base")).not.toBeInTheDocument();
    expect(screen.queryByText("Context-aware")).not.toBeInTheDocument();
    expect(screen.getByText(/raised by context to 8.6/)).toBeInTheDocument();
  });

  it("hides the visual numbers from screen readers (they read the summary)", () => {
    render(<ScoreDisplay base={4.3} final={8.6} />);
    expect(screen.getByText("8.6").closest("[aria-hidden]")).not.toBeNull();
  });
});
