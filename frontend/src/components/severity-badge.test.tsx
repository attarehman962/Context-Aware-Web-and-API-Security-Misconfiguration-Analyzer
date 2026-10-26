import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { Severity } from "@/lib/api-types";
import { SEVERITY_ORDER } from "@/lib/severity";

import { SeverityBadge } from "./severity-badge";

const LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "None",
};

describe("SeverityBadge", () => {
  it.each(SEVERITY_ORDER)("shows %s as a text label, not colour alone", (s) => {
    const { container } = render(<SeverityBadge severity={s} />);
    const badge = container.firstElementChild as HTMLElement;
    expect(badge).toHaveTextContent(LABELS[s]);
    expect(badge).toHaveAttribute("data-severity", s);
  });

  it("gives screen readers the context", () => {
    const { container } = render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("Severity:")).toHaveClass("sr-only");
    expect(container.firstElementChild).toHaveTextContent(/^Severity: High$/);
  });

  it("shows INFO as None (CVSS v3.1 name for 0.0)", () => {
    const { container } = render(<SeverityBadge severity="INFO" />);
    expect(container.firstElementChild).toHaveTextContent(/^Severity: None$/);
  });

  it("has a decorative icon hidden from assistive tech", () => {
    const { container } = render(<SeverityBadge severity="CRITICAL" />);
    const icon = container.querySelector("svg");
    expect(icon).not.toBeNull();
    expect(icon).toHaveAttribute("aria-hidden", "true");
  });

  it("uses a different icon for every level", () => {
    const icons = SEVERITY_ORDER.map((s) => {
      const { container, unmount } = render(<SeverityBadge severity={s} />);
      const markup = container.querySelector("svg")!.innerHTML;
      unmount();
      return markup;
    });
    expect(new Set(icons).size).toBe(SEVERITY_ORDER.length);
  });

  it("applies the level's colour tokens", () => {
    const { container } = render(<SeverityBadge severity="MEDIUM" />);
    expect(container.firstElementChild).toHaveClass(
      "text-sev-medium",
      "bg-sev-medium-bg",
      "border-sev-medium-solid",
    );
  });

  it("supports a small size", () => {
    const { container } = render(<SeverityBadge severity="LOW" size="sm" />);
    expect(container.firstElementChild).toHaveClass("text-xs");
  });
});
