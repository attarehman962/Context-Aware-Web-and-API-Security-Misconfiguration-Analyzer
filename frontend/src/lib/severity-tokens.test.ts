/**
 * WCAG AA check of the severity colours in globals.css, light and dark:
 * text 4.5:1 on its badge background and on the page, fills 3:1 on the page.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { SEVERITY, severityFromScore } from "./severity";

const css = readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8");

function block(selector: string): Record<string, string> {
  const start = css.indexOf(`${selector} {`);
  const body = css.slice(start, css.indexOf("\n}", start));
  return Object.fromEntries(
    [...body.matchAll(/--([\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2]]),
  );
}

/** oklch(L C H) -> relative luminance (WCAG 2.x), via OKLab and linear sRGB. */
function luminance(value: string): number {
  const [l, c, h] = value
    .replace(/oklch\(|\)/g, "")
    .trim()
    .split(/\s+/)
    .map(Number);
  const a = c * Math.cos((h * Math.PI) / 180);
  const b = c * Math.sin((h * Math.PI) / 180);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const clamp = (x: number) => Math.min(1, Math.max(0, x));
  const r = clamp(4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_);
  const g = clamp(-1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_);
  const bl = clamp(-0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_);
  return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
}

function contrast(x: string, y: string): number {
  const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p);
  return (hi + 0.05) / (lo + 0.05);
}

const LEVELS = ["critical", "high", "medium", "low", "none", "success"];

describe.each([
  ["light", block(":root")],
  ["dark", { ...block(":root"), ...block(".dark") }],
])("severity tokens (%s)", (_theme, vars) => {
  it.each(LEVELS)("%s text passes AA on its badge and the page", (level) => {
    const text = vars[`sev-${level}`];
    expect(contrast(text, vars[`sev-${level}-bg`])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(text, vars.background)).toBeGreaterThanOrEqual(4.5);
  });

  it.each(LEVELS)("%s fill passes 3:1 on the page", (level) => {
    expect(
      contrast(vars[`sev-${level}-solid`], vars.background),
    ).toBeGreaterThanOrEqual(3);
  });
});

describe("severity tokens", () => {
  it("gives every level its own icon and label", () => {
    const tokens = Object.values(SEVERITY);
    expect(new Set(tokens.map((t) => t.icon)).size).toBe(tokens.length);
    expect(tokens.map((t) => t.label)).toEqual([
      "Critical",
      "High",
      "Medium",
      "Low",
      "None",
    ]);
  });

  it("maps scores to the CVSS v3.1 rating scale", () => {
    expect(severityFromScore(0)).toBe("INFO");
    expect(severityFromScore(0.1)).toBe("LOW");
    expect(severityFromScore(3.9)).toBe("LOW");
    expect(severityFromScore(4.0)).toBe("MEDIUM");
    expect(severityFromScore(6.9)).toBe("MEDIUM");
    expect(severityFromScore(7.0)).toBe("HIGH");
    expect(severityFromScore(8.9)).toBe("HIGH");
    expect(severityFromScore(9.0)).toBe("CRITICAL");
    expect(severityFromScore(10)).toBe("CRITICAL");
  });
});
