/**
 * Severity levels: label, icon and colour classes in one place. Colour values
 * live in globals.css (`--sev-*`, light and dark); everything that shows a
 * severity reads from here.
 *
 * Keys are the contract's `severity_bucket` values. `INFO` is shown as
 * "None", the CVSS v3.1 name for a 0.0 score.
 *
 * Accessibility: every level has its own icon shape and a text label, so it
 * reads without colour (colour-blind users, greyscale print).
 */

import {
  CircleAlert,
  CircleArrowDown,
  CircleMinus,
  OctagonAlert,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";

import type { Severity } from "./api-types";

export interface SeverityToken {
  label: string;
  icon: LucideIcon;
  /** Text + icon colour; readable on the page background and on `bg`. */
  text: string;
  /** Tinted background for badges. */
  bg: string;
  /** Border for badges and outlines. */
  border: string;
  /** Solid fill for bars and dots (non-text). */
  fill: string;
}

export const SEVERITY: Record<Severity, SeverityToken> = {
  CRITICAL: {
    label: "Critical",
    icon: OctagonAlert,
    text: "text-sev-critical",
    bg: "bg-sev-critical-bg",
    border: "border-sev-critical-solid",
    fill: "bg-sev-critical-solid",
  },
  HIGH: {
    label: "High",
    icon: TriangleAlert,
    text: "text-sev-high",
    bg: "bg-sev-high-bg",
    border: "border-sev-high-solid",
    fill: "bg-sev-high-solid",
  },
  MEDIUM: {
    label: "Medium",
    icon: CircleAlert,
    text: "text-sev-medium",
    bg: "bg-sev-medium-bg",
    border: "border-sev-medium-solid",
    fill: "bg-sev-medium-solid",
  },
  LOW: {
    label: "Low",
    icon: CircleArrowDown,
    text: "text-sev-low",
    bg: "bg-sev-low-bg",
    border: "border-sev-low-solid",
    fill: "bg-sev-low-solid",
  },
  INFO: {
    label: "None",
    icon: CircleMinus,
    text: "text-sev-none",
    bg: "bg-sev-none-bg",
    border: "border-sev-none-solid",
    fill: "bg-sev-none-solid",
  },
};

/** Highest first, the order findings are ranked in. */
export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

/**
 * CVSS v3.1 qualitative rating of a score (used for the base score; a
 * finding's final severity is its `severity_bucket`, which may be forced).
 */
export function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score >= 0.1) return "LOW";
  return "INFO";
}
