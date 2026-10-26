/**
 * Findings view logic for /scans/[id]: ranking by context-aware or base
 * score, filters, and their URL query form. Pure functions; the components
 * only render what these return.
 *
 * Ranking by base score shows each check's official CVSS v3.1 order;
 * ranking by final score shows CAWASMA's context-aware order. Comparing the
 * two is the project's main idea, so both ranks are kept on every row.
 */

import type { Finding, Severity } from "./api-types";
import { SEVERITY_ORDER, severityFromScore } from "./severity";

export type RankBy = "final" | "base";

export interface FindingFilters {
  /** Context-aware severities (`severity_bucket`); empty = all. */
  severities: Severity[];
  category: string | null;
  owasp: string | null;
  chainsOnly: boolean;
  /** Case-insensitive substring of the endpoint URL. */
  endpoint: string;
}

export interface FindingsView {
  rankBy: RankBy;
  filters: FindingFilters;
}

export const NO_FILTERS: FindingFilters = {
  severities: [],
  category: null,
  owasp: null,
  chainsOnly: false,
  endpoint: "",
};

export interface RankedFinding {
  finding: Finding;
  /** 1-based position when ranked by final_score (context-aware). */
  finalRank: number;
  /** 1-based position when ranked by base_score (official CVSS). */
  baseRank: number;
  /** CVSS rating of the base score. */
  baseSeverity: Severity;
  /** Severity steps gained through context: > 0 up, < 0 down. */
  severityShift: number;
}

function byFinal(a: Finding, b: Finding): number {
  return b.final_score - a.final_score || a.check_id.localeCompare(b.check_id);
}

function byBase(a: Finding, b: Finding): number {
  return (
    b.base_score - a.base_score ||
    b.final_score - a.final_score ||
    a.check_id.localeCompare(b.check_id)
  );
}

/** Both ranks for every finding, returned in the requested order. */
export function rankFindings(
  findings: Finding[],
  rankBy: RankBy = "final",
): RankedFinding[] {
  const finalRank = new Map(
    [...findings].sort(byFinal).map((f, i) => [f.id, i + 1]),
  );
  const baseOrder = [...findings].sort(byBase);
  const baseRank = new Map(baseOrder.map((f, i) => [f.id, i + 1]));
  const ranked = findings.map((finding) => {
    const baseSeverity = severityFromScore(finding.base_score);
    return {
      finding,
      finalRank: finalRank.get(finding.id)!,
      baseRank: baseRank.get(finding.id)!,
      baseSeverity,
      severityShift:
        SEVERITY_ORDER.indexOf(baseSeverity) -
        SEVERITY_ORDER.indexOf(finding.severity_bucket),
    };
  });
  return ranked.sort((a, b) =>
    rankBy === "final" ? a.finalRank - b.finalRank : a.baseRank - b.baseRank,
  );
}

/** How many findings context moved up or down at least one severity. */
export function severityShifts(ranked: RankedFinding[]) {
  return {
    up: ranked.filter((r) => r.severityShift > 0).length,
    down: ranked.filter((r) => r.severityShift < 0).length,
  };
}

export function applyFilters(
  ranked: RankedFinding[],
  filters: FindingFilters,
): RankedFinding[] {
  const needle = filters.endpoint.trim().toLowerCase();
  return ranked.filter(({ finding: f }) => {
    if (
      filters.severities.length > 0 &&
      !filters.severities.includes(f.severity_bucket)
    ) {
      return false;
    }
    if (filters.category && f.category !== filters.category) return false;
    if (filters.owasp && !f.owasp_map.includes(filters.owasp)) return false;
    if (filters.chainsOnly && f.chain_ids.length === 0) return false;
    if (needle && !(f.endpoint_url ?? "").toLowerCase().includes(needle)) {
      return false;
    }
    return true;
  });
}

export function hasFilters(filters: FindingFilters): boolean {
  return (
    filters.severities.length > 0 ||
    filters.category !== null ||
    filters.owasp !== null ||
    filters.chainsOnly ||
    filters.endpoint.trim() !== ""
  );
}

/** Values present in the scan, for the filter menus. */
export function filterOptions(findings: Finding[]) {
  const sorted = (values: Iterable<string>) => [...new Set(values)].sort();
  return {
    categories: sorted(findings.map((f) => f.category)),
    owasp: sorted(findings.flatMap((f) => f.owasp_map)),
    hasChains: findings.some((f) => f.chain_ids.length > 0),
  };
}

const CATEGORY_LABELS: Record<string, string> = {
  HEADERS: "Headers",
  COOKIES: "Cookies",
  CORS: "CORS",
  TLS: "TLS",
  REST_API: "REST API",
  AUTH: "Auth",
  INFO_DISCLOSURE: "Info disclosure",
};

/** Display name of a finding category (unknown ones are tidied up). */
export function categoryLabel(category: string): string {
  return (
    CATEGORY_LABELS[category] ??
    category.charAt(0) + category.slice(1).replace(/_/g, " ").toLowerCase()
  );
}

// ------------------------------------------------------------- URL query

/**
 * Query keys: `rank=base`, `severity=CRITICAL,HIGH`, `category=HEADERS`,
 * `owasp=API8:2023`, `chains=1`, `endpoint=admin`. Defaults are omitted so
 * an unfiltered view has a clean URL.
 */
export function parseView(params: URLSearchParams): FindingsView {
  const severities = (params.get("severity") ?? "")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter((s): s is Severity => SEVERITY_ORDER.includes(s as Severity));
  return {
    rankBy: params.get("rank") === "base" ? "base" : "final",
    filters: {
      severities: SEVERITY_ORDER.filter((s) => severities.includes(s)),
      category: params.get("category") || null,
      owasp: params.get("owasp") || null,
      chainsOnly: params.get("chains") === "1",
      endpoint: params.get("endpoint") ?? "",
    },
  };
}

export function serializeView(
  view: FindingsView,
  base: URLSearchParams = new URLSearchParams(),
): URLSearchParams {
  const params = new URLSearchParams(base);
  const set = (key: string, value: string | null) =>
    value ? params.set(key, value) : params.delete(key);
  const { filters } = view;
  set("rank", view.rankBy === "base" ? "base" : null);
  set(
    "severity",
    filters.severities.length > 0
      ? SEVERITY_ORDER.filter((s) => filters.severities.includes(s)).join(",")
      : null,
  );
  set("category", filters.category);
  set("owasp", filters.owasp);
  set("chains", filters.chainsOnly ? "1" : null);
  set("endpoint", filters.endpoint.trim() || null);
  return params;
}

/** Path (+ query) when the endpoint is on the target's origin, else the URL. */
export function displayEndpoint(
  endpointUrl: string,
  targetUrl: string,
): string {
  try {
    const endpoint = new URL(endpointUrl);
    if (endpoint.origin === new URL(targetUrl).origin) {
      return endpoint.pathname + endpoint.search;
    }
  } catch {
    // Not a URL we can parse: show it as sent.
  }
  return endpointUrl;
}
