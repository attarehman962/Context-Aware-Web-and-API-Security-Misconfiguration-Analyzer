import { describe, expect, it } from "vitest";

import { resultsDone } from "@/mocks/fixtures";

import {
  NO_FILTERS,
  applyFilters,
  categoryLabel,
  filterOptions,
  hasFilters,
  parseView,
  rankFindings,
  serializeView,
  severityShifts,
  type FindingFilters,
} from "./findings";

const findings = resultsDone.findings;
const ids = (ranked: { finding: { check_id: string } }[]) =>
  ranked.map((r) => r.finding.check_id);
const filter = (patch: Partial<FindingFilters>) =>
  ids(applyFilters(rankFindings(findings), { ...NO_FILTERS, ...patch }));

describe("rankFindings", () => {
  it("ranks by final_score, ties by check_id", () => {
    expect(ids(rankFindings(findings))).toEqual([
      "API-003", // 10.0
      "HDR-002", // 10.0
      "INF-003", // 10.0
      "CKI-003", // 8.6
      "TLS-001", // 7.4
      "HDR-001", // 5.3
      "HDR-007", // 3.2
      "HDR-012", // 0.0
    ]);
  });

  it("ranks by base_score, then final_score, then check_id", () => {
    expect(ids(rankFindings(findings, "base"))).toEqual([
      "API-003", // 7.5 / 10.0
      "INF-003", // 7.5 / 10.0
      "TLS-001", // 7.4
      "HDR-002", // 6.1
      "HDR-001", // 5.3 / 5.3
      "HDR-007", // 5.3 / 3.2
      "CKI-003", // 4.3
      "HDR-012", // 3.1
    ]);
  });

  it("gives every finding both ranks, whatever the order", () => {
    const byFinal = rankFindings(findings, "final");
    const byBase = rankFindings(findings, "base");
    const cki = byFinal.find((r) => r.finding.check_id === "CKI-003")!;
    expect(cki).toMatchObject({ finalRank: 4, baseRank: 7 });
    expect(byBase.find((r) => r.finding.check_id === "CKI-003")).toEqual(cki);
    expect(byFinal.map((r) => r.finalRank)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(byBase.map((r) => r.baseRank)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("measures the severity shift from the base rating", () => {
    const shift = Object.fromEntries(
      rankFindings(findings).map((r) => [r.finding.check_id, r.severityShift]),
    );
    expect(shift).toEqual({
      "API-003": 1, // HIGH -> CRITICAL
      "HDR-002": 2, // MEDIUM -> CRITICAL
      "INF-003": 1, // HIGH -> CRITICAL
      "CKI-003": 1, // MEDIUM -> HIGH
      "TLS-001": 0,
      "HDR-001": 0,
      "HDR-007": -1, // MEDIUM -> LOW
      "HDR-012": -1, // LOW -> INFO
    });
    expect(severityShifts(rankFindings(findings))).toEqual({ up: 4, down: 2 });
  });

  it("does not modify its input", () => {
    const before = ids(findings.map((finding) => ({ finding })));
    rankFindings(findings, "base");
    expect(ids(findings.map((finding) => ({ finding })))).toEqual(before);
  });
});

describe("applyFilters", () => {
  it("keeps everything without filters", () => {
    expect(filter({})).toHaveLength(8);
    expect(hasFilters(NO_FILTERS)).toBe(false);
  });

  it("filters by several context-aware severities", () => {
    expect(filter({ severities: ["HIGH", "LOW"] })).toEqual([
      "CKI-003",
      "TLS-001",
      "HDR-007",
    ]);
  });

  it("filters by category, OWASP id and chains", () => {
    expect(filter({ category: "HEADERS" })).toEqual([
      "HDR-002",
      "HDR-001",
      "HDR-007",
      "HDR-012",
    ]);
    expect(filter({ owasp: "API2:2023" })).toEqual(["API-003"]);
    expect(filter({ chainsOnly: true })).toEqual(["INF-003", "HDR-007"]);
  });

  it("searches endpoints case-insensitively and skips host-level findings", () => {
    expect(filter({ endpoint: "  /API/ " })).toEqual(["API-003", "HDR-002"]);
    expect(filter({ endpoint: "shop.example.com" })).not.toContain("TLS-001");
  });

  it("combines filters (all must match) and keeps the ranking", () => {
    expect(filter({ severities: ["CRITICAL"], category: "HEADERS" })).toEqual([
      "HDR-002",
    ]);
    expect(
      ids(
        applyFilters(rankFindings(findings, "base"), {
          ...NO_FILTERS,
          severities: ["CRITICAL"],
        }),
      ),
    ).toEqual(["API-003", "INF-003", "HDR-002"]);
  });

  it("lists the filter values present in the scan", () => {
    expect(filterOptions(findings)).toEqual({
      categories: ["COOKIES", "HEADERS", "INFO_DISCLOSURE", "REST_API", "TLS"],
      owasp: ["API2:2023", "API8:2023"],
      hasChains: true,
    });
  });
});

describe("URL query", () => {
  it("round-trips a full view", () => {
    const view = {
      rankBy: "base" as const,
      filters: {
        severities: ["LOW" as const, "CRITICAL" as const],
        category: "HEADERS",
        owasp: "API8:2023",
        chainsOnly: true,
        endpoint: "/admin",
      },
    };
    const query = serializeView(view).toString();
    expect(query).toBe(
      "rank=base&severity=CRITICAL%2CLOW&category=HEADERS&owasp=API8%3A2023&chains=1&endpoint=%2Fadmin",
    );
    expect(parseView(new URLSearchParams(query))).toEqual({
      ...view,
      filters: { ...view.filters, severities: ["CRITICAL", "LOW"] },
    });
  });

  it("omits defaults and keeps unrelated parameters", () => {
    const query = serializeView(
      { rankBy: "final", filters: NO_FILTERS },
      new URLSearchParams("tab=chains&severity=HIGH"),
    ).toString();
    expect(query).toBe("tab=chains");
  });

  it("ignores values it does not understand", () => {
    expect(
      parseView(
        new URLSearchParams("rank=nope&severity=high,BOGUS&chains=yes"),
      ),
    ).toEqual({
      rankBy: "final",
      filters: { ...NO_FILTERS, severities: ["HIGH"] },
    });
  });
});

describe("categoryLabel", () => {
  it("names categories for display", () => {
    expect(categoryLabel("REST_API")).toBe("REST API");
    expect(categoryLabel("TLS")).toBe("TLS");
    expect(categoryLabel("NEW_THING")).toBe("New thing");
  });
});
