import { describe, expect, it } from "vitest";

import { compareVectors, firstCalculatorUrl, parseVector } from "./cvss";

const BASE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N";

describe("parseVector", () => {
  it("parses a base vector", () => {
    expect(parseVector(BASE)).toEqual({
      ok: true,
      vector: BASE,
      metrics: {
        AV: "N",
        AC: "H",
        PR: "N",
        UI: "R",
        S: "U",
        C: "H",
        I: "N",
        A: "N",
      },
    });
  });

  it("parses environmental and temporal metrics, in any order", () => {
    const parsed = parseVector(`  ${BASE}/CR:H/IR:M/AR:X/E:F/MAV:L  `);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.metrics).toMatchObject({
      CR: "H",
      IR: "M",
      AR: "X",
      E: "F",
      MAV: "L",
    });
    expect(parseVector("CVSS:3.1/A:N/I:N/C:H/S:U/UI:R/PR:N/AC:H/AV:N").ok).toBe(
      true,
    );
  });

  it.each([
    ["", /empty/],
    ["   ", /empty/],
    [null, /empty/],
    ["AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", /starts with "CVSS:3.1\/"/],
    ["CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", /CVSS 3\.0/],
    ["CVSS:2.0/AV:N", /CVSS 2\.0/],
    [`${BASE}/`, /"" is not a metric/],
    ["CVSS:3.1/AV=N/AC:H", /"AV=N" is not a metric/],
    [`${BASE}/XX:H`, /"XX" is not a CVSS v3.1 metric/],
    [
      `${BASE}/CR:Q`,
      /"Q" is not a valid value for Confidentiality Requirement \(CR\); expected one of X, L, M, H/,
    ],
    [
      "CVSS:3.1/AV:Z/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
      /valid value for Attack Vector/,
    ],
    [`${BASE}/AV:L`, /"AV" appears more than once/],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H", /Base metrics missing: I, A/],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N", /Base metric missing: A\./],
    ["CVSS:3.1/av:n/AC:H", /"av:n" is not a metric/],
  ])("rejects malformed vector %j", (input, error) => {
    const parsed = parseVector(input);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.error).toMatch(error);
  });
});

describe("compareVectors", () => {
  const metrics = (vector: string) => {
    const parsed = parseVector(vector);
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed.metrics;
  };

  it("lists the base metrics, then the environmental ones context sets", () => {
    const rows = compareVectors(
      metrics(BASE),
      metrics(`${BASE}/CR:H/IR:M/AR:X`),
    );
    expect(rows.map((r) => r.code)).toEqual([
      "AV",
      "AC",
      "PR",
      "UI",
      "S",
      "C",
      "I",
      "A",
      "CR",
      "IR",
      "AR",
    ]);
    expect(rows[0]).toEqual({
      code: "AV",
      name: "Attack Vector",
      group: "base",
      base: "Network",
      context: "Network",
      changed: false,
    });
    expect(rows.find((r) => r.code === "CR")).toMatchObject({
      base: null,
      context: "High",
      changed: true,
    });
  });

  it("highlights only environmental metrics set beyond Not Defined", () => {
    const changed = compareVectors(
      metrics(BASE),
      metrics(`${BASE}/CR:H/IR:M/AR:X`),
    )
      .filter((r) => r.changed)
      .map((r) => r.code);
    expect(changed).toEqual(["CR", "IR"]);
  });

  it("shows only base metrics without a context vector", () => {
    const rows = compareVectors(metrics(BASE), null);
    expect(rows).toHaveLength(8);
    expect(rows.every((r) => r.context === null && !r.changed)).toBe(true);
  });
});

describe("firstCalculatorUrl", () => {
  it("pre-fills the FIRST v3.1 calculator with the vector", () => {
    expect(firstCalculatorUrl(`${BASE}/CR:H`)).toBe(
      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N/CR:H",
    );
  });
});
