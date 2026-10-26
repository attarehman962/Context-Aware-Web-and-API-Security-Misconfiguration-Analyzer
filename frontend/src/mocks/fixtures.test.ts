import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { resultsDone } from "./fixtures";

const docsDir = path.resolve(__dirname, "../../../docs/examples");
const fixturesDir = path.resolve(__dirname, "fixtures");

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8"));
}

describe("mock fixtures", () => {
  it.each(readdirSync(fixturesDir))("%s matches docs/examples", (name) => {
    expect(readJson(path.join(fixturesDir, name))).toEqual(
      readJson(path.join(docsDir, name)),
    );
  });

  it("covers every severity, a chain and body signals", () => {
    const severities = new Set(
      resultsDone.findings.map((f) => f.severity_bucket),
    );
    expect([...severities].sort()).toEqual([
      "CRITICAL",
      "HIGH",
      "INFO",
      "LOW",
      "MEDIUM",
    ]);
    expect(resultsDone.chains.length).toBeGreaterThan(0);
    expect(resultsDone.findings.some((f) => f.chain_ids.length > 0)).toBe(true);
    expect(resultsDone.findings.some((f) => f.body_signals.length > 0)).toBe(
      true,
    );
  });

  it("keeps severity_counts in line with the findings", () => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of resultsDone.findings) {
      counts[f.severity_bucket.toLowerCase() as keyof typeof counts] += 1;
    }
    expect(resultsDone.scan.severity_counts).toEqual(counts);
  });
});
