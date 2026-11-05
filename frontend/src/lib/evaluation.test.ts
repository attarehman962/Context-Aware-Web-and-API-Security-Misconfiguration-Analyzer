import { describe, expect, it } from "vitest";

import {
  classifierTakeaway,
  confusionMatrix,
  confusionTakeaway,
  evaluation,
  movementTakeaway,
  ndcgTakeaway,
  overallByTool,
  rankedFindings,
  rankingTakeaway,
  timeTakeaway,
  toolsTakeaway,
  type Evaluation,
} from "./evaluation";

// A small hand-made table set, so these tests do not move when Asim
// re-runs the evaluation; the real data is checked by src/data/evaluation.test.ts.
const data: Evaluation = {
  source: "test",
  tools: [
    {
      tool: "cawasma",
      target: "a",
      tp: 4,
      fp: 1,
      fn: 1,
      tn: 4,
      precision: 0.8,
      recall: 0.8,
      fpr: 0.2,
      scan_seconds: 2,
    },
    {
      tool: "cawasma",
      target: "all (micro)",
      tp: 4,
      fp: 1,
      fn: 1,
      tn: 4,
      precision: 0.8,
      recall: 0.8,
      fpr: 0.2,
      scan_seconds: 2,
    },
    {
      tool: "zap",
      target: "all (micro)",
      tp: 1,
      fp: 0,
      fn: 4,
      tn: 5,
      precision: 1,
      recall: 0.2,
      fpr: 0,
      scan_seconds: 20,
    },
    {
      tool: "nuclei",
      target: "all (micro)",
      tp: 0,
      fp: 0,
      fn: 5,
      tn: 5,
      precision: null,
      recall: 0,
      fpr: 0,
      scan_seconds: 100,
    },
  ],
  ranking: [
    {
      target: "a",
      priority_items: 5,
      critical_items: 2,
      ndcg10_base: 0.2,
      ndcg10_context: 0.4,
      first_critical_base: 3,
      first_critical_context: 1,
    },
    {
      target: "b",
      priority_items: 5,
      critical_items: 2,
      ndcg10_base: 0.5,
      ndcg10_context: 0.5,
      first_critical_base: null,
      first_critical_context: null,
    },
    {
      target: "mean",
      priority_items: null,
      critical_items: null,
      ndcg10_base: 0.35,
      ndcg10_context: 0.45,
      first_critical_base: 3,
      first_critical_context: 1,
    },
  ],
  mapping: [
    {
      check_id: "HIGH-1",
      title: "High base",
      base_vector: "",
      base: 8,
      low: 8,
      medium: 8,
      high: 8.5,
      critical: 8.5,
    },
    {
      check_id: "LOW-1",
      title: "Low base",
      base_vector: "",
      base: 5,
      low: 5,
      medium: 5,
      high: 8.8,
      critical: 8.8,
    },
  ],
  classifier: [
    {
      families: "shipped",
      split: "test",
      n: 10,
      accuracy: 0.4,
      macro_f1: 0.3,
      off_by_two_or_more: 2,
      recall_low: 1,
      recall_medium: 0,
      recall_high: 0,
      recall_critical: 0,
    },
    {
      families: "proposed",
      split: "test",
      n: 10,
      accuracy: 0.5,
      macro_f1: 0.45,
      off_by_two_or_more: 1,
      recall_low: 1,
      recall_medium: 0.5,
      recall_high: 0,
      recall_critical: 0,
    },
  ],
  confusion: [
    { "true \\ predicted": "LOW", LOW: 3, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    { "true \\ predicted": "MEDIUM", LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 4 },
    { "true \\ predicted": "HIGH", LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    {
      "true \\ predicted": "CRITICAL",
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 1,
    },
  ],
};

describe("tool comparison", () => {
  it("reads the pooled row per tool", () => {
    expect(overallByTool(data).zap.recall).toBe(0.2);
  });

  it("takeaways quote the numbers", () => {
    expect(toolsTakeaway(data)).toBe(
      "CAWASMA finds 4 of 5 expected issues (recall 0.80), against 0.20 for ZAP and 0.00 for Nuclei, at the cost of 1 false positive (precision 0.80).",
    );
    expect(timeTakeaway(data)).toBe(
      "A CAWASMA scan takes 2 s per target on average: 10× faster than ZAP (20 s) and 50× faster than Nuclei (100 s).",
    );
  });
});

describe("ranking", () => {
  it("ranks the same findings by base and by final score", () => {
    const ranked = rankedFindings(data);
    const byId = Object.fromEntries(ranked.map((f) => [f.id, f]));
    expect(byId["LOW-1@CRITICAL"]).toMatchObject({
      baseRank: 3,
      finalRank: 1,
      moved: 2,
    });
    expect(byId["HIGH-1@LOW"]).toMatchObject({
      baseRank: 1,
      finalRank: 3,
      moved: -2,
    });
    // Ties share a place: both LOW-1 copies are #3 by base score.
    expect(byId["LOW-1@LOW"]).toMatchObject({
      baseRank: 3,
      finalRank: 4,
      moved: -1,
    });
  });

  it("takeaways", () => {
    expect(movementTakeaway(rankedFindings(data))).toBe(
      "Low base on a critical endpoint climbs from #3 to #1, and 2 of 2 findings on low-sensitivity endpoints drop.",
    );
    expect(rankingTakeaway(data)).toBe(
      "Ranked by the context-aware score, the first critical issue appears at position 1.0 on average instead of 3.0, and NDCG@10 rises from 0.35 to 0.45.",
    );
    const lower = {
      ...data,
      ranking: data.ranking.map((r) =>
        r.target === "mean" ? { ...r, ndcg10_context: 0.3 } : r,
      ),
    };
    expect(rankingTakeaway(lower)).toMatch(
      /NDCG@10 falls from 0\.35 to 0\.30\.$/,
    );
    expect(ndcgTakeaway(data)).toBe(
      "NDCG@10 is higher with context on 1 of 2 targets and lower on none.",
    );
  });
});

describe("classifier", () => {
  it("builds the matrix in class order", () => {
    const m = confusionMatrix(data);
    expect(m.rows.map((r) => r.truth)).toEqual([
      "LOW",
      "MEDIUM",
      "HIGH",
      "CRITICAL",
    ]);
    expect(m.rows[1].cells).toEqual([0, 1, 0, 4]);
    expect(m).toMatchObject({ total: 10, max: 4 });
  });

  it("takeaways name the commonest mistake and its direction", () => {
    expect(confusionTakeaway(data)).toBe(
      "5 of 10 endpoints are classed correctly; the commonest mistake is MEDIUM endpoints rated CRITICAL (4 of 5), which over-scores their findings rather than hiding them.",
    );
    expect(classifierTakeaway(data)).toBe(
      "On the held-out test split (n = 10) the shipped classifier is 40% accurate; the proposed keyword families raise that to 50% (macro F1 0.30 → 0.45).",
    );
  });
});

describe("the real tables", () => {
  it("have every tool, the mean ranking row and a 4x4 matrix", () => {
    expect(() => overallByTool(evaluation)).not.toThrow();
    expect(evaluation.ranking.some((r) => r.target === "mean")).toBe(true);
    expect(
      confusionMatrix(evaluation).rows.flatMap((r) => r.cells),
    ).toHaveLength(16);
  });
});
