import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  EVAL_DIR,
  OUT_FILE,
  buildEvaluation,
  parseCsv,
  readTable,
  serialise,
} from "../../scripts/sync-eval.mjs";

describe("evaluation.json", () => {
  it.runIf(existsSync(EVAL_DIR))(
    "matches eval/results/final (run npm run sync:eval)",
    () => {
      expect(readFileSync(OUT_FILE, "utf8")).toBe(serialise(buildEvaluation()));
    },
  );
});

describe("parseCsv", () => {
  it("handles quotes, doubled quotes, CRLF and empty cells", () => {
    expect(parseCsv('a,b,c\r\n"x, y","say ""hi""",\n1,,3\n')).toEqual([
      ["a", "b", "c"],
      ["x, y", 'say "hi"', ""],
      ["1", "", "3"],
    ]);
  });
});

describe("readTable", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "cawasma-eval-"));

  it("types numbers and empty cells", () => {
    writeFileSync(
      path.join(dir, "ranking.csv"),
      "target,priority_items,critical_items,ndcg10_base,ndcg10_context,first_critical_base,first_critical_context\n" +
        "juice-shop,9,6,0.0,0.0,,\n",
    );
    expect(readTable("ranking", dir)).toEqual([
      {
        target: "juice-shop",
        priority_items: 9,
        critical_items: 6,
        ndcg10_base: 0,
        ndcg10_context: 0,
        first_critical_base: null,
        first_critical_context: null,
      },
    ]);
  });

  it("stops when a column changes instead of drawing a wrong chart", () => {
    writeFileSync(
      path.join(dir, "tools.csv"),
      "tool,target,tp\ncawasma,dvwa,1\n",
    );
    expect(() => readTable("tools", dir)).toThrow(/tools\.csv columns changed/);
  });
});
