// The /evaluation page's data: Asim's final tables (eval/results/final),
// copied in by scripts/sync-eval.mjs, plus the derived views and the one-line
// takeaways. Every number on the page comes from here; nothing is hand-typed.
import raw from "@/data/evaluation.json";

export type Tool = "cawasma" | "zap" | "nuclei";
export type SensitivityClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ToolRow {
  tool: Tool;
  target: string;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  /** null when the tool reported nothing it can be scored on (tp + fp = 0). */
  precision: number | null;
  recall: number | null;
  fpr: number | null;
  scan_seconds: number;
}

export interface RankingRow {
  target: string;
  priority_items: number | null;
  critical_items: number | null;
  ndcg10_base: number;
  ndcg10_context: number;
  /** Mean rank of the first critical item; null if it was not found. */
  first_critical_base: number | null;
  first_critical_context: number | null;
}

export interface MappingRow {
  check_id: string;
  title: string;
  base_vector: string;
  base: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ClassifierRow {
  families: "shipped" | "proposed";
  split: "dev" | "test";
  n: number;
  accuracy: number;
  macro_f1: number;
  off_by_two_or_more: number;
  recall_low: number;
  recall_medium: number;
  recall_high: number;
  recall_critical: number;
}

export type ConfusionRow = { "true \\ predicted": SensitivityClass } & Record<
  SensitivityClass,
  number
>;

export interface Evaluation {
  source: string;
  tools: ToolRow[];
  ranking: RankingRow[];
  mapping: MappingRow[];
  classifier: ClassifierRow[];
  confusion: ConfusionRow[];
}

export const evaluation = raw as unknown as Evaluation;

export const TOOLS: Tool[] = ["cawasma", "zap", "nuclei"];
export const TOOL_LABEL: Record<Tool, string> = {
  cawasma: "CAWASMA",
  zap: "ZAP",
  nuclei: "Nuclei",
};
export const CLASSES: SensitivityClass[] = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

/** The pooled ("all (micro)") row is how the harness names the overall score. */
const OVERALL = /^all\b/;

export const TARGET_LABEL: Record<string, string> = {
  "juice-shop": "Juice Shop",
  dvwa: "DVWA",
  vampi: "VAmPI",
  crapi: "crAPI",
  mean: "Mean",
};
export const targetLabel = (t: string) => TARGET_LABEL[t] ?? t;

export function overallByTool(data = evaluation): Record<Tool, ToolRow> {
  return Object.fromEntries(
    TOOLS.map((tool) => {
      const row = data.tools.find(
        (r) => r.tool === tool && OVERALL.test(r.target),
      );
      if (!row) throw new Error(`tools.csv has no overall row for ${tool}`);
      return [tool, row];
    }),
  ) as Record<Tool, ToolRow>;
}

export function perTarget(data = evaluation): ToolRow[] {
  return data.tools.filter((r) => !OVERALL.test(r.target));
}

export function targets(data = evaluation): string[] {
  return [...new Set(perTarget(data).map((r) => r.target))];
}

const fmt = (n: number, digits = 2) => n.toFixed(digits);
const times = (a: number, b: number) => `${Math.round(a / b)}×`;

export function toolsTakeaway(data = evaluation): string {
  const o = overallByTool(data);
  const c = o.cawasma;
  return (
    `CAWASMA finds ${c.tp} of ${c.tp + c.fn} expected issues (recall ` +
    `${fmt(c.recall ?? 0)}), against ${fmt(o.zap.recall ?? 0)} for ZAP and ` +
    `${fmt(o.nuclei.recall ?? 0)} for Nuclei, at the cost of ${c.fp} false ` +
    `positive${c.fp === 1 ? "" : "s"} (precision ${fmt(c.precision ?? 0)}).`
  );
}

export function timeTakeaway(data = evaluation): string {
  const o = overallByTool(data);
  const c = o.cawasma.scan_seconds;
  return (
    `A CAWASMA scan takes ${c} s per target on average: ` +
    `${times(o.zap.scan_seconds, c)} faster than ZAP (${o.zap.scan_seconds} s) ` +
    `and ${times(o.nuclei.scan_seconds, c)} faster than Nuclei (${o.nuclei.scan_seconds} s).`
  );
}

export function rankingRows(data = evaluation) {
  return {
    targets: data.ranking.filter((r) => r.target !== "mean"),
    mean: data.ranking.find((r) => r.target === "mean"),
  };
}

export function rankingTakeaway(data = evaluation): string {
  const { mean } = rankingRows(data);
  if (!mean) return "";
  return (
    `Ranked by the context-aware score, the first critical issue appears at ` +
    `position ${fmt(mean.first_critical_context ?? 0, 1)} on average instead of ` +
    `${fmt(mean.first_critical_base ?? 0, 1)}, and NDCG@10 rises from ` +
    `${fmt(mean.ndcg10_base)} to ${fmt(mean.ndcg10_context)}.`
  );
}

export function ndcgTakeaway(data = evaluation): string {
  const { targets: rows } = rankingRows(data);
  const higher = rows.filter((r) => r.ndcg10_context > r.ndcg10_base).length;
  const lower = rows.filter((r) => r.ndcg10_context < r.ndcg10_base).length;
  return (
    `NDCG@10 is higher with context on ${higher} of ${rows.length} targets ` +
    `and lower on ${lower === 0 ? "none" : lower}.`
  );
}

export interface RankedFinding {
  id: string;
  checkId: string;
  title: string;
  endpointClass: SensitivityClass;
  base: number;
  final: number;
  baseRank: number;
  finalRank: number;
  /** Places gained by context-aware scoring (negative: dropped). */
  moved: number;
}

/** Competition ranking ("1, 1, 3"): ties share a place, so a tie never
 * looks like movement. */
function competitionRank(values: number[], v: number): number {
  return 1 + values.filter((x) => x > v).length;
}

/**
 * The before/after illustration: every check in mapping.csv, once on a LOW
 * and once on a CRITICAL endpoint, ranked by base score and by the
 * context-aware (environmental) score.
 */
export function rankedFindings(
  data = evaluation,
  classes: SensitivityClass[] = ["LOW", "CRITICAL"],
): RankedFinding[] {
  const items = data.mapping.flatMap((m) =>
    classes.map((cls) => ({
      id: `${m.check_id}@${cls}`,
      checkId: m.check_id,
      title: m.title,
      endpointClass: cls,
      base: m.base,
      final: m[cls.toLowerCase() as Lowercase<SensitivityClass>],
    })),
  );
  const bases = items.map((i) => i.base);
  const finals = items.map((i) => i.final);
  return items.map((i) => {
    const baseRank = competitionRank(bases, i.base);
    const finalRank = competitionRank(finals, i.final);
    return { ...i, baseRank, finalRank, moved: baseRank - finalRank };
  });
}

export function movementTakeaway(findings = rankedFindings()): string {
  const best = [...findings].sort((a, b) => b.moved - a.moved)[0];
  if (!best || best.moved <= 0) return "No finding changes place.";
  const low = findings.filter((f) => f.endpointClass === "LOW");
  const lowDropped = low.filter((f) => f.moved < 0).length;
  return (
    `${best.title} on a ${best.endpointClass.toLowerCase()} endpoint climbs ` +
    `from #${best.baseRank} to #${best.finalRank}, and ${lowDropped} of ` +
    `${low.length} findings on low-sensitivity endpoints drop.`
  );
}

export function classifierRows(data = evaluation) {
  const get = (
    families: ClassifierRow["families"],
    split: ClassifierRow["split"],
  ) =>
    data.classifier.find((r) => r.families === families && r.split === split);
  return {
    shippedTest: get("shipped", "test"),
    proposedTest: get("proposed", "test"),
    all: data.classifier,
  };
}

export function classifierTakeaway(data = evaluation): string {
  const { shippedTest: s, proposedTest: p } = classifierRows(data);
  if (!s || !p) return "";
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  return (
    `On the held-out test split (n = ${s.n}) the shipped classifier is ` +
    `${pct(s.accuracy)} accurate; the proposed keyword families raise that to ` +
    `${pct(p.accuracy)} (macro F1 ${fmt(s.macro_f1)} → ${fmt(p.macro_f1)}).`
  );
}

export function confusionMatrix(data = evaluation) {
  const rows = CLASSES.map((truth) => {
    const row = data.confusion.find((r) => r["true \\ predicted"] === truth);
    return { truth, cells: CLASSES.map((p) => row?.[p] ?? 0) };
  });
  const total = rows.reduce(
    (s, r) => s + r.cells.reduce((a, b) => a + b, 0),
    0,
  );
  const max = Math.max(...rows.flatMap((r) => r.cells));
  return { rows, total, max };
}

export function confusionTakeaway(data = evaluation): string {
  const { rows } = confusionMatrix(data);
  let worst = { truth: "", predicted: "", n: 0, of: 0 };
  for (const r of rows) {
    const of = r.cells.reduce((a, b) => a + b, 0);
    r.cells.forEach((n, i) => {
      if (CLASSES[i] !== r.truth && n > worst.n)
        worst = { truth: r.truth, predicted: CLASSES[i], n, of };
    });
  }
  const correct = rows.reduce((s, r, i) => s + r.cells[i], 0);
  const total = rows.reduce(
    (s, r) => s + r.cells.reduce((a, b) => a + b, 0),
    0,
  );
  return (
    `${correct} of ${total} endpoints are classed correctly; the commonest ` +
    `mistake is ${worst.truth} endpoints rated ${worst.predicted} ` +
    `(${worst.n} of ${worst.of}), which ${
      CLASSES.indexOf(worst.predicted as SensitivityClass) >
      CLASSES.indexOf(worst.truth as SensitivityClass)
        ? "over-scores their findings rather than hiding them"
        : "under-scores their findings"
    }.`
  );
}
