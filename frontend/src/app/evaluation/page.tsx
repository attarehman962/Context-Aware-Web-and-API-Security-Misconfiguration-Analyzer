import type { Metadata } from "next";

import { ChartCard, DataTable } from "@/components/evaluation/chart-card";
import { ConfusionMatrix } from "@/components/evaluation/confusion-matrix";
import {
  GroupedBars,
  type BarSeries,
} from "@/components/evaluation/grouped-bars";
import { RankingCompare } from "@/components/evaluation/ranking-compare";
import {
  CLASSES,
  TOOL_LABEL,
  TOOLS,
  classifierRows,
  classifierTakeaway,
  confusionMatrix,
  confusionTakeaway,
  evaluation,
  movementTakeaway,
  ndcgTakeaway,
  overallByTool,
  perTarget,
  rankedFindings,
  rankingRows,
  rankingTakeaway,
  targetLabel,
  targets,
  timeTakeaway,
  toolsTakeaway,
} from "@/lib/evaluation";

export const metadata: Metadata = { title: "Evaluation · CAWASMA" };

const TOOL_SERIES: BarSeries[] = TOOLS.map((t, i) => ({
  key: t,
  label: TOOL_LABEL[t],
  color: `var(--viz-${i + 1})`,
}));
const BEFORE_AFTER: BarSeries[] = [
  { key: "base", label: "Base score", color: "var(--viz-neutral)" },
  { key: "context", label: "Context-aware score", color: "var(--viz-1)" },
];
const num = (v: number | null, d = 2) => (v == null ? "–" : v.toFixed(d));

function Section({
  id,
  title,
  intro,
  children,
}: {
  id: string;
  title: string;
  intro: string;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2
          id={id}
          className="font-heading text-xl font-semibold tracking-tight"
        >
          {title}
        </h2>
        <p className="max-w-prose text-sm text-muted-foreground">{intro}</p>
      </div>
      {children}
    </section>
  );
}

export default function EvaluationPage() {
  const overall = overallByTool();
  const rows = perTarget();
  const { targets: rankTargets, mean } = rankingRows();
  const ranked = rankedFindings();
  const { all: classifier } = classifierRows();
  const confusion = confusionMatrix();

  return (
    <>
      <div className="flex flex-col gap-2">
        <h1 className="font-heading text-2xl font-semibold tracking-tight">
          Evaluation
        </h1>
        <p className="max-w-prose text-sm text-muted-foreground">
          Results of the final evaluation on four deliberately vulnerable apps
          (Juice Shop, DVWA, VAmPI and crAPI), from{" "}
          <code className="font-mono text-xs">{evaluation.source}</code>. Every
          number here is read from those CSV files at build time.
        </p>
      </div>

      <Section
        id="tools"
        title="CAWASMA vs ZAP vs Nuclei"
        intro="Each tool is scored only on the checks it can detect, against hand-written ground truth. Overall figures pool every target (micro average)."
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <ChartCard
            id="tool-quality"
            title="Detection quality, all targets"
            takeaway={toolsTakeaway()}
            note="Precision and recall: higher is better. False-positive rate: lower is better."
            table={
              <DataTable
                caption="Detection quality per tool and target"
                columns={[
                  "Tool · target",
                  "TP",
                  "FP",
                  "FN",
                  "TN",
                  "Precision",
                  "Recall",
                  "FPR",
                ]}
                rows={[...rows, ...TOOLS.map((t) => overall[t])].map((r) => [
                  `${TOOL_LABEL[r.tool]} · ${targetLabel(r.target)}`,
                  r.tp,
                  r.fp,
                  r.fn,
                  r.tn,
                  num(r.precision),
                  num(r.recall),
                  num(r.fpr),
                ])}
              />
            }
          >
            <GroupedBars
              label="Precision, recall and false-positive rate per tool"
              series={TOOL_SERIES}
              max={1}
              groups={(
                [
                  ["Precision", "precision"],
                  ["Recall", "recall"],
                  ["False-positive rate", "fpr"],
                ] as const
              ).map(([label, key]) => ({
                label,
                values: Object.fromEntries(
                  TOOLS.map((t) => [t, overall[t][key]]),
                ),
              }))}
            />
          </ChartCard>

          <ChartCard
            id="tool-time"
            title="Scan time per target"
            takeaway={timeTakeaway()}
            note="Seconds per scan: lower is better."
            table={
              <DataTable
                caption="Scan time in seconds per tool and target"
                columns={["Target", ...TOOLS.map((t) => TOOL_LABEL[t])]}
                rows={[...targets(), "all (micro)"].map((target) => [
                  target === "all (micro)" ? "Mean" : targetLabel(target),
                  ...TOOLS.map(
                    (t) =>
                      (target === "all (micro)"
                        ? overall[t]
                        : rows.find((r) => r.tool === t && r.target === target)
                      )?.scan_seconds ?? "–",
                  ),
                ])}
              />
            }
          >
            <GroupedBars
              label="Scan time in seconds per tool and target"
              series={TOOL_SERIES}
              max={Math.max(...rows.map((r) => r.scan_seconds))}
              format={(v) => `${v.toFixed(1)} s`}
              groups={targets().map((target) => ({
                label: targetLabel(target),
                values: Object.fromEntries(
                  TOOLS.map((t) => [
                    t,
                    rows.find((r) => r.tool === t && r.target === target)
                      ?.scan_seconds ?? null,
                  ]),
                ),
              }))}
            />
          </ChartCard>
        </div>
      </Section>

      <Section
        id="ranking"
        title="Before and after: base score vs context-aware score"
        intro="The same findings ranked two ways: by the official CVSS v3.1 base score, and by CAWASMA's context-aware (environmental) score. A good ranking puts the issues a human would fix first at the top."
      >
        <ChartCard
          id="ranking-movement"
          title="The same findings, ranked both ways"
          takeaway={movementTakeaway(ranked)}
          note="Each check from the mapping table, once on a low-sensitivity and once on a critical endpoint. Equal scores share a place, so ties never count as movement."
          table={
            <DataTable
              caption="Findings ranked by base score and by context-aware score"
              columns={[
                "Finding",
                "Base",
                "Rank",
                "Context-aware",
                "Rank",
                "Moved",
              ]}
              rows={ranked.map((f) => [
                `${f.checkId} on a ${f.endpointClass.toLowerCase()} endpoint`,
                f.base.toFixed(1),
                f.baseRank,
                f.final.toFixed(1),
                f.finalRank,
                f.moved > 0 ? `+${f.moved}` : f.moved,
              ])}
            />
          }
        >
          <RankingCompare findings={ranked} />
        </ChartCard>

        <div className="grid gap-4 lg:grid-cols-2">
          <ChartCard
            id="ranking-first-critical"
            title="Where the first critical issue appears"
            takeaway={rankingTakeaway()}
            note="Mean rank over 1000 random tie-breaks; lower is better. Four targets with 6-10 priority items each: descriptive, no significance claimed."
            table={
              <DataTable
                caption="Ranking quality per target"
                columns={[
                  "Target",
                  "First critical (base)",
                  "First critical (context)",
                  "NDCG@10 (base)",
                  "NDCG@10 (context)",
                ]}
                rows={[...rankTargets, ...(mean ? [mean] : [])].map((r) => [
                  targetLabel(r.target),
                  num(r.first_critical_base, 1),
                  num(r.first_critical_context, 1),
                  num(r.ndcg10_base, 3),
                  num(r.ndcg10_context, 3),
                ])}
              />
            }
          >
            <GroupedBars
              label="Rank of the first critical finding per target"
              series={BEFORE_AFTER}
              max={Math.max(
                ...rankTargets.flatMap((r) => [
                  r.first_critical_base ?? 0,
                  r.first_critical_context ?? 0,
                ]),
              )}
              format={(v) => `#${v.toFixed(1)}`}
              missing="not in the ranking"
              groups={rankTargets.map((r) => ({
                label: targetLabel(r.target),
                values: {
                  base: r.first_critical_base,
                  context: r.first_critical_context,
                },
              }))}
            />
          </ChartCard>

          <ChartCard
            id="ranking-ndcg"
            title="Ranking quality (NDCG@10)"
            takeaway={ndcgTakeaway()}
            note="1.0 is the hand-written priority order exactly; higher is better."
          >
            <GroupedBars
              label="NDCG at 10 per target"
              series={BEFORE_AFTER}
              max={1}
              format={(v) => v.toFixed(3)}
              groups={rankTargets.map((r) => ({
                label: targetLabel(r.target),
                values: { base: r.ndcg10_base, context: r.ndcg10_context },
              }))}
            />
          </ChartCard>
        </div>
      </Section>

      <Section
        id="classifier"
        title="Endpoint sensitivity classifier"
        intro="How often the URL-path classifier gives an endpoint the same sensitivity class as the hand label. The shipped classifier is what scans use today; the proposed keyword families were tuned on the dev split only and reported once on test."
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <ChartCard
            id="classifier-accuracy"
            title="Accuracy and macro F1"
            takeaway={classifierTakeaway()}
            table={
              <DataTable
                caption="Classifier accuracy and recall per class"
                columns={[
                  "Classifier · split",
                  "n",
                  "Accuracy",
                  "Macro F1",
                  ...CLASSES.map((c) => `Recall ${c}`),
                ]}
                rows={classifier.map((r) => [
                  `${r.families} · ${r.split}`,
                  r.n,
                  num(r.accuracy, 3),
                  num(r.macro_f1, 3),
                  num(r.recall_low, 3),
                  num(r.recall_medium, 3),
                  num(r.recall_high, 3),
                  num(r.recall_critical, 3),
                ])}
              />
            }
          >
            <GroupedBars
              label="Classifier accuracy and macro F1"
              series={[
                {
                  key: "shipped",
                  label: "Shipped",
                  color: "var(--viz-neutral)",
                },
                { key: "proposed", label: "Proposed", color: "var(--viz-1)" },
              ]}
              max={1}
              groups={(["test", "dev"] as const).flatMap((split) =>
                (
                  [
                    ["Accuracy", "accuracy"],
                    ["Macro F1", "macro_f1"],
                  ] as const
                ).map(([label, key]) => ({
                  label: `${label} (${split})`,
                  values: Object.fromEntries(
                    (["shipped", "proposed"] as const).map((f) => [
                      f,
                      classifier.find(
                        (r) => r.families === f && r.split === split,
                      )?.[key] ?? null,
                    ]),
                  ),
                })),
              )}
            />
          </ChartCard>

          <ChartCard
            id="classifier-confusion"
            title="Confusion matrix, shipped classifier (test split)"
            takeaway={confusionTakeaway()}
            note="Rows: hand label; columns: the classifier. Outlined cells are correct."
          >
            <ConfusionMatrix rows={confusion.rows} max={confusion.max} />
          </ChartCard>
        </div>
      </Section>
    </>
  );
}
