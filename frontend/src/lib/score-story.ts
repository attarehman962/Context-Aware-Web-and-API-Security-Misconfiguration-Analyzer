/**
 * The one-line "score story" of a finding: how context moved its score from
 * the official CVSS base score to CAWASMA's context-aware score, and why.
 *
 * For checks scored with CVSS environmental metrics (`final_vector` set) the
 * reasons come from `score_reasons`, which the backend writes as e.g.
 *   ["sensitivity:HIGH", "signal:CREDENTIALS",
 *    "CR:H<-sensitivity:HIGH+signal:CREDENTIALS", ..., "base:5.3",
 *    "environmental:7.1"]
 * Only the class and signals that set a requirement (`X:Y<-sources`) are
 * named. Checks still on the interim formula (`final_vector` null) have no
 * reasons, so their endpoint class and signals are named instead.
 */

import type { BodySignal, Finding, SensitivityClass } from "./api-types";
import { SENSITIVITY, SIGNALS, joinWords } from "./context";

export type ScoreDirection = "up" | "down" | "same";

export interface ScoreStory {
  sentence: string;
  direction: ScoreDirection;
  /** "environmental": CVSS v3.1 CR/IR/AR; "interim": the legacy formula. */
  method: "environmental" | "interim";
  /** The endpoint class that drove the change, if any. */
  sensitivity: SensitivityClass | null;
  /** The body signals that drove the change. */
  signals: BodySignal[];
  /** Requirements set by context, e.g. { CR: "H", IR: "M" }. */
  requirements: Record<string, string>;
}

type StoryInput = Pick<
  Finding,
  | "base_score"
  | "final_score"
  | "final_vector"
  | "score_reasons"
  | "sensitivity_class"
  | "body_signals"
>;

const CLASSES = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/** Which class/signals set each requirement, from `score_reasons`. */
export function parseScoreReasons(reasons: string[]) {
  const requirements: Record<string, string> = {};
  let sensitivity: SensitivityClass | null = null;
  const signals = new Set<BodySignal>();
  let declaredClass: SensitivityClass | null = null;

  for (const reason of reasons) {
    const requirement = /^(CR|IR|AR):([XLMH])<-(.+)$/.exec(reason);
    if (requirement) {
      const [, metric, value, sources] = requirement;
      requirements[metric] = value;
      for (const source of sources.split("+")) {
        const [kind, name] = source.split(":");
        if (kind === "sensitivity" && CLASSES.has(name)) {
          sensitivity = name as SensitivityClass;
        } else if (kind === "signal" && name in SIGNALS) {
          signals.add(name as BodySignal);
        }
      }
      continue;
    }
    const declared = /^sensitivity:(\w+)$/.exec(reason);
    if (declared && CLASSES.has(declared[1])) {
      declaredClass = declared[1] as SensitivityClass;
    }
  }
  return { requirements, sensitivity, signals: [...signals], declaredClass };
}

const fmt = (score: number) => score.toFixed(1);

export function scoreStory(finding: StoryInput): ScoreStory {
  const base = fmt(finding.base_score);
  const final = fmt(finding.final_score);
  const direction: ScoreDirection =
    final === base
      ? "same"
      : finding.final_score > finding.base_score
        ? "up"
        : "down";

  if (!finding.final_vector) return interimStory(finding, direction);

  const parsed = parseScoreReasons(finding.score_reasons);
  const cls =
    parsed.sensitivity ?? parsed.declaredClass ?? finding.sensitivity_class;
  const story = {
    direction,
    method: "environmental" as const,
    sensitivity: parsed.sensitivity,
    signals: parsed.signals,
    requirements: parsed.requirements,
  };

  if (direction === "same") {
    let why: string;
    if (cls === null) {
      why = "a host-level finding has no endpoint context to apply";
    } else if (cls === "LOW" && parsed.signals.length === 0) {
      why =
        "the endpoint is public and the response shows no sensitive data, so context adds nothing";
    } else {
      why = `the endpoint is classified as ${SENSITIVITY[cls].label}${signalClause(parsed.signals, ", and")}, but ${requirementWords(parsed.requirements)} leave this check's CVSS score as it is`;
    }
    return { ...story, sentence: `Unchanged at ${base}: ${why}.` };
  }

  const causes = [
    parsed.sensitivity && parsed.sensitivity !== "LOW"
      ? `the endpoint is classified as ${SENSITIVITY[parsed.sensitivity].label}`
      : null,
    parsed.signals.length > 0
      ? `the response contains ${joinWords(parsed.signals.map((s) => SIGNALS[s].phrase))}`
      : null,
  ].filter(Boolean);
  const verb = direction === "up" ? "Raised" : "Lowered";
  const because =
    causes.length > 0
      ? ` because ${causes.join(" and ")}`
      : " by the CVSS environmental metrics";
  return { ...story, sentence: `${verb} from ${base} to ${final}${because}.` };
}

function interimStory(
  finding: StoryInput,
  direction: ScoreDirection,
): ScoreStory {
  const base = fmt(finding.base_score);
  const final = fmt(finding.final_score);
  const cls = finding.sensitivity_class;
  const signals = finding.body_signals;
  const story = {
    direction,
    method: "interim" as const,
    sensitivity: cls,
    signals,
    requirements: {},
  };
  const note =
    " (CAWASMA's interim formula; this check is not yet scored with CVSS environmental metrics)";

  if (cls === null) {
    return {
      ...story,
      sentence:
        direction === "same"
          ? `Unchanged at ${base}: a host-level finding has no endpoint context to apply.`
          : `${direction === "up" ? "Raised" : "Lowered"} from ${base} to ${final}${note}.`,
    };
  }
  const context = `the endpoint is classified as ${SENSITIVITY[cls].label}${signalClause(signals, " and")}`;
  if (direction === "same") {
    return { ...story, sentence: `Unchanged at ${base}: ${context}${note}.` };
  }
  const verb = direction === "up" ? "Raised" : "Lowered";
  return {
    ...story,
    sentence: `${verb} from ${base} to ${final} because ${context}${note}.`,
  };
}

function signalClause(signals: BodySignal[], joiner: string): string {
  if (signals.length === 0) return "";
  return `${joiner} the response contains ${joinWords(signals.map((s) => SIGNALS[s].phrase))}`;
}

const LEVEL: Record<string, string> = {
  X: "Not Defined",
  L: "Low",
  M: "Medium",
  H: "High",
};

/** "Medium security requirements" / "the CR:H, IR:M security requirements". */
function requirementWords(requirements: Record<string, string>): string {
  const values = Object.values(requirements);
  if (values.length === 0) return "the security requirements";
  if (values.every((v) => v === values[0])) {
    return `${LEVEL[values[0]]} security requirements`;
  }
  return `the ${Object.entries(requirements)
    .map(([k, v]) => `${k}:${v}`)
    .join(", ")} security requirements`;
}
