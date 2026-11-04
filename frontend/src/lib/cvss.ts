/**
 * CVSS v3.1 vector strings: parsing into metrics, human-readable names, and
 * the base-vs-context comparison shown in the finding detail. Scores are not
 * computed here; the API's base_score / final_score are authoritative, and
 * the FIRST calculator link lets anyone re-check them.
 *
 * Reference: CVSS v3.1 Specification, section 6 (Vector String),
 * https://www.first.org/cvss/v3.1/specification-document
 */

export type MetricGroup = "base" | "temporal" | "environmental";

interface MetricDef {
  name: string;
  group: MetricGroup;
  values: Record<string, string>;
}

const IMPACT = { H: "High", L: "Low", N: "None" };
const REQUIREMENT = {
  X: "Not Defined",
  L: "Low",
  M: "Medium",
  H: "High",
};
const notDefined = <T extends Record<string, string>>(values: T) => ({
  X: "Not Defined",
  ...values,
});

/** Every v3.1 metric, in specification order. */
export const METRICS: Record<string, MetricDef> = {
  AV: {
    name: "Attack Vector",
    group: "base",
    values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  },
  AC: {
    name: "Attack Complexity",
    group: "base",
    values: { L: "Low", H: "High" },
  },
  PR: {
    name: "Privileges Required",
    group: "base",
    values: { N: "None", L: "Low", H: "High" },
  },
  UI: {
    name: "User Interaction",
    group: "base",
    values: { N: "None", R: "Required" },
  },
  S: { name: "Scope", group: "base", values: { U: "Unchanged", C: "Changed" } },
  C: { name: "Confidentiality", group: "base", values: IMPACT },
  I: { name: "Integrity", group: "base", values: IMPACT },
  A: { name: "Availability", group: "base", values: IMPACT },
  E: {
    name: "Exploit Code Maturity",
    group: "temporal",
    values: notDefined({
      U: "Unproven",
      P: "Proof-of-Concept",
      F: "Functional",
      H: "High",
    }),
  },
  RL: {
    name: "Remediation Level",
    group: "temporal",
    values: notDefined({
      O: "Official Fix",
      T: "Temporary Fix",
      W: "Workaround",
      U: "Unavailable",
    }),
  },
  RC: {
    name: "Report Confidence",
    group: "temporal",
    values: notDefined({ U: "Unknown", R: "Reasonable", C: "Confirmed" }),
  },
  CR: {
    name: "Confidentiality Requirement",
    group: "environmental",
    values: REQUIREMENT,
  },
  IR: {
    name: "Integrity Requirement",
    group: "environmental",
    values: REQUIREMENT,
  },
  AR: {
    name: "Availability Requirement",
    group: "environmental",
    values: REQUIREMENT,
  },
  MAV: {
    name: "Modified Attack Vector",
    group: "environmental",
    values: notDefined({
      N: "Network",
      A: "Adjacent",
      L: "Local",
      P: "Physical",
    }),
  },
  MAC: {
    name: "Modified Attack Complexity",
    group: "environmental",
    values: notDefined({ L: "Low", H: "High" }),
  },
  MPR: {
    name: "Modified Privileges Required",
    group: "environmental",
    values: notDefined({ N: "None", L: "Low", H: "High" }),
  },
  MUI: {
    name: "Modified User Interaction",
    group: "environmental",
    values: notDefined({ N: "None", R: "Required" }),
  },
  MS: {
    name: "Modified Scope",
    group: "environmental",
    values: notDefined({ U: "Unchanged", C: "Changed" }),
  },
  MC: {
    name: "Modified Confidentiality",
    group: "environmental",
    values: notDefined(IMPACT),
  },
  MI: {
    name: "Modified Integrity",
    group: "environmental",
    values: notDefined(IMPACT),
  },
  MA: {
    name: "Modified Availability",
    group: "environmental",
    values: notDefined(IMPACT),
  },
};

export const BASE_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
const PREFIX = "CVSS:3.1/";

export type ParsedVector =
  | { ok: true; vector: string; metrics: Record<string, string> }
  | { ok: false; vector: string; error: string };

/**
 * Parses a CVSS v3.1 vector. Rejects anything the specification does not
 * allow: another version, unknown or repeated metrics, invalid values and a
 * missing base metric. The error says what is wrong, for display.
 */
export function parseVector(input: string | null | undefined): ParsedVector {
  const vector = (input ?? "").trim();
  const fail = (error: string): ParsedVector => ({ ok: false, vector, error });

  if (!vector) return fail("The vector is empty.");
  if (!vector.startsWith(PREFIX)) {
    const version = /^CVSS:(\d+(?:\.\d+)?)\//.exec(vector)?.[1];
    return fail(
      version
        ? `Only CVSS v3.1 vectors are supported (this one is CVSS ${version}).`
        : 'A CVSS v3.1 vector starts with "CVSS:3.1/".',
    );
  }

  const metrics: Record<string, string> = {};
  for (const part of vector.slice(PREFIX.length).split("/")) {
    const match = /^([A-Z]+):([A-Z])$/.exec(part);
    if (!match)
      return fail(`"${part}" is not a metric of the form Name:Value.`);
    const [, code, value] = match;
    const def = METRICS[code];
    if (!def) return fail(`"${code}" is not a CVSS v3.1 metric.`);
    if (code in metrics) return fail(`"${code}" appears more than once.`);
    if (!(value in def.values)) {
      return fail(
        `"${value}" is not a valid value for ${def.name} (${code}); expected one of ${Object.keys(def.values).join(", ")}.`,
      );
    }
    metrics[code] = value;
  }

  const missing = BASE_METRICS.filter((code) => !(code in metrics));
  if (missing.length > 0) {
    return fail(
      `Base metric${missing.length > 1 ? "s" : ""} missing: ${missing.join(", ")}.`,
    );
  }
  return { ok: true, vector, metrics };
}

export interface MetricRow {
  code: string;
  name: string;
  group: MetricGroup;
  /** Value label in the base vector ("High"), or null when absent there. */
  base: string | null;
  /** Value label in the context-aware vector, or null when absent there. */
  context: string | null;
  /** The context vector sets this metric (not Not Defined) beyond the base. */
  changed: boolean;
}

/**
 * Rows comparing the official base vector with the context-aware vector:
 * all eight base metrics, then every temporal/environmental metric either
 * vector sets. An environmental metric counts as changed when the context
 * vector gives it a value other than Not Defined (X).
 */
export function compareVectors(
  base: Record<string, string>,
  context: Record<string, string> | null,
): MetricRow[] {
  const codes = Object.keys(METRICS).filter(
    (code) =>
      BASE_METRICS.includes(code) ||
      code in base ||
      (context !== null && code in context),
  );
  return codes.map((code) => {
    const def = METRICS[code];
    const b = base[code];
    const c = context?.[code];
    return {
      code,
      name: def.name,
      group: def.group,
      base: b ? def.values[b] : null,
      context: c ? def.values[c] : null,
      changed: def.group !== "base" && c !== undefined && c !== "X" && c !== b,
    };
  });
}

/** The FIRST CVSS v3.1 calculator, pre-filled with the vector. */
export function firstCalculatorUrl(vector: string): string {
  return `https://www.first.org/cvss/calculator/3.1#${vector}`;
}
