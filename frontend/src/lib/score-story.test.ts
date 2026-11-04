import { describe, expect, it } from "vitest";

import { resultsDone } from "@/mocks/fixtures";

import type { Finding } from "./api-types";
import { parseScoreReasons, scoreStory } from "./score-story";

const byCheck = (checkId: string) =>
  resultsDone.findings.find((f) => f.check_id === checkId)!;

/** HDR-001 on a login page whose response holds a token (base 5.3 -> 7.1). */
const hstsOnLogin: Finding = {
  ...byCheck("HDR-001"),
  final_score: 7.1,
  final_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N/CR:H/IR:H/AR:M",
  score_reasons: [
    "sensitivity:HIGH",
    "signal:CREDENTIALS",
    "CR:H<-sensitivity:HIGH+signal:CREDENTIALS",
    "IR:H<-signal:CREDENTIALS",
    "AR:M<-sensitivity:HIGH+signal:CREDENTIALS",
    "base:5.3",
    "environmental:7.1",
  ],
  severity_bucket: "HIGH",
  sensitivity_class: "HIGH",
  body_signals: ["CREDENTIALS"],
};

describe("scoreStory: CVSS environmental scoring", () => {
  it("names the class and the signal that raised the score", () => {
    const story = scoreStory(hstsOnLogin);
    expect(story.sentence).toBe(
      "Raised from 5.3 to 7.1 because the endpoint is classified as Authentication and the response contains credentials.",
    );
    expect(story).toMatchObject({
      direction: "up",
      method: "environmental",
      sensitivity: "HIGH",
      signals: ["CREDENTIALS"],
      requirements: { CR: "H", IR: "H", AR: "M" },
    });
  });

  it("names the class alone when no signal set a requirement", () => {
    expect(scoreStory(byCheck("CKI-003")).sentence).toBe(
      "Raised from 7.1 to 8.6 because the endpoint is classified as Admin / payment.",
    );
  });

  it("lists several signals", () => {
    expect(scoreStory(byCheck("HDR-002")).sentence).toBe(
      "Raised from 5.4 to 6.4 because the endpoint is classified as Admin / payment and the response contains financial data and personal data.",
    );
  });

  it("names a signal alone when the class added nothing", () => {
    const story = scoreStory({
      ...hstsOnLogin,
      sensitivity_class: "LOW",
      score_reasons: [
        "sensitivity:LOW",
        "signal:PII",
        "CR:H<-signal:PII",
        "IR:M<-signal:PII",
        "base:5.3",
        "environmental:7.1",
      ],
    });
    expect(story.sentence).toBe(
      "Raised from 5.3 to 7.1 because the response contains personal data.",
    );
  });

  it("explains an unchanged score on a public page", () => {
    expect(scoreStory(byCheck("HDR-001")).sentence).toBe(
      "Unchanged at 5.3: the endpoint is public and the response shows no sensitive data, so context adds nothing.",
    );
  });

  it("explains why Medium requirements leave the score as it is", () => {
    expect(scoreStory(byCheck("INF-007")).sentence).toBe(
      "Unchanged at 5.3: the endpoint is classified as User data, and the response contains internal IP addresses, but Medium security requirements leave this check's CVSS score as it is.",
    );
  });

  it("says how a score was raised even without readable reasons", () => {
    expect(
      scoreStory({
        ...hstsOnLogin,
        score_reasons: ["base:5.3", "environmental:7.1"],
      }).sentence,
    ).toBe("Raised from 5.3 to 7.1 by the CVSS environmental metrics.");
  });
});

describe("scoreStory: interim formula", () => {
  it("names the context and says it is the interim formula", () => {
    const story = scoreStory(byCheck("API-003"));
    expect(story.sentence).toBe(
      "Raised from 7.5 to 10.0 because the endpoint is classified as Authentication and the response contains personal data (CAWASMA's interim formula; this check is not yet scored with CVSS environmental metrics).",
    );
    expect(story.method).toBe("interim");
  });

  it("explains a lowered score", () => {
    expect(scoreStory(byCheck("HDR-012")).sentence).toMatch(
      /^Lowered from 3\.1 to 0\.0 because the endpoint is classified as Public \(CAWASMA's interim formula/,
    );
  });

  it("explains a host-level finding", () => {
    expect(scoreStory(byCheck("TLS-001")).sentence).toBe(
      "Unchanged at 7.4: a host-level finding has no endpoint context to apply.",
    );
  });
});

describe("parseScoreReasons", () => {
  it("reads which source set each requirement", () => {
    expect(parseScoreReasons(byCheck("HDR-002").score_reasons)).toEqual({
      requirements: { CR: "H", IR: "H", AR: "H" },
      sensitivity: "CRITICAL",
      signals: ["FINANCIAL", "PII"],
      declaredClass: "CRITICAL",
    });
  });

  it("ignores reasons it does not know", () => {
    expect(
      parseScoreReasons(["weird", "CR:Z<-x", "signal:NOPE", "sensitivity:ODD"]),
    ).toEqual({
      requirements: {},
      sensitivity: null,
      signals: [],
      declaredClass: null,
    });
  });
});
