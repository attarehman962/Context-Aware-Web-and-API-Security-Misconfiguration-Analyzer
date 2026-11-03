/**
 * Words for CAWASMA's context: endpoint sensitivity classes and response
 * body signals, as defined in docs/cvss-mapping.md (the source of the
 * CR/IR/AR mapping in config/cvss_mapping.yaml).
 */

import type { BodySignal, SensitivityClass } from "./api-types";

export const SENSITIVITY: Record<
  SensitivityClass,
  { label: string; definition: string; requirements: string }
> = {
  LOW: {
    label: "Public",
    definition: "Public, non-sensitive pages and static content.",
    requirements: "CR, IR and AR stay Not Defined: no uplift.",
  },
  MEDIUM: {
    label: "User data",
    definition: "Ordinary user data, profiles, and user-facing operations.",
    requirements: "CR, IR and AR set to Medium: normal business value.",
  },
  HIGH: {
    label: "Authentication",
    definition: "Authentication, token, session, and account-control surfaces.",
    requirements: "CR High, IR and AR Medium.",
  },
  CRITICAL: {
    label: "Admin / payment",
    definition:
      "Administrative, privileged, payment, and high-impact financial operations.",
    requirements: "CR, IR and AR all High.",
  },
};

export const SIGNALS: Record<
  BodySignal,
  { label: string; phrase: string; definition: string }
> = {
  CREDENTIALS: {
    label: "Credentials",
    phrase: "credentials",
    definition: "Passwords, session tokens, API keys, or private keys.",
  },
  PII: {
    label: "Personal data",
    phrase: "personal data",
    definition:
      "Personal data such as email addresses, phone numbers, or national IDs.",
  },
  FINANCIAL: {
    label: "Financial data",
    phrase: "financial data",
    definition: "Payment records, card data, IBANs, or financial transactions.",
  },
  INTERNAL_IP: {
    label: "Internal IP addresses",
    phrase: "internal IP addresses",
    definition: "RFC 1918, loopback, or link-local addresses.",
  },
};

/** "a", "a and b", "a, b and c". */
export function joinWords(words: string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}
