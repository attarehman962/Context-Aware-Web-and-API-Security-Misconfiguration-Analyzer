/**
 * Mock data for MSW. The JSON files in fixtures/ are copies of
 * docs/examples/ (what the backend's MOCK_API mode returns);
 * fixtures.test.ts fails if they drift. Refresh them by copying again.
 */

import type {
  Finding,
  ScanList,
  ScanResults,
  ScanStatus,
} from "@/lib/api-types";

import errorJson from "./fixtures/error.json";
import resultsDoneJson from "./fixtures/results-done.json";
import resultsFailedJson from "./fixtures/results-failed.json";
import resultsRunningJson from "./fixtures/results-running.json";
import scanQueuedJson from "./fixtures/scan-status-queued.json";
import scansJson from "./fixtures/scans.json";

export const DONE_SCAN_ID = "11111111-1111-4111-8111-111111111111";
export const RUNNING_SCAN_ID = "22222222-2222-4222-8222-222222222222";
export const QUEUED_SCAN_ID = "33333333-3333-4333-8333-333333333333";
export const FAILED_SCAN_ID = "44444444-4444-4444-8444-444444444444";

const ROOT_ENDPOINT = "c0b5ddf3-9d0c-5470-ab70-a622c550b246";
const ORDERS_ENDPOINT = "0d3c4a51-7f0e-5b8e-9c2a-3e1f6a7b8c90";
export const C002_CHAIN_ID = "c0020000-0000-4000-8000-000000000001";

/*
 * Mock-only findings, added to the contract example so the UI sees every
 * severity and a chain with more than one member. Vectors, scores and
 * mappings are the catalog's (config/checks.yaml); context scores come from
 * the CVSS v3.1 environmental formula as the backend computes them.
 */

/** LOW: TLS-009 on a public page; context leaves 3.1 unchanged. */
const lowFinding: Finding = {
  id: "f0000000-0000-4000-8000-000000000009",
  check_id: "TLS-009",
  title: "Weak HSTS Policy",
  category: "TLS",
  endpoint_id: ROOT_ENDPOINT,
  endpoint_url: "https://shop.example.com/",
  owasp_map: ["A02:2021"],
  cwe_map: ["CWE-319"],
  cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
  base_score: 3.1,
  final_score: 3.1,
  final_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N/CR:X/IR:X/AR:X",
  score_reasons: [
    "sensitivity:LOW",
    "no-context-change",
    "base:3.1",
    "environmental:3.1",
  ],
  severity_bucket: "LOW",
  evidence: {
    text: "Weak Strict-Transport-Security on /",
    header: "Strict-Transport-Security",
    value: "max-age=300",
  },
  sensitivity_class: "LOW",
  body_signals: [],
  chain_ids: [],
  recommendation: "Use max-age of at least one year with includeSubDomains.",
  limitation: null,
};

/**
 * INFO: no current check scores 0.0, so this one is scored by the interim
 * (legacy) formula, which can lower a score; it keeps INFO rendered.
 */
const infoFinding: Finding = {
  id: "f0000000-0000-4000-8000-000000000008",
  check_id: "HDR-012",
  title: "Missing Expect-CT / CT enforcement",
  category: "HEADERS",
  endpoint_id: ROOT_ENDPOINT,
  endpoint_url: "https://shop.example.com/",
  owasp_map: ["API8:2023"],
  cwe_map: [],
  cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
  base_score: 3.1,
  final_score: 0.0,
  final_vector: null,
  score_reasons: [],
  severity_bucket: "INFO",
  evidence: {
    text: "Missing Expect-CT on /",
    header: "Expect-CT",
    present: false,
  },
  sensitivity_class: "LOW",
  body_signals: [],
  chain_ids: [],
  recommendation:
    "Certificate Transparency is now enforced by browsers; ensure CT-logged certs.",
  limitation: "Legacy control; browsers enforce CT themselves.",
};

const C002_REF = {
  chain_id: "C002",
  name: "Error disclosure plus version banner enables targeted exploitation",
};

/** MEDIUM, chain C002 with HDR-007: a debug error page on the orders API. */
const verboseErrorFinding: Finding = {
  id: "f0000000-0000-4000-8000-00000000000a",
  check_id: "INF-007",
  title: "Verbose Error Response",
  category: "INFO_DISCLOSURE",
  endpoint_id: ORDERS_ENDPOINT,
  endpoint_url: "https://shop.example.com/api/v1/orders",
  owasp_map: ["A05:2021"],
  cwe_map: ["CWE-209"],
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
  base_score: 5.3,
  final_score: 5.3,
  final_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/CR:M/IR:M/AR:M",
  score_reasons: [
    "sensitivity:MEDIUM",
    "signal:INTERNAL_IP",
    "CR:M<-sensitivity:MEDIUM+signal:INTERNAL_IP",
    "IR:M<-sensitivity:MEDIUM",
    "AR:M<-sensitivity:MEDIUM",
    "base:5.3",
    "environmental:5.3",
  ],
  severity_bucket: "MEDIUM",
  evidence: {
    text: "Verbose error response on /api/v1/orders",
    status: 500,
    body_excerpt: [
      "Traceback (most recent call last):",
      '  File "/srv/app/orders.py", line 88, in list_orders',
      "    rows = db.execute(query)",
      "psycopg.OperationalError: could not connect to server at 10.0.4.12:5432",
      "DEBUG = True",
    ].join("\n"),
    chains: [C002_REF],
  },
  sensitivity_class: "MEDIUM",
  body_signals: ["INTERNAL_IP"],
  chain_ids: [C002_CHAIN_ID],
  recommendation:
    "Disable debug output and return a generic error envelope in production.",
  limitation: null,
};

const done = resultsDoneJson as ScanResults;
const BANNER_ID = "f0000000-0000-4000-8000-000000000006"; // HDR-007

/** C002 (config/chains.yaml): debug page + version banner on one host. */
const c002: ScanResults["chains"][number] = {
  id: C002_CHAIN_ID,
  chain_code: "C002",
  name: C002_REF.name,
  description:
    "Stack traces or debug pages reveal internals while banners name the exact server or framework version, so an attacker can pick a matching exploit.",
  composite_score: 5.6,
  severity: "MEDIUM",
  finding_ids: [verboseErrorFinding.id, BANNER_ID].sort(),
  composite_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
  evidence: {
    scope: { kind: "host", value: "shop.example.com" },
    groups: [["INF-007"], ["HDR-007"]],
    context: {},
    composite_cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
  },
};

const extra = [lowFinding, infoFinding, verboseErrorFinding];

/** DONE results: the contract example plus the mock-only findings above. */
export const resultsDone: ScanResults = {
  ...done,
  scan: {
    ...done.scan,
    severity_counts: {
      ...done.scan.severity_counts,
      low: done.scan.severity_counts.low + 1,
      info: done.scan.severity_counts.info + 1,
      medium: done.scan.severity_counts.medium + 1,
    },
  },
  // Ranked as the contract promises: final_score, then check_id.
  findings: [
    ...done.findings.map((f) =>
      f.id === BANNER_ID
        ? {
            ...f,
            chain_ids: [C002_CHAIN_ID],
            evidence: { ...f.evidence, chains: [C002_REF] },
          }
        : f,
    ),
    ...extra,
  ].sort(
    (a, b) =>
      b.final_score - a.final_score || a.check_id.localeCompare(b.check_id),
  ),
  chains: [...done.chains, c002],
};

export const resultsRunning = resultsRunningJson as ScanResults;
export const resultsFailed = resultsFailedJson as ScanResults;
export const scanQueued = scanQueuedJson as ScanStatus;
export const scanList = scansJson as ScanList;
export const errorExample = errorJson;
