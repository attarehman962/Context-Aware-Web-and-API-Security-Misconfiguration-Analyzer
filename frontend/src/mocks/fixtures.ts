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

/**
 * Mock-only finding so the UI sees every severity: the contract examples have
 * no INFO finding. HDR-012's vector and base score are the catalog's.
 */
const infoFinding: Finding = {
  id: "f0000000-0000-4000-8000-000000000008",
  check_id: "HDR-012",
  title: "Missing Expect-CT / CT enforcement",
  category: "HEADERS",
  endpoint_id: "c0b5ddf3-9d0c-5470-ab70-a622c550b246",
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

const done = resultsDoneJson as ScanResults;

/** DONE results: the contract example's 7 findings plus `infoFinding`. */
export const resultsDone: ScanResults = {
  ...done,
  scan: {
    ...done.scan,
    severity_counts: { ...done.scan.severity_counts, info: 1 },
  },
  findings: [...done.findings, infoFinding],
};

export const resultsRunning = resultsRunningJson as ScanResults;
export const resultsFailed = resultsFailedJson as ScanResults;
export const scanQueued = scanQueuedJson as ScanStatus;
export const scanList = scansJson as ScanList;
export const errorExample = errorJson;
