/**
 * Mock-only scan with many findings, for checking that the results page
 * stays smooth (virtualised list, filters) at 500+ findings. Deterministic:
 * the same id always gives the same findings. Not part of the contract
 * examples.
 */

import type { Finding, ScanResults, Severity } from "@/lib/api-types";
import { severityFromScore } from "@/lib/severity";

import { resultsDone } from "./fixtures";

export const LARGE_SCAN_ID = "55555555-5555-4555-8555-555555555555";
export const LARGE_SCAN_SIZE = 600;

const PATHS = [
  "/",
  "/login",
  "/admin",
  "/admin/users",
  "/api/v1/users",
  "/api/v1/orders",
  "/api/payment/checkout",
  "/api/v1/products",
  "/static/app.js",
  "/account/settings",
  "/search",
  "/.env",
];

/** Small deterministic PRNG (mulberry32) so the data never changes. */
function random(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildLargeScan(): ScanResults {
  const next = random(42);
  const templates = resultsDone.findings;
  const chainId = resultsDone.chains[0].id;
  const findings: Finding[] = Array.from(
    { length: LARGE_SCAN_SIZE },
    (_, i) => {
      const t = templates[i % templates.length];
      const path = `${PATHS[Math.floor(next() * PATHS.length)]}${i >= PATHS.length ? `?page=${i}` : ""}`;
      // Context moves the score anywhere from -2.5 to +3.5 around the base.
      const final =
        Math.round(
          Math.min(10, Math.max(0, t.base_score + (next() * 6 - 2.5))) * 10,
        ) / 10;
      const hex = i.toString(16).padStart(12, "0");
      return {
        ...t,
        id: `f5555555-0000-4000-8000-${hex}`,
        endpoint_id: t.endpoint_id && `e5555555-0000-4000-8000-${hex}`,
        endpoint_url: t.endpoint_url && `https://shop.example.com${path}`,
        final_score: final,
        final_vector: null,
        score_reasons: [],
        severity_bucket: severityFromScore(final),
        chain_ids: i % 25 === 0 ? [chainId] : [],
      };
    },
  );
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity_bucket.toLowerCase() as Lowercase<Severity>] += 1;
  }
  return {
    ...resultsDone,
    scan: {
      ...resultsDone.scan,
      scan_id: LARGE_SCAN_ID,
      severity_counts: counts,
    },
    findings,
    chains: [
      {
        ...resultsDone.chains[0],
        finding_ids: findings
          .filter((f) => f.chain_ids.length > 0)
          .map((f) => f.id),
      },
    ],
  };
}

let cached: ScanResults | undefined;

export function largeScanResults(): ScanResults {
  cached ??= buildLargeScan();
  return cached;
}
