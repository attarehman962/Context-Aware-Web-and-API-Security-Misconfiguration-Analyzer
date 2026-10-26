/**
 * Simulated scans for mock mode: a scan started with `POST /api/scan` moves
 * QUEUED -> RUNNING -> DONE over `SCAN_DURATION_MS`, then returns the DONE
 * fixture re-addressed to the new scan.
 *
 * The creation time is encoded in the scan id, so a simulated scan survives a
 * page reload and is understood by both the browser worker and the Node
 * server. Only its URL and options live in memory (with defaults as fallback).
 */

import type { ScanOptions, ScanResults, ScanStatus } from "@/lib/api-types";

import { resultsDone, scanQueued } from "./fixtures";

export const SCAN_DURATION_MS = 10_000;
/** Time spent QUEUED before the scan starts running. */
export const QUEUED_MS = 1_500;

const ID_PREFIX = "5ca10000-0000-4000-8000-";

interface ScanInput {
  url: string;
  options: ScanOptions;
}

const inputs = new Map<string, ScanInput>();

export function startSimulatedScan(input: ScanInput, now: number): string {
  const id = ID_PREFIX + now.toString(16).padStart(12, "0");
  inputs.set(id, input);
  return id;
}

/** Ids of simulated scans started in this process, newest first. */
export function simulatedScanIds(): string[] {
  return [...inputs.keys()].reverse();
}

/** `ScanResults` for a simulated scan at time `now`, or null for other ids. */
export function simulatedResults(id: string, now: number): ScanResults | null {
  const createdAt = createdAtOf(id);
  if (createdAt === null) return null;

  const { url, options } = inputs.get(id) ?? {
    url: scanQueued.url,
    options: scanQueued.options,
  };
  const elapsed = Math.max(0, now - createdAt);
  const base: ScanStatus = {
    ...scanQueued,
    scan_id: id,
    url,
    options,
    created_at: iso(createdAt),
  };

  if (elapsed < QUEUED_MS) {
    return { ...resultsDone, scan: base, findings: [], chains: [] };
  }

  const startedAt = iso(createdAt + QUEUED_MS);
  if (elapsed < SCAN_DURATION_MS) {
    const fraction = (elapsed - QUEUED_MS) / (SCAN_DURATION_MS - QUEUED_MS);
    const progress = Math.min(99, Math.max(1, Math.round(fraction * 100)));
    return {
      ...resultsDone,
      scan: {
        ...base,
        status: "RUNNING",
        progress,
        stage: stageAt(progress),
        started_at: startedAt,
      },
      findings: [],
      chains: [],
    };
  }

  const origin = originOf(url);
  return {
    ...resultsDone,
    scan: {
      ...resultsDone.scan,
      scan_id: id,
      url,
      options,
      created_at: base.created_at,
      started_at: startedAt,
      completed_at: iso(createdAt + SCAN_DURATION_MS),
    },
    findings: resultsDone.findings.map((f) => ({
      ...f,
      endpoint_url:
        f.endpoint_url?.replace(originOf(resultsDone.scan.url), origin) ?? null,
    })),
  };
}

/**
 * The real pipeline's stages and the progress at which each starts
 * (backend/app/core/pipeline.py run_pipeline).
 */
const STAGES: [number, string][] = [
  [92, "correlating"],
  [15, "analyzing"],
  [12, "tls"],
  [8, "crawling"],
  [0, "initializing"],
];

function stageAt(progress: number): string {
  return STAGES.find(([from]) => progress >= from)![1];
}

function createdAtOf(id: string): number | null {
  if (!id.startsWith(ID_PREFIX)) return null;
  const ms = Number.parseInt(id.slice(ID_PREFIX.length), 16);
  return Number.isFinite(ms) ? ms : null;
}

function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** Like the real API: microsecond precision, e.g. 2026-10-26T17:26:21.445000Z. */
function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/Z$/, "000Z");
}
