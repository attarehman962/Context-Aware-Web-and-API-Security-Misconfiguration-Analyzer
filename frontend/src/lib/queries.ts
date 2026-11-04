"use client";

/**
 * Query and mutation hooks for the contract routes. Components use these, not
 * the client directly, so caching and polling behave the same everywhere.
 */

import {
  useMutation,
  useQuery,
  useQueryClient,
  type Query,
} from "@tanstack/react-query";

import {
  cancelScan,
  createScan,
  getFindingDetail,
  getResults,
  listScans,
} from "./api";
import type {
  Finding,
  ScanRequest,
  ScanResults,
  ScanStatus,
} from "./api-types";
import { unwrap } from "./query-client";

/** Poll interval while a scan is QUEUED or RUNNING (the contract says 2-3 s). */
export const POLL_INTERVAL_MS = 2_000;
/**
 * While live updates arrive, results are still re-read this often, in case
 * the socket misses the final event.
 */
export const LIVE_SAFETY_POLL_MS = 15_000;

export const queryKeys = {
  history: ["history"] as const,
  results: (scanId: string) => ["results", scanId] as const,
  finding: (scanId: string, findingId: string) =>
    ["results", scanId, "finding", findingId] as const,
};

export function isFinished(scan: ScanStatus): boolean {
  return scan.status === "DONE" || scan.status === "FAILED";
}

/** Findings ranked by final_score, highest first; ties by check_id. */
export function sortByFinalScore(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      b.final_score - a.final_score || a.check_id.localeCompare(b.check_id),
  );
}

/**
 * Status and results of a scan; polls every `pollIntervalMs` until it is
 * DONE or FAILED. A function is read before every poll, so the rate can
 * follow live updates. Polling stops while the API is failing (after the
 * retries); `refetch` resumes it.
 */
export function useScanResults(
  scanId: string,
  {
    pollIntervalMs = POLL_INTERVAL_MS,
  }: { pollIntervalMs?: number | (() => number) } = {},
) {
  return useQuery({
    queryKey: queryKeys.results(scanId),
    queryFn: async ({ signal }) => {
      const results = unwrap(await getResults(scanId, { signal }));
      // The contract ranks findings, but the API does not sort them yet.
      return { ...results, findings: sortByFinalScore(results.findings) };
    },
    refetchInterval: (query: Query<ScanResults>) => {
      const data = query.state.data;
      if (query.state.status === "error") return false;
      if (data && isFinished(data.scan)) return false;
      return typeof pollIntervalMs === "function"
        ? pollIntervalMs()
        : pollIntervalMs;
    },
    // A finished scan never changes.
    staleTime: (query: Query<ScanResults>) =>
      query.state.data && isFinished(query.state.data.scan) ? Infinity : 0,
  });
}

/**
 * One finding's drill-down (contract 1.2). Fetched only while `enabled`
 * (the finding is expanded); a finished scan's findings never change.
 */
export function useFindingDetail(
  scanId: string,
  findingId: string,
  { enabled = true }: { enabled?: boolean } = {},
) {
  return useQuery({
    queryKey: queryKeys.finding(scanId, findingId),
    queryFn: async ({ signal }) =>
      unwrap(await getFindingDetail(scanId, findingId, { signal })),
    enabled,
    staleTime: Infinity,
  });
}

/** GET /api/scans allows at most 100 per page. */
const HISTORY_FETCH_LIMIT = 100;
/** Stop after this many pages (10,000 scans) rather than loop forever. */
const HISTORY_MAX_PAGES = 100;

/**
 * Every past scan, newest first. The API has no search parameter, so the
 * history page loads all pages once and searches/pages on the client.
 */
export function useScanHistory() {
  return useQuery({
    queryKey: queryKeys.history,
    queryFn: async ({ signal }) => {
      const scans: ScanStatus[] = [];
      for (let page = 1; page <= HISTORY_MAX_PAGES; page += 1) {
        const data = unwrap(
          await listScans(page, HISTORY_FETCH_LIMIT, { signal }),
        );
        scans.push(...data.items);
        if (page >= data.meta.pages || data.items.length === 0) break;
      }
      return scans;
    },
    // Running scans change; refresh the list now and then while it is open.
    refetchInterval: (query: Query<ScanStatus[]>) =>
      query.state.data?.some((s) => !isFinished(s)) ? 10_000 : false,
  });
}

/** Stop a queued or running scan (contract 1.3); refreshes its results. */
export function useCancelScan(scanId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => unwrap(await cancelScan(scanId)),
    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: queryKeys.results(scanId) }),
  });
}

/** Start a scan. Resolves to the QUEUED scan; follow it with useScanResults. */
export function useCreateScan() {
  return useMutation({
    mutationFn: async (body: ScanRequest) => unwrap(await createScan(body)),
  });
}
