"use client";

/**
 * Query and mutation hooks for the contract routes. Components use these, not
 * the client directly, so caching and polling behave the same everywhere.
 */

import { useMutation, useQuery, type Query } from "@tanstack/react-query";

import { createScan, getResults } from "./api";
import type { ScanRequest, ScanResults, ScanStatus } from "./api-types";
import { unwrap } from "./query-client";

/** Poll interval while a scan is QUEUED or RUNNING (the contract says 2-3 s). */
export const POLL_INTERVAL_MS = 2_500;

export const queryKeys = {
  results: (scanId: string) => ["results", scanId] as const,
};

export function isFinished(scan: ScanStatus): boolean {
  return scan.status === "DONE" || scan.status === "FAILED";
}

/** Status and results of a scan; polls until it is DONE or FAILED. */
export function useScanResults(scanId: string) {
  return useQuery({
    queryKey: queryKeys.results(scanId),
    queryFn: async ({ signal }) => unwrap(await getResults(scanId, { signal })),
    refetchInterval: (query: Query<ScanResults>) => {
      const data = query.state.data;
      if (query.state.status === "error") return false;
      return data && isFinished(data.scan) ? false : POLL_INTERVAL_MS;
    },
    // A finished scan never changes.
    staleTime: (query: Query<ScanResults>) =>
      query.state.data && isFinished(query.state.data.scan) ? Infinity : 0,
  });
}

/** Start a scan. Resolves to the QUEUED scan; follow it with useScanResults. */
export function useCreateScan() {
  return useMutation({
    mutationFn: async (body: ScanRequest) => unwrap(await createScan(body)),
  });
}
