/**
 * TanStack Query setup. The API client returns `ApiResult`s; queries need a
 * thrown error to enter their error state, so `unwrap` turns a failed result
 * into an `ApiRequestError` that still carries the typed `ApiError`.
 */

import { QueryClient } from "@tanstack/react-query";

import type { ApiError, ApiResult } from "./api";

export class ApiRequestError extends Error {
  constructor(readonly error: ApiError) {
    super(error.message);
    this.name = "ApiRequestError";
  }
}

export function unwrap<T>(result: ApiResult<T>): T {
  if (!result.ok) throw new ApiRequestError(result.error);
  return result.data;
}

const MAX_RETRIES = 2;

/** Retry what may succeed next time (network, 5xx); a 4xx won't change. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= MAX_RETRIES) return false;
  return !(error instanceof ApiRequestError && error.error.kind === "client");
}

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Scan data changes only while a scan runs, and those queries poll.
        staleTime: 30_000,
        retry: shouldRetry,
        refetchOnWindowFocus: false,
      },
      mutations: {
        // Starting a scan is not idempotent: never repeat it automatically.
        retry: false,
      },
    },
  });
}
