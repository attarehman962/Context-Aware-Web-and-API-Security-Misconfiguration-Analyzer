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

export const MAX_RETRIES = 3;
const MAX_RETRY_DELAY_MS = 8_000;

/** Retry what may succeed next time (network, 5xx); a 4xx won't change. */
export function shouldRetry(failureCount: number, error: unknown): boolean {
  if (failureCount >= MAX_RETRIES) return false;
  return !(error instanceof ApiRequestError && error.error.kind === "client");
}

/** Exponential backoff between retries: 1 s, 2 s, 4 s, ... capped at 8 s. */
export function retryDelay(failureCount: number): number {
  return Math.min(1_000 * 2 ** failureCount, MAX_RETRY_DELAY_MS);
}

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Scan data changes only while a scan runs, and those queries poll.
        staleTime: 30_000,
        retry: shouldRetry,
        retryDelay,
        refetchOnWindowFocus: false,
      },
      mutations: {
        // Starting a scan is not idempotent: never repeat it automatically.
        retry: false,
      },
    },
  });
}
