/**
 * Typed client for the CAWASMA API contract v1 (docs/api-contract.md).
 *
 * Calls never throw: they resolve to an `ApiResult`, either `{ ok: true, data }`
 * or `{ ok: false, error }`, where `error.kind` says whether the request never
 * got an answer (`network`), was rejected (`client`, 4xx) or failed on the
 * server (`server`, 5xx). Show `error.message`; branch on `error.code`.
 * The one exception: a request cancelled through `signal` rejects with its
 * AbortError, which TanStack Query expects for cancelled queries.
 */

import type {
  ApiErrorCode,
  ExportFormat,
  FindingDetail,
  ResultsQuery,
  ScanRequest,
  ScanResults,
  ScanStatus,
  ValidationIssue,
} from "./api-types";
import { publicEnv, serverApiUrl } from "./env";

export type ApiError =
  | { kind: "network"; message: string }
  | {
      kind: "client" | "server";
      status: number;
      /** Contract error code; `UNKNOWN` if the body was not an error envelope. */
      code: ApiErrorCode | "UNKNOWN";
      message: string;
      /** Per-field problems, set on 422 responses. */
      details?: ValidationIssue[];
    };

export type ApiResult<T> =
  { ok: true; data: T } | { ok: false; error: ApiError };

export interface RequestOptions {
  signal?: AbortSignal;
}

/** API base URL for wherever this code runs (browser or Next.js server). */
export function apiBaseUrl(): string {
  return typeof window === "undefined" ? serverApiUrl() : publicEnv.apiUrl;
}

/** `POST /api/scan`: start a scan. Resolves to the QUEUED scan. */
export function createScan(
  body: ScanRequest,
  options: RequestOptions = {},
): Promise<ApiResult<ScanStatus>> {
  return request<ScanStatus>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: options.signal,
  });
}

/** `GET /api/results/{id}`: status, and findings + chains once DONE. */
export function getResults(
  scanId: string,
  options: RequestOptions & { query?: ResultsQuery } = {},
): Promise<ApiResult<ScanResults>> {
  const search = resultsSearch(options.query);
  return request<ScanResults>(
    `/api/results/${encodeURIComponent(scanId)}${search}`,
    { signal: options.signal },
  );
}

/**
 * `GET /api/results/{id}/findings/{finding_id}` (since 1.2): one finding with
 * its endpoint, check description, impact, references and chains.
 */
export function getFindingDetail(
  scanId: string,
  findingId: string,
  options: RequestOptions = {},
): Promise<ApiResult<FindingDetail>> {
  return request<FindingDetail>(
    `/api/results/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`,
    { signal: options.signal },
  );
}

/** Filters repeat their parameter (?severity=HIGH&severity=LOW). */
function resultsSearch(query: ResultsQuery = {}): string {
  const params = new URLSearchParams();
  for (const v of query.severity ?? []) params.append("severity", v);
  for (const v of query.category ?? []) params.append("category", v);
  for (const v of query.owasp ?? []) params.append("owasp", v);
  if (query.in_chain !== undefined)
    params.set("in_chain", String(query.in_chain));
  if (query.page !== undefined) params.set("page", String(query.page));
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  const search = params.toString();
  return search ? `?${search}` : "";
}

/** Download link for a finished scan's report; use it as `<a href download>`. */
export function getExportUrl(
  scanId: string,
  format: ExportFormat = "json",
): string {
  return `${apiBaseUrl()}/api/results/${encodeURIComponent(scanId)}/export?format=${format}`;
}

async function request<T>(
  path: string,
  init: RequestInit,
): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      headers: { Accept: "application/json", ...init.headers },
    });
  } catch (err) {
    // Cancelled on purpose: not a network failure. (`instanceof DOMException`
    // is unreliable across realms, so check the signal.)
    if (init.signal?.aborted) throw err;
    return {
      ok: false,
      error: {
        kind: "network",
        message: "Could not reach the CAWASMA API. Check that it is running.",
      },
    };
  }

  const body: unknown = await response.json().catch(() => undefined);

  if (response.ok) {
    if (body === undefined) {
      return {
        ok: false,
        error: {
          kind: "server",
          status: response.status,
          code: "UNKNOWN",
          message: "The API sent a response that is not valid JSON.",
        },
      };
    }
    return { ok: true, data: body as T };
  }

  return { ok: false, error: toHttpError(response.status, body) };
}

function toHttpError(status: number, body: unknown): ApiError {
  const kind = status >= 500 ? "server" : "client";
  const envelope = body as
    | {
        error?: { code?: string; message?: string };
        details?: ValidationIssue[];
      }
    | undefined;
  const code = envelope?.error?.code;
  const message = envelope?.error?.message;
  if (typeof code === "string" && typeof message === "string") {
    return {
      kind,
      status,
      code: code as ApiErrorCode,
      message,
      ...(Array.isArray(envelope?.details) && { details: envelope.details }),
    };
  }
  return {
    kind,
    status,
    code: "UNKNOWN",
    message:
      kind === "server"
        ? `The API failed with HTTP ${status}. Try again later.`
        : `The API rejected the request (HTTP ${status}).`,
  };
}
