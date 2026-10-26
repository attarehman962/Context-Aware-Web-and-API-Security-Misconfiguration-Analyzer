/**
 * MSW request handlers for the contract v1 routes (docs/api-contract.md).
 *
 * They mirror the backend's MOCK_API mode: the fixed example scans by id, the
 * same validation (422) and HTTPS rule (400), 404 for unknown ids. In
 * addition, `POST /api/scan` starts a simulated scan (see scenario.ts) so the
 * progress view can be built against a scan that actually moves.
 *
 * Paths match on any origin (`*`), so they work whatever the API base URL is.
 */

import { http, HttpResponse } from "msw";

import type {
  ApiErrorCode,
  ExportFormat,
  ScanResults,
  ScanStatus,
  ValidationIssue,
} from "@/lib/api-types";

import {
  DONE_SCAN_ID,
  FAILED_SCAN_ID,
  QUEUED_SCAN_ID,
  RUNNING_SCAN_ID,
  resultsDone,
  resultsFailed,
  resultsRunning,
  scanList,
  scanQueued,
} from "./fixtures";
import {
  simulatedResults,
  simulatedScanIds,
  startSimulatedScan,
} from "./scenario";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SCAN_REQUEST_FIELDS = [
  "url",
  "authorisation_confirmed",
  "crawl_depth",
  "use_wordlist",
  "passive_only",
];
const EXPORT_FORMATS: ExportFormat[] = ["json", "csv", "html", "pdf"];
const CSV_COLUMNS = [
  "id",
  "check_id",
  "title",
  "category",
  "severity_bucket",
  "final_score",
  "base_score",
  "cvss_vector",
  "sensitivity_class",
  "body_signals",
  "owasp_map",
  "cwe_map",
  "endpoint_url",
  "chain_ids",
] as const;

export interface HandlerOptions {
  /** Clock for the simulated scans; tests pass a fake one. */
  now?: () => number;
}

export function createHandlers({ now = Date.now }: HandlerOptions = {}) {
  function findResults(id: string): ScanResults | null {
    switch (id) {
      case DONE_SCAN_ID:
        return resultsDone;
      case RUNNING_SCAN_ID:
        return resultsRunning;
      case FAILED_SCAN_ID:
        return resultsFailed;
      case QUEUED_SCAN_ID:
        return { ...resultsDone, scan: scanQueued, findings: [], chains: [] };
      default:
        return simulatedResults(id, now());
    }
  }

  /** 422 for a malformed id, 404 for an unknown one, else the results. */
  function lookup(id: string): ScanResults | Response {
    if (!UUID.test(id)) {
      return validationError([
        {
          loc: ["path", "scan_id"],
          msg: "Input should be a valid UUID",
          type: "uuid_parsing",
        },
      ]);
    }
    return findResults(id) ?? apiError(404, "NOT_FOUND", "Scan not found.");
  }

  return [
    http.post("*/api/scan", async ({ request }) => {
      const body: unknown = await request.json().catch(() => undefined);
      const issues = validateScanRequest(body);
      if (issues.length > 0) return validationError(issues);

      const input = body as Record<string, unknown>;
      const url = input.url as string;
      if (!isHttpsUrl(url)) {
        return apiError(
          400,
          "INVALID_TARGET",
          "Only HTTPS targets are allowed.",
        );
      }

      const options = {
        crawl_depth: (input.crawl_depth as number | undefined) ?? 2,
        use_wordlist: (input.use_wordlist as boolean | undefined) ?? true,
        passive_only: (input.passive_only as boolean | undefined) ?? false,
      };
      const id = startSimulatedScan({ url, options }, now());
      const scan = simulatedResults(id, now())!.scan;
      return HttpResponse.json<ScanStatus>(scan, {
        status: 202,
        headers: { Location: `/api/results/${id}` },
      });
    }),

    http.get("*/api/results/:scanId", ({ params }) => {
      const found = lookup(String(params.scanId));
      return found instanceof Response ? found : HttpResponse.json(found);
    }),

    http.get("*/api/results/:scanId/export", ({ params, request }) => {
      const format = new URL(request.url).searchParams.get("format") ?? "json";
      if (!EXPORT_FORMATS.includes(format as ExportFormat)) {
        return validationError([
          {
            loc: ["query", "format"],
            msg: "Input should be 'json', 'csv', 'html' or 'pdf'",
            type: "literal_error",
          },
        ]);
      }
      const found = lookup(String(params.scanId));
      if (found instanceof Response) return found;
      if (found.scan.status !== "DONE") {
        return apiError(409, "SCAN_NOT_FINISHED", "Scan is not finished yet.");
      }
      const disposition = `attachment; filename="cawasma-${found.scan.scan_id}.${format}"`;
      if (format === "json") {
        return HttpResponse.json(found, {
          headers: { "Content-Disposition": disposition },
        });
      }
      // The real API renders a PDF (WeasyPrint is in the image); a minimal
      // valid PDF keeps the mock's response the same shape.
      const [body, type] =
        format === "csv"
          ? [toCsv(found), "text/csv; charset=utf-8"]
          : format === "pdf"
            ? [MINIMAL_PDF, "application/pdf"]
            : [toHtml(found), "text/html; charset=utf-8"];
      return new HttpResponse(body, {
        headers: { "Content-Type": type, "Content-Disposition": disposition },
      });
    }),

    http.get("*/api/scans", ({ request }) => {
      const query = new URL(request.url).searchParams;
      const page = Number(query.get("page") ?? 1);
      const limit = Number(query.get("limit") ?? 20);
      const issues: ValidationIssue[] = [];
      if (!Number.isInteger(page) || page < 1) {
        issues.push({
          loc: ["query", "page"],
          msg: "Input should be greater than or equal to 1",
          type: "greater_than_equal",
        });
      }
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        issues.push({
          loc: ["query", "limit"],
          msg: "Input should be between 1 and 100",
          type: "less_than_equal",
        });
      }
      if (issues.length > 0) return validationError(issues);

      const all = [
        ...simulatedScanIds().map((id) => simulatedResults(id, now())!.scan),
        ...scanList.items,
      ];
      return HttpResponse.json({
        items: all.slice((page - 1) * limit, page * limit),
        meta: {
          page,
          limit,
          total: all.length,
          pages: Math.ceil(all.length / limit),
        },
      });
    }),
  ];
}

export const handlers = createHandlers();

const MINIMAL_PDF = [
  "%PDF-1.4",
  "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj",
  "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj",
  "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj",
  "trailer<</Root 1 0 R>>",
  "%%EOF",
].join("\n");

function apiError(status: number, code: ApiErrorCode, message: string) {
  return HttpResponse.json(
    { success: false, error: { code, message } },
    { status },
  );
}

function validationError(details: ValidationIssue[]) {
  return HttpResponse.json(
    {
      success: false,
      error: {
        code: "VALIDATION_ERROR",
        message: "Request validation failed.",
      },
      details,
    },
    { status: 422 },
  );
}

/** The ScanRequest rules from the contract, reported like pydantic does. */
function validateScanRequest(body: unknown): ValidationIssue[] {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return [
      {
        loc: ["body"],
        msg: "Input should be a valid dictionary",
        type: "dict_type",
      },
    ];
  }
  const input = body as Record<string, unknown>;
  const issues: ValidationIssue[] = [];
  const at = (field: string, msg: string, type: string) =>
    issues.push({ loc: ["body", field], msg, type });

  if (input.url === undefined) at("url", "Field required", "missing");
  else if (typeof input.url !== "string") {
    at("url", "Input should be a valid string", "string_type");
  }
  if (input.authorisation_confirmed === undefined) {
    at("authorisation_confirmed", "Field required", "missing");
  } else if (input.authorisation_confirmed !== true) {
    at("authorisation_confirmed", "Input should be True", "literal_error");
  }
  if (
    input.crawl_depth !== undefined &&
    input.crawl_depth !== 1 &&
    input.crawl_depth !== 2
  ) {
    at("crawl_depth", "Input should be 1 or 2", "literal_error");
  }
  for (const field of ["use_wordlist", "passive_only"]) {
    if (input[field] !== undefined && typeof input[field] !== "boolean") {
      at(field, "Input should be a valid boolean", "bool_type");
    }
  }
  for (const field of Object.keys(input)) {
    if (!SCAN_REQUEST_FIELDS.includes(field)) {
      at(field, "Extra inputs are not permitted", "extra_forbidden");
    }
  }
  return issues;
}

function isHttpsUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

function toCsv(results: ScanResults): string {
  const cell = (value: unknown): string => {
    const text = Array.isArray(value) ? value.join(";") : String(value ?? "");
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const rows = results.findings.map((f) =>
    CSV_COLUMNS.map((column) => cell(f[column])).join(","),
  );
  return [CSV_COLUMNS.join(","), ...rows].join("\r\n") + "\r\n";
}

function toHtml(results: ScanResults): string {
  const escape = (text: string) =>
    text.replace(
      /[&<>"]/g,
      (c) => `&${{ "&": "amp", "<": "lt", ">": "gt", '"': "quot" }[c]};`,
    );
  const rows = results.findings
    .map(
      (f) =>
        `<tr><td>${f.severity_bucket}</td><td>${f.final_score}</td><td>${escape(f.check_id)}</td><td>${escape(f.title)}</td><td>${escape(f.endpoint_url ?? "(host)")}</td></tr>`,
    )
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>CAWASMA report (mock)</title></head><body><h1>CAWASMA report: ${escape(results.scan.url)}</h1><table><tr><th>Severity</th><th>Score</th><th>Check</th><th>Title</th><th>Endpoint</th></tr>${rows}</table></body></html>`;
}
