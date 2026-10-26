/**
 * Friendly names for the API contract v1 types (docs/api-contract.md).
 *
 * The shapes come from `api-schema.ts`, generated from docs/openapi.json with
 * `npm run gen:api`. Never edit that file by hand; regenerate it after the
 * backend runs `make openapi`. Field names are the contract's (`check_id`,
 * `final_score`, ...): don't rename them on the client.
 */

import type { components } from "./api-schema";

type Schemas = components["schemas"];

export type ScanStatus = Schemas["app__api__schemas__contract__ScanStatus"];
export type ScanState = Schemas["app__db__models__enums__ScanStatus"];
export type ScanOptions = Schemas["ScanOptions"];
export type ScanResults = Schemas["ScanResults"];
export type ScanList = Schemas["Page_ScanStatus_"];
export type Finding = Schemas["Finding"];
export type Chain = Schemas["Chain"];
export type Severity = Schemas["Severity"];
export type SeverityCounts = Schemas["SeverityCounts"];
export type SensitivityClass = Schemas["ContextClass"];
export type BodySignal = Schemas["BodySignal"];
export type ErrorResponse = Schemas["ErrorResponse"];

/**
 * Body of `POST /api/scan`. The generated type marks fields with a server-side
 * default as required; here they are optional, as the contract allows.
 */
export type ScanRequest = Pick<
  Schemas["ScanRequest"],
  "url" | "authorisation_confirmed"
> &
  Partial<
    Pick<
      Schemas["ScanRequest"],
      "crawl_depth" | "use_wordlist" | "passive_only"
    >
  >;

export type ExportFormat = "json" | "csv" | "html" | "pdf";

/** Error codes from the contract's error table. */
export type ApiErrorCode =
  | "VALIDATION_ERROR"
  | "INVALID_TARGET"
  | "NOT_FOUND"
  | "SCAN_NOT_FINISHED"
  | "FORMAT_UNAVAILABLE"
  | "INTERNAL_ERROR";

/** One entry of `details` on a 422 response. */
export interface ValidationIssue {
  loc: (string | number)[];
  msg: string;
  type: string;
}
