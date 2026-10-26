/**
 * New-scan form rules: target URL validation and mapping API errors back to
 * form fields. The backend enforces the same rules (docs/api-contract.md,
 * POST /api/scan); checking here only gives faster, clearer feedback.
 */

import type { ApiError } from "./api";
import type { ScanRequest } from "./api-types";

export type ScanFormField =
  | "url"
  | "authorisation_confirmed"
  | "crawl_depth"
  | "use_wordlist"
  | "passive_only";

export interface ScanFormValues {
  url: string;
  authorisation_confirmed: boolean;
  crawl_depth: 1 | 2;
  use_wordlist: boolean;
  passive_only: boolean;
}

/** The contract's defaults for the advanced options. */
export const DEFAULT_SCAN_FORM: ScanFormValues = {
  url: "",
  authorisation_confirmed: false,
  crawl_depth: 2,
  use_wordlist: true,
  passive_only: false,
};

const UNSUPPORTED_SCHEME = "Only web addresses (https://...) can be scanned.";

/**
 * Returns an error message, or null when the URL is acceptable. Only http(s)
 * URLs are URLs here, and of those only https:// can be scanned: CAWASMA
 * tests HTTPS targets only.
 */
export function validateTargetUrl(input: string): string | null {
  const value = input.trim();
  if (!value) return "Enter the URL of the site or API to scan.";

  if (!value.includes("://")) {
    // "javascript:", "mailto:" ... are schemes; "host:8443" is not.
    if (/^[a-z][a-z\d+.-]*:(?!\d)/i.test(value)) return UNSUPPORTED_SCHEME;
    return `Include the scheme, for example https://${value.replace(/^\/+/, "")}`;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "This is not a valid URL. Example: https://shop.example.com";
  }

  if (url.protocol === "http:") {
    return `Only HTTPS targets can be scanned. Try https://${url.host}${url.pathname === "/" ? "" : url.pathname}`;
  }
  if (url.protocol !== "https:") return UNSUPPORTED_SCHEME;
  // Whether the host resolves to an allowed address is the backend's call
  // (SSRF guard, ALLOWED_INTERNAL_HOSTS): single-label names such as the
  // demo target "demo-target" can be valid.
  if (!url.hostname) {
    return "Enter a host name, for example https://shop.example.com";
  }
  if (url.username || url.password) {
    return "Remove the user name or password from the URL.";
  }
  return null;
}

export function toScanRequest(values: ScanFormValues): ScanRequest {
  return {
    url: values.url.trim(),
    // The field name is the contract's (British spelling); the backend
    // rejects the scan unless it is true.
    authorisation_confirmed: values.authorisation_confirmed as true,
    crawl_depth: values.crawl_depth,
    use_wordlist: values.use_wordlist,
    passive_only: values.passive_only,
  };
}

export interface SubmitErrors {
  /** Shown next to the field it concerns. */
  fields: Partial<Record<ScanFormField, string>>;
  /** Shown above the Start button when it is not about one field. */
  form?: { title: string; message: string };
}

/** Where to show an error from POST /api/scan. */
export function submitErrors(error: ApiError): SubmitErrors {
  if (error.kind === "network") {
    return {
      fields: {},
      form: {
        title: "Can't reach the CAWASMA API",
        message: `${error.message} Your scan was not started.`,
      },
    };
  }
  if (error.code === "INVALID_TARGET") {
    return { fields: { url: error.message } };
  }
  if (error.code === "VALIDATION_ERROR" && error.details?.length) {
    const fields: SubmitErrors["fields"] = {};
    for (const issue of error.details) {
      const field = issue.loc[1];
      if (
        issue.loc[0] === "body" &&
        typeof field === "string" &&
        isField(field)
      ) {
        fields[field] ??= issue.msg;
      }
    }
    if (Object.keys(fields).length > 0) return { fields };
  }
  if (error.kind === "server") {
    return {
      fields: {},
      form: {
        title: "The API could not start the scan",
        message: `${error.message} Try again in a moment.`,
      },
    };
  }
  return {
    fields: {},
    form: { title: "The scan was not accepted", message: error.message },
  };
}

function isField(name: string): name is ScanFormField {
  return name in DEFAULT_SCAN_FORM;
}
