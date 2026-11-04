/**
 * Turns a finding's stored evidence into something readable. The scanner does
 * not keep raw HTTP exchanges; it stores the endpoint's method, status,
 * content type, security headers and cookie metadata (never values) plus a
 * redacted body excerpt. The snippet below is rebuilt from those, so it is
 * labelled as such in the UI.
 */

import type { CookieMeta, EndpointDetail, Finding } from "./api-types";

/** Evidence keys shown elsewhere (text as the summary, excerpt in the snippet). */
const SHOWN_ELSEWHERE = new Set(["text", "body_excerpt", "chains"]);

export function evidenceEntries(
  evidence: Finding["evidence"],
): [string, string][] {
  return Object.entries(evidence)
    .filter(([key]) => !SHOWN_ELSEWHERE.has(key))
    .map(([key, value]) => [key, formatValue(value)]);
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "none";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function bodyExcerpt(evidence: Finding["evidence"]): string | null {
  const excerpt = evidence.body_excerpt;
  return typeof excerpt === "string" && excerpt.trim() ? excerpt : null;
}

/** Request line + response head + body excerpt, or null for host-level findings. */
export function httpSnippet(
  endpoint: EndpointDetail | null,
  evidence: Finding["evidence"],
): string | null {
  if (!endpoint) return null;
  const url = new URL(endpoint.url);
  const lines = [
    `${endpoint.method} ${endpoint.path || url.pathname} HTTP/1.1`,
    `Host: ${url.host}`,
    "",
    `HTTP/1.1 ${endpoint.status_code ?? "(status not recorded)"}`,
  ];
  if (endpoint.content_type)
    lines.push(`Content-Type: ${endpoint.content_type}`);
  for (const [name, value] of Object.entries(endpoint.security_headers)) {
    lines.push(`${name}: ${value}`);
  }
  for (const cookie of endpoint.cookies as unknown as CookieMeta[]) {
    lines.push(`Set-Cookie: ${cookieLine(cookie)}`);
  }
  const excerpt = bodyExcerpt(evidence);
  if (excerpt) lines.push("", excerpt);
  return lines.join("\n");
}

function cookieLine(cookie: CookieMeta): string {
  const parts = [`${cookie.name}=<value not stored>`];
  if (cookie.domain) parts.push(`Domain=${cookie.domain}`);
  if (cookie.path) parts.push(`Path=${cookie.path}`);
  if (cookie.secure) parts.push("Secure");
  if (cookie.http_only) parts.push("HttpOnly");
  parts.push(`SameSite=${cookie.same_site}`);
  return parts.join("; ");
}
