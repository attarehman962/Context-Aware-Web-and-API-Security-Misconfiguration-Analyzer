/**
 * Mock GET /api/results/{scan_id}/findings/{finding_id} (contract 1.2): a
 * finding plus its endpoint, check text and chains, in the shape the real
 * route returns (backend contract_service.get_finding_detail). Endpoint
 * details are plausible values for the example site; the sensitivity
 * reasons are the real classifier's wording (backend core/sensitivity.py).
 */

import type {
  CookieMeta,
  EndpointDetail,
  Finding,
  FindingDetail,
  ScanResults,
} from "@/lib/api-types";

interface EndpointExtra {
  reason: string[];
  confidence: number;
  content_type: string;
  status_code: number;
  security_headers: Record<string, string>;
  cookies?: CookieMeta[];
}

const SERVER = { Server: "nginx/1.18.0 (Ubuntu)" };

const ENDPOINTS: Record<string, EndpointExtra> = {
  "/": {
    reason: ["Public/informational path"],
    confidence: 0.7,
    content_type: "text/html; charset=utf-8",
    status_code: 200,
    security_headers: {
      ...SERVER,
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security": "max-age=300",
    },
  },
  "/.env": {
    reason: ["No sensitive tokens detected; treated as low-sensitivity"],
    confidence: 0.5,
    content_type: "text/plain",
    status_code: 200,
    security_headers: SERVER,
  },
  "/api/v1/users/42": {
    reason: [
      "Contains user/account tokens",
      "Semantic similarity agrees with keyword signal",
    ],
    confidence: 0.82,
    content_type: "application/json",
    status_code: 200,
    security_headers: { ...SERVER, "Cache-Control": "no-store" },
  },
  "/api/v1/orders": {
    reason: ["Contains generic API/data tokens"],
    confidence: 0.7,
    content_type: "text/html; charset=utf-8",
    status_code: 500,
    security_headers: SERVER,
  },
  "/api/payment/checkout": {
    reason: [
      "Contains payment/financial tokens",
      "Semantic similarity agrees with keyword signal",
    ],
    confidence: 0.9,
    content_type: "application/json",
    status_code: 200,
    security_headers: { ...SERVER, "X-Frame-Options": "DENY" },
  },
  "/admin/login": {
    reason: [
      "Contains identity/privilege tokens",
      "Semantic similarity agrees with keyword signal",
    ],
    confidence: 0.9,
    content_type: "text/html; charset=utf-8",
    status_code: 200,
    security_headers: { ...SERVER, "X-Frame-Options": "SAMEORIGIN" },
    cookies: [
      {
        name: "admin_session",
        http_only: true,
        secure: true,
        same_site: "UNSET",
        domain: null,
        path: "/",
      },
    ],
  },
};

/** What the catalog says about each check (backend config/checks.yaml). */
const CHECK_TEXT: Record<
  string,
  { description: string; impact: string; references: string[] }
> = {
  "HDR-001": {
    description:
      "The HTTPS response does not send Strict-Transport-Security, so browsers may still reach the site over plain HTTP.",
    impact:
      "An on-path attacker can downgrade the first visit to HTTP and read or change the traffic.",
    references: [
      "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ],
  },
  "INF-003": {
    description: "A .env configuration file is served to anyone who asks.",
    impact:
      "Database passwords, API keys and internal hosts in the file become usable by an attacker.",
    references: ["https://owasp.org/www-project-top-ten/"],
  },
  "INF-007": {
    description:
      "The response exposes a development error page or diagnostic details beyond a generic production error message.",
    impact:
      "Stack traces reveal file paths, library versions and internal addresses that help an attacker plan an exploit.",
    references: ["https://owasp.org/www-community/Improper_Error_Handling"],
  },
};

export function findingDetail(
  results: ScanResults,
  findingId: string,
): FindingDetail | null {
  const finding = results.findings.find((f) => f.id === findingId);
  if (!finding) return null;
  const text = CHECK_TEXT[finding.check_id];
  return {
    ...finding,
    description: text?.description ?? String(finding.evidence.text ?? ""),
    impact: text?.impact ?? null,
    references: text?.references ?? [],
    endpoint: endpointDetail(finding),
    chains: results.chains.filter((c) => finding.chain_ids.includes(c.id)),
  };
}

function endpointDetail(f: Finding): EndpointDetail | null {
  if (!f.endpoint_id || !f.endpoint_url) return null;
  const url = new URL(f.endpoint_url);
  const extra = ENDPOINTS[url.pathname] ?? {
    reason: ["No sensitive tokens detected; treated as low-sensitivity"],
    confidence: 0.5,
    content_type: "text/html; charset=utf-8",
    status_code: 200,
    security_headers: SERVER,
  };
  return {
    id: f.endpoint_id,
    url: f.endpoint_url,
    path: url.pathname + url.search,
    method: "GET",
    status_code: extra.status_code,
    content_type: extra.content_type,
    sensitivity_class: f.sensitivity_class,
    sensitivity_confidence: extra.confidence,
    sensitivity_reason: extra.reason,
    body_signals: f.body_signals,
    security_headers: extra.security_headers,
    cookies: (extra.cookies ?? []) as unknown as Record<string, unknown>[],
  };
}
