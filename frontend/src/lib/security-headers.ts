/**
 * Response headers for every page (security review SEC-08).
 *
 * The pages show text the scanned target controls (URLs, evidence). React
 * escapes it, so these are defence in depth. The CSP sets only directives that
 * don't need a nonce: Next.js injects inline scripts, so a script-src policy
 * would need per-request nonces (docs/01-app/02-guides/content-security-policy.md).
 */
export const SECURITY_HEADERS = [
  {
    key: "Content-Security-Policy",
    value:
      "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'",
  },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
];
