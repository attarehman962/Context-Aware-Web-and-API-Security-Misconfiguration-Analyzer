/**
 * Links to the official pages for the standards ids on a finding: OWASP Top
 * 10 2021, OWASP API Security Top 10 2023, and MITRE CWE. Unknown ids get
 * no link rather than a guessed one.
 */

export interface StandardLink {
  id: string;
  name: string | null;
  url: string | null;
}

const TOP10_2021: Record<string, [string, string]> = {
  A01: ["Broken Access Control", "A01_2021-Broken_Access_Control"],
  A02: ["Cryptographic Failures", "A02_2021-Cryptographic_Failures"],
  A03: ["Injection", "A03_2021-Injection"],
  A04: ["Insecure Design", "A04_2021-Insecure_Design"],
  A05: ["Security Misconfiguration", "A05_2021-Security_Misconfiguration"],
  A06: [
    "Vulnerable and Outdated Components",
    "A06_2021-Vulnerable_and_Outdated_Components",
  ],
  A07: [
    "Identification and Authentication Failures",
    "A07_2021-Identification_and_Authentication_Failures",
  ],
  A08: [
    "Software and Data Integrity Failures",
    "A08_2021-Software_and_Data_Integrity_Failures",
  ],
  A09: [
    "Security Logging and Monitoring Failures",
    "A09_2021-Security_Logging_and_Monitoring_Failures",
  ],
  A10: [
    "Server-Side Request Forgery",
    "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
  ],
};

const API_2023: Record<string, [string, string]> = {
  API1: [
    "Broken Object Level Authorization",
    "0xa1-broken-object-level-authorization",
  ],
  API2: ["Broken Authentication", "0xa2-broken-authentication"],
  API3: [
    "Broken Object Property Level Authorization",
    "0xa3-broken-object-property-level-authorization",
  ],
  API4: [
    "Unrestricted Resource Consumption",
    "0xa4-unrestricted-resource-consumption",
  ],
  API5: [
    "Broken Function Level Authorization",
    "0xa5-broken-function-level-authorization",
  ],
  API6: [
    "Unrestricted Access to Sensitive Business Flows",
    "0xa6-unrestricted-access-to-sensitive-business-flows",
  ],
  API7: ["Server Side Request Forgery", "0xa7-server-side-request-forgery"],
  API8: ["Security Misconfiguration", "0xa8-security-misconfiguration"],
  API9: ["Improper Inventory Management", "0xa9-improper-inventory-management"],
  API10: ["Unsafe Consumption of APIs", "0xaa-unsafe-consumption-of-apis"],
};

/** "A05:2021" or "API8:2023" -> name and owasp.org page. */
export function owaspLink(id: string): StandardLink {
  const [code, year] = id.trim().toUpperCase().split(":");
  if (year === "2021" && TOP10_2021[code]) {
    const [name, slug] = TOP10_2021[code];
    return { id, name, url: `https://owasp.org/Top10/${slug}/` };
  }
  if (year === "2023" && API_2023[code]) {
    const [name, slug] = API_2023[code];
    return {
      id,
      name,
      url: `https://owasp.org/API-Security/editions/2023/en/${slug}/`,
    };
  }
  return { id, name: null, url: null };
}

/** "CWE-319" -> cwe.mitre.org definition page. */
export function cweLink(id: string): StandardLink {
  const number = /^CWE-(\d+)$/i.exec(id.trim())?.[1];
  return {
    id,
    name: null,
    url: number
      ? `https://cwe.mitre.org/data/definitions/${number}.html`
      : null,
  };
}
