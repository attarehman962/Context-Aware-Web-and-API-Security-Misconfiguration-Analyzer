import { describe, expect, it } from "vitest";

import nextConfig from "../../next.config";
import { SECURITY_HEADERS } from "./security-headers";

const byKey = Object.fromEntries(SECURITY_HEADERS.map((h) => [h.key, h.value]));

describe("security headers (security review SEC-08)", () => {
  it("forbids framing, sniffing and referrers", () => {
    expect(byKey["Content-Security-Policy"]).toContain(
      "frame-ancestors 'none'",
    );
    expect(byKey["Content-Security-Policy"]).toContain("object-src 'none'");
    expect(byKey["X-Content-Type-Options"]).toBe("nosniff");
    expect(byKey["Referrer-Policy"]).toBe("no-referrer");
    expect(byKey["X-Frame-Options"]).toBe("DENY");
  });

  it("is sent on every route", async () => {
    const rules = await nextConfig.headers!();
    expect(rules).toEqual([{ source: "/:path*", headers: SECURITY_HEADERS }]);
  });
});
