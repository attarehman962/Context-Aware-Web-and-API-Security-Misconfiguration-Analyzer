import { http, HttpResponse } from "msw";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  DONE_SCAN_ID,
  FAILED_SCAN_ID,
  RUNNING_SCAN_ID,
} from "@/mocks/fixtures";
import { createMockServer } from "@/mocks/node";
import { QUEUED_MS, SCAN_DURATION_MS } from "@/mocks/scenario";

import {
  createScan,
  getExportUrl,
  getFindingDetail,
  getResults,
  type ApiResult,
} from "./api";

const T0 = Date.parse("2026-10-26T10:00:00Z");
let clock = T0;
const server = createMockServer({ now: () => clock });

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  clock = T0;
});
afterAll(() => server.close());

const UNKNOWN_ID = "99999999-9999-4999-8999-999999999999";

function expectOk<T>(result: ApiResult<T>): T {
  if (!result.ok)
    throw new Error(`expected ok, got ${JSON.stringify(result.error)}`);
  return result.data;
}

function expectError<T>(result: ApiResult<T>) {
  if (result.ok) throw new Error("expected an error result");
  return result.error;
}

describe("createScan", () => {
  it("queues a scan with the contract defaults", async () => {
    const scan = expectOk(
      await createScan({
        url: "https://target.example",
        authorisation_confirmed: true,
      }),
    );
    expect(scan.status).toBe("QUEUED");
    expect(scan.progress).toBe(0);
    expect(scan.url).toBe("https://target.example");
    expect(scan.options).toEqual({
      crawl_depth: 2,
      use_wordlist: true,
      passive_only: false,
    });
  });

  it("rejects a non-HTTPS target with INVALID_TARGET (400)", async () => {
    const error = expectError(
      await createScan({
        url: "http://target.example",
        authorisation_confirmed: true,
      }),
    );
    expect(error).toMatchObject({
      kind: "client",
      status: 400,
      code: "INVALID_TARGET",
      message: "Only HTTPS targets are allowed.",
    });
  });

  it("reports field details when authorisation is not confirmed (422)", async () => {
    const error = expectError(
      await createScan({
        url: "https://target.example",
        authorisation_confirmed: false as true,
      }),
    );
    expect(error.kind).toBe("client");
    if (error.kind === "network") return;
    expect(error.code).toBe("VALIDATION_ERROR");
    expect(error.details?.map((d) => d.loc)).toEqual([
      ["body", "authorisation_confirmed"],
    ]);
  });

  it("rejects unknown fields and an out-of-range crawl depth (422)", async () => {
    const error = expectError(
      await createScan({
        url: "https://target.example",
        authorisation_confirmed: true,
        crawl_depth: 3,
        cookies: "x",
      } as never),
    );
    if (error.kind === "network") throw new Error("unexpected network error");
    expect(error.details?.map((d) => d.type).sort()).toEqual([
      "extra_forbidden",
      "literal_error",
    ]);
  });
});

describe("getResults", () => {
  it("returns the DONE example ranked by final_score", async () => {
    const results = expectOk(await getResults(DONE_SCAN_ID));
    expect(results.scan.status).toBe("DONE");
    const scores = results.findings.map((f) => f.final_score);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(results.chains.map((c) => c.chain_code)).toEqual(["C005", "C002"]);
  });

  it("returns the RUNNING and FAILED examples", async () => {
    const running = expectOk(await getResults(RUNNING_SCAN_ID));
    expect(running.scan).toMatchObject({ status: "RUNNING", progress: 45 });
    expect(running.findings).toEqual([]);

    const failed = expectOk(await getResults(FAILED_SCAN_ID));
    expect(failed.scan.status).toBe("FAILED");
    expect(failed.scan.error).toMatch(/unreachable/);
  });

  it("returns NOT_FOUND (404) for an unknown id", async () => {
    expect(expectError(await getResults(UNKNOWN_ID))).toMatchObject({
      kind: "client",
      status: 404,
      code: "NOT_FOUND",
    });
  });

  it("returns VALIDATION_ERROR (422) for an id that is not a UUID", async () => {
    expect(expectError(await getResults("not-a-uuid"))).toMatchObject({
      status: 422,
      code: "VALIDATION_ERROR",
    });
  });
});

describe("simulated scan", () => {
  it("moves QUEUED -> RUNNING -> DONE over the scan duration", async () => {
    const { scan_id } = expectOk(
      await createScan({
        url: "https://target.example",
        authorisation_confirmed: true,
        passive_only: true,
      }),
    );

    expect(expectOk(await getResults(scan_id)).scan.status).toBe("QUEUED");

    clock = T0 + QUEUED_MS + 1_000;
    const running = expectOk(await getResults(scan_id));
    expect(running.scan.status).toBe("RUNNING");
    expect(running.scan.progress).toBeGreaterThan(0);
    expect(running.scan.progress).toBeLessThan(100);
    expect(running.findings).toEqual([]);

    clock = T0 + SCAN_DURATION_MS - 1;
    const later = expectOk(await getResults(scan_id));
    expect(later.scan.progress).toBeGreaterThan(running.scan.progress);

    clock = T0 + SCAN_DURATION_MS;
    const done = expectOk(await getResults(scan_id));
    expect(done.scan).toMatchObject({
      scan_id,
      status: "DONE",
      progress: 100,
      url: "https://target.example",
      options: { passive_only: true },
    });
    expect(new Set(done.findings.map((f) => f.severity_bucket))).toEqual(
      new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    );
    expect(done.findings.some((f) => f.chain_ids.length > 0)).toBe(true);
    expect(done.findings.some((f) => f.body_signals.length > 0)).toBe(true);
    for (const f of done.findings) {
      if (f.endpoint_url)
        expect(f.endpoint_url).toMatch(/^https:\/\/target\.example\//);
    }
  });
});

describe("error handling", () => {
  it("returns a network error when the API cannot be reached", async () => {
    server.use(http.get("*/api/results/:id", () => HttpResponse.error()));
    expect(expectError(await getResults(DONE_SCAN_ID))).toEqual({
      kind: "network",
      message: expect.stringContaining("Could not reach"),
    });
  });

  it("returns a server error with the envelope's code on 5xx", async () => {
    server.use(
      http.get("*/api/results/:id", () =>
        HttpResponse.json(
          {
            success: false,
            error: { code: "INTERNAL_ERROR", message: "Something broke." },
          },
          { status: 500 },
        ),
      ),
    );
    expect(expectError(await getResults(DONE_SCAN_ID))).toEqual({
      kind: "server",
      status: 500,
      code: "INTERNAL_ERROR",
      message: "Something broke.",
    });
  });

  it("returns UNKNOWN when an error body is not the envelope", async () => {
    server.use(
      http.get(
        "*/api/results/:id",
        () => new HttpResponse("Bad Gateway", { status: 502 }),
      ),
    );
    expect(expectError(await getResults(DONE_SCAN_ID))).toMatchObject({
      kind: "server",
      status: 502,
      code: "UNKNOWN",
    });
  });

  it("treats a 2xx body that is not JSON as a server error", async () => {
    server.use(http.get("*/api/results/:id", () => new HttpResponse("<html>")));
    expect(expectError(await getResults(DONE_SCAN_ID))).toMatchObject({
      kind: "server",
      code: "UNKNOWN",
    });
  });

  it("rejects with AbortError when the request is cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      getResults(DONE_SCAN_ID, { signal: controller.signal }),
    ).rejects.toMatchObject({
      name: "AbortError",
    });
  });
});

describe("getExportUrl", () => {
  it("builds the export link, defaulting to JSON", () => {
    expect(getExportUrl(DONE_SCAN_ID)).toBe(
      `http://localhost:8000/api/results/${DONE_SCAN_ID}/export?format=json`,
    );
    expect(getExportUrl(DONE_SCAN_ID, "csv")).toMatch(/\/export\?format=csv$/);
  });

  it("serves a CSV with the contract's columns for a DONE scan", async () => {
    const response = await fetch(getExportUrl(DONE_SCAN_ID, "csv"));
    expect(response.headers.get("Content-Disposition")).toBe(
      `attachment; filename="cawasma-${DONE_SCAN_ID}.csv"`,
    );
    const [header, ...rows] = (await response.text()).trim().split("\r\n");
    expect(header).toBe(
      "id,check_id,title,category,severity_bucket,final_score,base_score,cvss_vector," +
        "sensitivity_class,body_signals,owasp_map,cwe_map,endpoint_url,chain_ids",
    );
    expect(rows).toHaveLength(10);
  });

  it("answers 409 before DONE", async () => {
    expect((await fetch(getExportUrl(RUNNING_SCAN_ID))).status).toBe(409);
  });

  it("serves a PDF, as the real API does", async () => {
    const response = await fetch(getExportUrl(DONE_SCAN_ID, "pdf"));
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/pdf");
    expect(await response.text()).toMatch(/^%PDF-/);
  });
});

describe("getResults with filters (contract 1.2)", () => {
  it("filters, pages and reports findings_meta; counts stay whole-scan", async () => {
    const results = expectOk(
      await getResults(DONE_SCAN_ID, {
        query: {
          severity: ["MEDIUM", "LOW"],
          in_chain: true,
          page: 1,
          limit: 1,
        },
      }),
    );
    expect(results.findings.map((f) => f.check_id)).toEqual(["HDR-007"]);
    expect(results.findings_meta).toEqual({
      total: 2,
      page: 1,
      limit: 1,
      pages: 2,
      filters: { severity: ["LOW", "MEDIUM"], in_chain: true },
    });
    expect(results.scan.severity_counts.medium).toBe(4);
    expect(results.chains).toHaveLength(2);
  });

  it("returns the 1.1 body without parameters", async () => {
    const results = expectOk(await getResults(DONE_SCAN_ID));
    expect(results.findings_meta).toBeNull();
    expect(results.findings).toHaveLength(10);
  });

  it("rejects an unknown severity (422)", async () => {
    expect(
      expectError(
        await getResults(DONE_SCAN_ID, {
          query: { severity: ["URGENT" as never] },
        }),
      ),
    ).toMatchObject({ status: 422, code: "VALIDATION_ERROR" });
  });
});

describe("getFindingDetail (contract 1.2)", () => {
  const CHAIN_MEMBER = "f0000000-0000-4000-8000-00000000000a"; // INF-007

  it("returns the finding with endpoint, check text and chains", async () => {
    const detail = expectOk(await getFindingDetail(DONE_SCAN_ID, CHAIN_MEMBER));
    expect(detail.check_id).toBe("INF-007");
    expect(detail.endpoint).toMatchObject({
      path: "/api/v1/orders",
      method: "GET",
      status_code: 500,
      sensitivity_class: "MEDIUM",
      sensitivity_reason: ["Contains generic API/data tokens"],
    });
    expect(detail.chains.map((c) => c.chain_code)).toEqual(["C002"]);
    expect(detail.chains[0].finding_ids).toHaveLength(2);
    expect(detail.description).toMatch(/development error page/);
  });

  it("has no endpoint for a host-level finding", async () => {
    const tls = "f0000000-0000-4000-8000-000000000004";
    expect(
      expectOk(await getFindingDetail(DONE_SCAN_ID, tls)).endpoint,
    ).toBeNull();
  });

  it("returns NOT_FOUND for a finding outside the scan", async () => {
    expect(
      expectError(await getFindingDetail(DONE_SCAN_ID, UNKNOWN_ID)),
    ).toMatchObject({ status: 404, code: "NOT_FOUND" });
  });

  it("returns VALIDATION_ERROR for an id that is not a UUID", async () => {
    expect(
      expectError(await getFindingDetail(DONE_SCAN_ID, "not-a-uuid")),
    ).toMatchObject({ status: 422, code: "VALIDATION_ERROR" });
  });
});
