// The whole user journey against the real stack and a real evaluation
// target: new scan -> live status -> results -> filter -> drill-down ->
// export. Default target: VAmPI behind the eval TLS front, started by
// scripts/eval-stack.sh. Run with:
//   E2E_TARGET_URL=https://vampi-tls/ npm run test:e2e:real -- eval-flow
import { readFile } from "node:fs/promises";

import { expect, test, type Download, type Page } from "@playwright/test";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TARGET_URL = process.env.E2E_TARGET_URL ?? "https://vampi-tls/";
const TARGET_HOST = new URL(TARGET_URL).host;
// The harness gives a CAWASMA scan 20 minutes (eval/harness/run_all.py).
const SCAN_TIMEOUT = 20 * 60_000;

test.describe.configure({ mode: "serial", timeout: SCAN_TIMEOUT + 5 * 60_000 });

test.beforeAll(async ({ request }) => {
  const health = await request.get(`${API_URL}/health`).catch(() => null);
  expect(
    health?.ok(),
    `CAWASMA API not reachable at ${API_URL}. Start the stack with: ` +
      "bash frontend/scripts/eval-stack.sh",
  ).toBe(true);
});

async function exportAs(page: Page, item: RegExp): Promise<Download> {
  const download = page.waitForEvent("download", { timeout: 120_000 });
  await page.getByRole("button", { name: /^Export/ }).click();
  await page.getByRole("menuitem", { name: item }).click();
  return download;
}

test(`full flow on ${TARGET_URL}`, async ({ page }) => {
  // 1. New scan.
  await page.goto("/");
  await expect(page.getByRole("contentinfo")).toContainText("API: live");
  await page.getByLabel("Target URL").fill(TARGET_URL);
  await page.getByRole("checkbox", { name: /I own this target/ }).check();
  await page.getByRole("button", { name: "Start scan" }).click();
  await page.waitForURL(/\/scans\/[0-9a-f-]{36}$/);
  const scanId = page.url().split("/").pop()!;

  // 2. Live status: the SSE stream drives the steps and counts.
  const main = page.getByRole("main");
  await expect(
    main.locator("[data-live-mode]").filter({ visible: true }),
  ).toHaveAttribute("data-live-mode", "live", { timeout: 60_000 });
  await expect(main.getByRole("list", { name: "Steps" })).toBeVisible();
  await expect(main.getByTestId("endpoints-found")).toHaveText(/^\d+$/, {
    timeout: 120_000,
  });

  // 3. Results.
  await expect(main.getByRole("heading", { name: "Findings" })).toBeVisible({
    timeout: SCAN_TIMEOUT,
  });
  await expect(
    main.locator("[data-status]").filter({ visible: true }).first(),
  ).toHaveAttribute("data-status", "DONE");
  const rows = main.locator("article[data-check-id]");
  await expect(rows.first()).toBeVisible();
  const summary = await main
    .getByText(/^Showing \d+ of \d+ findings?$/)
    .textContent();
  const total = Number(/of (\d+)/.exec(summary ?? "")?.[1]);
  expect(total, "the scan found something").toBeGreaterThan(0);

  // 4. Filter by the first category in the scan, then clear.
  const category = main.getByLabel("Category");
  const firstCategory = await category
    .locator("option")
    .nth(1)
    .getAttribute("value");
  await category.selectOption(firstCategory!);
  await expect(page).toHaveURL(new RegExp(`category=${firstCategory}`));
  const shown = Number(
    /Showing (\d+)/.exec(
      (await main.getByText(/^Showing \d+ of \d+ findings?$/).textContent()) ??
        "",
    )?.[1],
  );
  expect(shown).toBeGreaterThan(0);
  expect(shown).toBeLessThanOrEqual(total);
  await main.getByRole("button", { name: "Clear filters" }).first().click();
  await expect(
    main.getByText(`Showing ${total} of ${total}`, { exact: false }),
  ).toBeVisible();

  // 5. Drill-down: why the first finding scored as it did.
  const first = rows.first();
  await first.locator("button[aria-expanded]").click();
  await expect(first.getByTestId("score-story")).toHaveText(
    /^(Raised|Lowered) from \d+\.\d to \d+\.\d|^Unchanged at \d+\.\d/,
    { timeout: 30_000 },
  );
  await expect(first.getByText("CVSS v3.1 vector")).toBeVisible();
  await expect(
    first.getByRole("link", { name: /Verify the base score/ }),
  ).toHaveAttribute(
    "href",
    /^https:\/\/www\.first\.org\/cvss\/calculator\/3\.1#CVSS:3\.1\//,
  );

  // 6. Export: named after the target and date; contents match the scan.
  const name = new RegExp(
    `^cawasma-${TARGET_HOST.replace(/[^a-z0-9.-]+/g, "-").replace(/\./g, "\\.")}-\\d{4}-\\d{2}-\\d{2}\\.`,
  );
  const json = await exportAs(page, /^JSON/);
  expect(json.suggestedFilename()).toMatch(new RegExp(name.source + "json$"));
  const exported = JSON.parse(await readFile((await json.path())!, "utf8"));
  expect(exported.scan.scan_id).toBe(scanId);
  expect(exported.findings).toHaveLength(total);

  const csv = await exportAs(page, /^CSV/);
  expect(csv.suggestedFilename()).toMatch(new RegExp(name.source + "csv$"));
  const lines = (await readFile((await csv.path())!, "utf8"))
    .trim()
    .split(/\r?\n/);
  expect(lines[0]).toMatch(/^id,check_id,title,category,severity_bucket,/);
  expect(lines).toHaveLength(total + 1);

  const pdf = await exportAs(page, /^PDF report/);
  expect(pdf.suggestedFilename()).toMatch(new RegExp(name.source + "pdf$"));
  const head = (await readFile((await pdf.path())!)).subarray(0, 5).toString();
  expect(head).toBe("%PDF-");
});
