// The frontend's definition of done, checked against the real backend: enter
// a URL, confirm authorisation, watch the scan run, read the ranked report,
// expand a finding to see why it scored as it did, view history, export.
// Each item is its own step, so the report says which one failed.
//
//   E2E_TARGET_URL=https://demo-target:8443/ npm run test:e2e:real -- definition-of-done
import { readFile } from "node:fs/promises";

import { expect, test, type Page } from "@playwright/test";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TARGET_URL = process.env.E2E_TARGET_URL ?? "https://demo-target:8443/";

test.describe.configure({ timeout: 25 * 60_000 });

async function exportAs(page: Page, item: RegExp) {
  const download = page.waitForEvent("download", { timeout: 120_000 });
  await page.getByRole("button", { name: /^Export/ }).click();
  await page.getByRole("menuitem", { name: item }).click();
  return download;
}

test(`definition of done on ${TARGET_URL}`, async ({ page, request }) => {
  const main = page.getByRole("main");
  let scanId = "";

  await test.step("1. Enter a URL", async () => {
    await page.goto("/");
    await expect(page.getByRole("contentinfo")).toContainText("API: live");
    await page.getByLabel("Target URL").fill(TARGET_URL);
    await expect(page.getByLabel("Target URL")).toHaveValue(TARGET_URL);
  });

  await test.step("2. Confirm authorisation", async () => {
    const start = page.getByRole("button", { name: "Start scan" });
    await expect(start).toBeDisabled();
    await page.getByRole("checkbox", { name: /I own this target/ }).check();
    await expect(start).toBeEnabled();
    await start.click();
    await page.waitForURL(/\/scans\/[0-9a-f-]{36}$/);
    scanId = page.url().split("/").pop()!;
  });

  await test.step("3. Watch the scan run", async () => {
    // A short scan can finish before the page paints its progress; the
    // results then show a finished scan, which also passes.
    await expect(
      main
        .getByRole("list", { name: "Steps" })
        .or(main.getByRole("heading", { name: "Findings" })),
    ).toBeVisible({ timeout: 60_000 });
    // Stop at the first terminal state rather than waiting out the timeout.
    const failed = main.getByText("The scan failed");
    await expect(
      main.getByRole("heading", { name: "Findings" }).or(failed),
    ).toBeVisible({ timeout: 20 * 60_000 });
    expect(
      await failed.isVisible(),
      `scan failed: ${await main.textContent()}`,
    ).toBe(false);
    await expect(
      main.locator("[data-status]").filter({ visible: true }).first(),
    ).toHaveAttribute("data-status", "DONE");
  });

  await test.step("4. Read the ranked report", async () => {
    const rows = main.locator("article[data-check-id]");
    await expect(rows.first()).toBeVisible();
    const results = await (
      await request.get(`${API_URL}/api/results/${scanId}`)
    ).json();
    const scores: number[] = results.findings.map(
      (f: { final_score: number }) => f.final_score,
    );
    const top = [...scores].sort((a, b) => b - a)[0];
    await expect(rows.first()).toContainText(top.toFixed(1));
  });

  await test.step("5. Expand a finding to see why it scored as it did", async () => {
    const first = main.locator("article[data-check-id]").first();
    await first.locator("button[aria-expanded]").click();
    await expect(first.getByTestId("score-story")).toHaveText(
      /^(Raised|Lowered) from \d+\.\d to \d+\.\d|^Unchanged at \d+\.\d/,
      { timeout: 30_000 },
    );
    await expect(first.getByText("CVSS v3.1 vector")).toBeVisible();
  });

  await test.step("6. View history", async () => {
    await page
      .getByRole("navigation", { name: "Main" })
      .getByRole("link", { name: "History" })
      .click();
    const link = page.locator(`a[href="/scans/${scanId}"]`);
    await expect(link).toBeVisible();
    await link.click();
    await expect(main.getByRole("heading", { name: "Findings" })).toBeVisible();
  });
  await test.step("7. Export", async () => {
    for (const [item, ext, check] of [
      [
        /^JSON/,
        "json",
        (b: Buffer) => JSON.parse(b.toString()).scan.scan_id === scanId,
      ],
      [/^CSV/, "csv", (b: Buffer) => b.toString().startsWith("id,check_id,")],
      [/^HTML/, "html", (b: Buffer) => /<html/i.test(b.toString())],
      [
        /^PDF report/,
        "pdf",
        (b: Buffer) => b.subarray(0, 5).toString() === "%PDF-",
      ],
    ] as const) {
      const download = await exportAs(page, item);
      expect(download.suggestedFilename()).toMatch(
        new RegExp(`^cawasma-.+-\\d{4}-\\d{2}-\\d{2}\\.${ext}$`),
      );
      expect(check(await readFile((await download.path())!)), ext).toBe(true);
    }
  });
});
