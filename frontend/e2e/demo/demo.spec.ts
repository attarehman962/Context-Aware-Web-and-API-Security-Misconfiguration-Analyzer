// The demo flow, recorded as a video, with a screenshot at each step for the
// README and the report. Run with `npm run demo:record` (playwright.demo.config.ts).
import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

const SHOTS = path.resolve(__dirname, "../../../docs/screenshots");
const VIDEO = path.resolve(__dirname, "../../demo-output/cawasma-demo.webm");
const real = process.env.DEMO_REAL === "1";
const TARGET =
  process.env.E2E_TARGET_URL ??
  (real ? "https://demo-target:8443/" : "https://shop.example.com/");

async function shot(page: Page, name: string, fullPage = false) {
  // Let transitions settle so the picture is the final state.
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage });
}

test.beforeAll(async () => {
  await mkdir(SHOTS, { recursive: true });
});

test("demo flow", async ({ page }) => {
  const main = page.getByRole("main");

  // 1. Enter the target and confirm authorisation.
  await page.goto("/");
  await page.getByLabel("Target URL").pressSequentially(TARGET, { delay: 40 });
  await page.getByRole("checkbox", { name: /I own this target/ }).check();
  await shot(page, "01-new-scan");
  await page.getByRole("button", { name: "Start scan" }).click();
  await page.waitForURL(/\/scans\/[0-9a-f-]{36}$/);

  // 2. Watch it run.
  await expect(main.getByRole("list", { name: "Steps" })).toBeVisible();
  await expect(main.getByTestId("endpoints-found")).toHaveText(/^[1-9]\d*$/, {
    timeout: real ? 120_000 : 30_000,
  });
  await shot(page, "02-live-scan");

  // 3. The ranked report.
  await expect(main.getByRole("heading", { name: "Findings" })).toBeVisible({
    timeout: real ? 20 * 60_000 : 60_000,
  });
  await expect(main.locator("article[data-check-id]").first()).toBeVisible();
  await shot(page, "03-results");

  // 4. Why the top finding scored as it did.
  const first = main.locator("article[data-check-id]").first();
  await first.locator("button[aria-expanded]").click();
  await expect(first.getByTestId("score-story")).toBeVisible();
  await first.scrollIntoViewIfNeeded();
  await shot(page, "04-finding-detail");
  await first.locator("button[aria-expanded]").click();

  // 5. Filter by severity.
  await page.evaluate(() => window.scrollTo(0, 0));
  const critical = main.getByRole("checkbox", { name: /critical/i });
  if (await critical.count()) {
    await critical.first().check();
    await shot(page, "05-filtered");
    await critical.first().uncheck();
  }

  // 6. Export.
  await page.getByRole("button", { name: /^Export/ }).click();
  await expect(
    page.getByRole("menuitem", { name: /^PDF report/ }),
  ).toBeVisible();
  await shot(page, "06-export-menu");
  const download = page.waitForEvent("download", { timeout: 120_000 });
  await page.getByRole("menuitem", { name: /^PDF report/ }).click();
  await download;

  // 7. History.
  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "History" })
    .click();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await shot(page, "07-history");

  // 8. Evaluation.
  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "Evaluation" })
    .click();
  await expect(
    page.getByRole("heading", { level: 1, name: "Evaluation" }),
  ).toBeVisible();
  await shot(page, "08-evaluation", true);
  await page.mouse.wheel(0, 900);
  await page.waitForTimeout(800);
  await page.mouse.wheel(0, 900);
  await page.waitForTimeout(800);

  // Dark mode, for the report. Back twice (client-side, so the mock's
  // simulated scan survives) to the results.
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goBack();
  await page.goBack();
  await expect(main.getByRole("heading", { name: "Findings" })).toBeVisible();
  await shot(page, "09-results-dark");
});

test.afterEach(async ({ page }) => {
  // The video is complete only once the page closes.
  const video = page.video();
  await page.close();
  if (video) await copyFile(await video.path(), VIDEO);
});
