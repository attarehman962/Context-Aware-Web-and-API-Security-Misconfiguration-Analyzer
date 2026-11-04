// The results page stays smooth with a large scan: the mock's 600-finding
// scan (src/mocks/large-scan.ts). Budgets are generous for a CI runner;
// they catch regressions such as un-virtualising the list, not milliseconds.
import { expect, test, type Page } from "@playwright/test";

const LARGE = "/scans/55555555-5555-4555-8555-555555555555";

/** Records main-thread tasks over 50 ms (the browser's "long task"). */
async function watchLongTasks(page: Page) {
  await page.evaluate(() => {
    const w = window as unknown as { __longTasks: number[] };
    w.__longTasks = [];
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) w.__longTasks.push(entry.duration);
    }).observe({ type: "longtask", buffered: false });
  });
  return async () =>
    page.evaluate(
      () => (window as unknown as { __longTasks: number[] }).__longTasks,
    );
}

test.describe("600 findings", () => {
  test("renders, scrolls, filters and opens a finding without jank", async ({
    page,
  }) => {
    const start = Date.now();
    await page.goto(LARGE);
    await page.locator("article[data-check-id]").first().waitFor();
    const firstRows = Date.now() - start;
    expect(firstRows, "time to first rows (ms)").toBeLessThan(5_000);

    // Only the rows in view are in the DOM.
    const rendered = await page.locator("article[data-check-id]").count();
    expect(rendered).toBeLessThan(40);
    await expect(page.getByText("Showing 600 of 600 findings")).toBeVisible();

    const longTasks = await watchLongTasks(page);
    for (let i = 0; i < 40; i += 1) {
      await page.mouse.wheel(0, 1200);
      await page.waitForTimeout(16);
    }
    await page.evaluate(() =>
      window.scrollTo(0, document.documentElement.scrollHeight),
    );
    await page.waitForTimeout(300);
    await expect(
      page.locator('article[data-rank="600"]'),
      "the last finding is reachable",
    ).toBeVisible();
    const scrollTasks = await longTasks();
    expect(
      Math.max(0, ...scrollTasks),
      "longest main-thread task while scrolling (ms)",
    ).toBeLessThan(200);

    await page.evaluate(() => window.scrollTo(0, 0));
    const filterStart = Date.now();
    await page.getByRole("checkbox", { name: /Critical/ }).check();
    await expect(
      page.getByText(/^Showing \d+ of 600 findings$/),
    ).not.toHaveText("Showing 600 of 600 findings");
    expect(Date.now() - filterStart, "filter applied (ms)").toBeLessThan(1_500);

    const openStart = Date.now();
    await page
      .locator("article[data-check-id] button[aria-expanded]")
      .first()
      .click();
    await page.getByText("CVSS v3.1 vector").first().waitFor();
    const opened = Date.now() - openStart;
    // Shown in the test output, for comparing runs.
    console.log(
      `600 findings: first rows ${firstRows} ms, ${rendered} rows in DOM, ` +
        `longest scroll task ${Math.round(Math.max(0, ...scrollTasks))} ms ` +
        `(${scrollTasks.length} long tasks), drill-down ${opened} ms`,
    );
    expect(Date.now() - openStart, "drill-down opened (ms)").toBeLessThan(
      3_000,
    );
  });
});
