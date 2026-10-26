// End to end against the real stack: the UI starts a scan of Atta's demo
// target, the API scans it, and the results page shows the HSTS finding.
// Run with `npm run test:e2e:real` (see scripts/e2e-real.mjs).
import { expect, test } from "@playwright/test";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
// docker-compose.demo.yml: an HTTPS server with every security header except
// HSTS, reachable by that name from the api container.
const TARGET_URL = process.env.E2E_TARGET_URL ?? "https://demo-target:8443/";

test.beforeAll(async ({ request }) => {
  const health = await request.get(`${API_URL}/health`).catch(() => null);
  expect(
    health?.ok(),
    `CAWASMA API not reachable at ${API_URL}. Start it with: docker compose ` +
      "-f docker-compose.yml -f docker-compose.demo.yml up -d --build --wait",
  ).toBe(true);
});

test("scan the demo target and see the missing-HSTS finding", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByRole("contentinfo")).toContainText("API: live");

  await page.getByLabel("Target URL").fill(TARGET_URL);
  await page.getByRole("checkbox", { name: /I own this target/ }).check();
  await page.getByRole("button", { name: "Start scan" }).click();

  await page.waitForURL(/\/scans\/[0-9a-f-]{36}$/);
  await expect(
    page.getByRole("heading", { level: 1, name: TARGET_URL }),
  ).toBeVisible();

  // The demo scan takes a few seconds (longer on a cold api container).
  // Next keeps the previous page mounted but hidden, so only look at what
  // is visible.
  const status = page
    .getByRole("main")
    .locator("[data-status]")
    .filter({ visible: true });
  await expect(status).toHaveAttribute("data-status", "DONE", {
    timeout: 150_000,
  });

  const hsts = page.locator('tr[data-check-id="HDR-001"]');
  await expect(hsts).toBeVisible();
  await expect(hsts).toContainText("Missing HSTS");
  await expect(hsts.locator("[data-severity]")).toHaveText(/Medium/);
  await expect(hsts).toContainText("5.3");
});
