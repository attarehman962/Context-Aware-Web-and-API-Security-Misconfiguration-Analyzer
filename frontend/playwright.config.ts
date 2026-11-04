import { defineConfig, devices } from "@playwright/test";

// E2E tests run against a production build (`next build` + the standalone
// server, as in the Docker image).
// Set E2E_BASE_URL to test an already-running app instead, e.g. the
// docker compose frontend: E2E_BASE_URL=http://localhost:3000 npm run test:e2e
//
// `npm run test:e2e` builds the app in mock mode (MSW, no backend), so every
// page has data for the flows and the axe accessibility checks.
//
// The `real-stack` project scans through the real API and runs only via
// `npm run test:e2e:real` (scripts/e2e-real.mjs), which serves the app on
// :3000 (allowed by the API's CORS list) against the live API.
const PORT = Number(process.env.E2E_PORT ?? 3100);
const baseURL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;
const realStack = process.env.E2E_REAL_STACK === "1";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  projects: realStack
    ? [
        {
          name: "real-stack",
          // Demo target (real-stack), the full flow on an eval target
          // (eval-flow) and the definition of done; the last two set their
          // own longer timeouts.
          testMatch: /(real-stack|eval-flow|definition-of-done)\.spec\.ts/,
          timeout: 180_000,
          // A retry would re-run a scan of up to 20 minutes; fail fast instead.
          retries: 0,
          use: { ...devices["Desktop Chrome"] },
        },
      ]
    : [
        {
          name: "chromium",
          // e2e/demo/ is the demo recorder (playwright.demo.config.ts).
          testIgnore: [
            /(real-stack|eval-flow|definition-of-done)\.spec\.ts/,
            /[\\/]demo[\\/]/,
          ],
          use: { ...devices["Desktop Chrome"] },
        },
      ],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: "npm run build && npm run start",
        env: {
          PORT: String(PORT),
          NEXT_PUBLIC_USE_MOCK: realStack ? "false" : "true",
        },
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      },
});
