import { defineConfig, devices } from "@playwright/test";

// E2E tests run against a production build (`next build` + the standalone
// server, as in the Docker image).
// Set E2E_BASE_URL to test an already-running app instead, e.g. the
// docker compose frontend: E2E_BASE_URL=http://localhost:3000 npm run test:e2e
//
// The `real-stack` project scans Atta's demo target through the real API and
// runs only via `npm run test:e2e:real` (scripts/e2e-real.mjs), which serves
// the app on :3000 (allowed by the API's CORS list) against the live API.
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
          testMatch: /real-stack\.spec\.ts/,
          timeout: 180_000,
          use: { ...devices["Desktop Chrome"] },
        },
      ]
    : [
        {
          name: "chromium",
          testIgnore: /real-stack\.spec\.ts/,
          use: { ...devices["Desktop Chrome"] },
        },
      ],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: "npm run build && npm run start",
        env: { PORT: String(PORT) },
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      },
});
