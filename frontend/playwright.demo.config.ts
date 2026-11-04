import { defineConfig, devices } from "@playwright/test";

// Records the demo: one video of the whole flow plus the screenshots used in
// the README and the report (docs/screenshots/). Not part of the test suite.
//
//   npm run demo:record                 # mock API (MSW), no backend needed
//   DEMO_REAL=1 npm run demo:record     # through the real API on :8000
//
// The video is written to demo-output/ (git-ignored); the screenshots go
// straight to docs/screenshots/ and are committed.
const PORT = Number(
  process.env.E2E_PORT ?? (process.env.DEMO_REAL ? 3000 : 3200),
);
const baseURL = process.env.E2E_BASE_URL ?? `http://localhost:${PORT}`;
const real = process.env.DEMO_REAL === "1";

export default defineConfig({
  testDir: "./e2e/demo",
  outputDir: "./demo-output",
  timeout: real ? 25 * 60_000 : 120_000,
  retries: 0,
  workers: 1,
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL,
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    colorScheme: "light",
    video: { mode: "on", size: { width: 1280, height: 800 } },
    // Slow enough for a viewer to follow each step.
    launchOptions: { slowMo: Number(process.env.DEMO_SLOWMO ?? 250) },
  },
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: "npm run build && npm run start",
        env: {
          PORT: String(PORT),
          NEXT_PUBLIC_USE_MOCK: real ? "false" : "true",
          NEXT_PUBLIC_API_URL:
            process.env.E2E_API_URL ?? "http://localhost:8000",
        },
        url: baseURL,
        reuseExistingServer: false,
        timeout: 180_000,
      },
});
