// Runs the real-stack e2e test (e2e/real-stack.spec.ts) against a running
// CAWASMA API with Atta's demo target:
//
//   docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build --wait
//   npm run test:e2e:real
//
// The app is built in live mode (never the MSW mock) and served on :3000,
// which the API's default FRONTEND_ORIGIN allows. Override with E2E_PORT and
// E2E_API_URL; E2E_TARGET_URL changes the scanned target.
import { spawn } from "node:child_process";

const env = {
  ...process.env,
  E2E_REAL_STACK: "1",
  E2E_PORT: process.env.E2E_PORT ?? "3000",
  NEXT_PUBLIC_API_URL: process.env.E2E_API_URL ?? "http://localhost:8000",
  NEXT_PUBLIC_USE_MOCK: "false",
};

const child = spawn("npx", ["playwright", "test", ...process.argv.slice(2)], {
  env,
  stdio: "inherit",
  shell: process.platform === "win32",
});
child.on("exit", (code) => process.exit(code ?? 1));
