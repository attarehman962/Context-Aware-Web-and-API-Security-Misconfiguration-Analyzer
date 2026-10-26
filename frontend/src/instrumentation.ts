/**
 * Runs once when the Next.js server starts. In mock mode it intercepts the
 * server's own API calls (server components) with the same MSW handlers the
 * browser uses.
 */

import { publicEnv } from "@/lib/env";

export async function register() {
  // NEXT_RUNTIME is set by Next.js itself; msw/node only works on Node.
  if (publicEnv.useMock && process.env.NEXT_RUNTIME === "nodejs") {
    const { createMockServer } = await import("./mocks/node");
    createMockServer().listen({ onUnhandledRequest: "bypass" });
  }
}
