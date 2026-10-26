/** MSW in the browser: serves the API from fixtures when mock mode is on. */

import { setupWorker } from "msw/browser";

import { handlers } from "./handlers";

let started: Promise<unknown> | undefined;

/** Start the service worker once (safe to call again, e.g. in Strict Mode). */
export function startMockWorker(): Promise<unknown> {
  started ??= setupWorker(...handlers).start({
    onUnhandledRequest: "bypass",
    quiet: true,
  });
  return started;
}
