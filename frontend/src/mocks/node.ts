/** MSW in Node: the Next.js server in mock mode, and the unit tests. */

import { setupServer } from "msw/node";

import { createHandlers, type HandlerOptions } from "./handlers";

export function createMockServer(options?: HandlerOptions) {
  return setupServer(...createHandlers(options));
}
