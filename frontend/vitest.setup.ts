import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { EventSource } from "eventsource";
import { afterEach } from "vitest";

// jsdom has no EventSource. This one is spec-compliant and runs over fetch,
// so MSW's sse() handlers answer it like a browser's.
if (!("EventSource" in globalThis)) {
  Object.assign(globalThis, { EventSource });
}

afterEach(() => {
  cleanup();
});
