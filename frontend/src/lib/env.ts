/**
 * Environment access for the frontend. Read env vars only through here.
 *
 * NEXT_PUBLIC_* values are inlined at build time, so they must be referenced
 * as literal `process.env.NEXT_PUBLIC_...` expressions (no destructuring).
 */

const DEFAULT_API_URL = "http://localhost:8000";

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/** Safe to use in client and server code. */
export const publicEnv = {
  /** CAWASMA API as reached from the browser. */
  apiUrl: trimSlash(process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL),
  /** Serve API calls from MSW fixtures instead of the real API (src/mocks/). */
  useMock: process.env.NEXT_PUBLIC_USE_MOCK === "true",
  /** /dev/* pages: always in `next dev`, in builds only when opted in. */
  showDevPages:
    process.env.NODE_ENV !== "production" ||
    process.env.NEXT_PUBLIC_SHOW_DEV_PAGES === "true",
};

/** CAWASMA API as reached from the Next.js server (e.g. http://api:8000 in compose). */
export function serverApiUrl(): string {
  return trimSlash(process.env.API_INTERNAL_URL ?? publicEnv.apiUrl);
}
