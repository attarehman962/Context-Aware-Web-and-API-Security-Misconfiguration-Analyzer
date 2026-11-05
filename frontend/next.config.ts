import path from "node:path";
import { fileURLToPath } from "node:url";

import type { NextConfig } from "next";

import { SECURITY_HEADERS } from "./src/lib/security-headers";

const nextConfig: NextConfig = {
  // Self-contained server in .next/standalone for the Docker image.
  output: "standalone",
  // Trace from frontend/ only, so stray lockfiles in parent folders can't
  // change the standalone layout (server.js stays at its root).
  outputFileTracingRoot: path.dirname(fileURLToPath(import.meta.url)),
  cacheComponents: true,
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
