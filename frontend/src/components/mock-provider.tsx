"use client";

import { useEffect, useState, type ReactNode } from "react";

import { publicEnv } from "@/lib/env";

/**
 * With NEXT_PUBLIC_USE_MOCK=true, starts the MSW worker and holds the app
 * back until it is ready, so no request slips past to the real API. Without
 * mock mode it renders its children straight away and loads no MSW code.
 */
export function MockProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(!publicEnv.useMock);

  useEffect(() => {
    if (!publicEnv.useMock) return;
    let active = true;
    import("@/mocks/browser")
      .then(({ startMockWorker }) => startMockWorker())
      .then(() => {
        if (active) setReady(true);
      });
    return () => {
      active = false;
    };
  }, []);

  return ready ? children : null;
}
