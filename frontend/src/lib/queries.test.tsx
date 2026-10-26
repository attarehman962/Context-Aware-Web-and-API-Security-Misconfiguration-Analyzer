import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { DONE_SCAN_ID } from "@/mocks/fixtures";
import { createMockServer } from "@/mocks/node";

import { useCreateScan, useScanResults } from "./queries";
import {
  ApiRequestError,
  makeQueryClient,
  retryDelay,
  shouldRetry,
} from "./query-client";

const server = createMockServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function wrapper({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={makeQueryClient()}>
      {children}
    </QueryClientProvider>
  );
}

describe("useScanResults", () => {
  it("loads a finished scan and stops polling", async () => {
    const { result } = renderHook(() => useScanResults(DONE_SCAN_ID), {
      wrapper,
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.scan.status).toBe("DONE");
    expect(result.current.isStale).toBe(false);
  });

  it("exposes the typed API error and does not retry a 404", async () => {
    const { result } = renderHook(
      () => useScanResults("99999999-9999-4999-8999-999999999999"),
      { wrapper },
    );
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.failureCount).toBe(1);
    expect(result.current.error).toBeInstanceOf(ApiRequestError);
    expect((result.current.error as ApiRequestError).error).toMatchObject({
      code: "NOT_FOUND",
    });
  });
});

describe("useCreateScan", () => {
  it("resolves to the QUEUED scan", async () => {
    const { result } = renderHook(() => useCreateScan(), { wrapper });
    const scan = await result.current.mutateAsync({
      url: "https://target.example",
      authorisation_confirmed: true,
    });
    expect(scan.status).toBe("QUEUED");
  });
});

describe("shouldRetry", () => {
  const error = (kind: "network" | "client" | "server") =>
    new ApiRequestError(
      kind === "network"
        ? { kind, message: "" }
        : {
            kind,
            status: kind === "client" ? 404 : 500,
            code: "UNKNOWN",
            message: "",
          },
    );

  it("retries network and server errors, up to three times", () => {
    expect(shouldRetry(0, error("network"))).toBe(true);
    expect(shouldRetry(2, error("server"))).toBe(true);
    expect(shouldRetry(3, error("server"))).toBe(false);
  });

  it("backs off exponentially, capped at 8 s", () => {
    expect([0, 1, 2, 3, 4, 10].map(retryDelay)).toEqual([
      1000, 2000, 4000, 8000, 8000, 8000,
    ]);
  });

  it("never retries a client error", () => {
    expect(shouldRetry(0, error("client"))).toBe(false);
  });
});
