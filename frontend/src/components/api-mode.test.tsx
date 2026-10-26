import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

async function load(useMock: boolean) {
  vi.stubEnv("NEXT_PUBLIC_USE_MOCK", useMock ? "true" : "false");
  vi.resetModules();
  return import("./api-mode");
}

describe("API mode", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("says mock data and shows the banner in mock mode", async () => {
    const { ApiModeIndicator, MockModeBanner } = await load(true);
    render(
      <>
        <MockModeBanner />
        <ApiModeIndicator />
      </>,
    );
    expect(screen.getByText("API: mock data")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent(/not a real scan/);
  });

  it("says live with the API URL and hides the banner otherwise", async () => {
    const { ApiModeIndicator, MockModeBanner } = await load(false);
    render(
      <>
        <MockModeBanner />
        <ApiModeIndicator />
      </>,
    );
    expect(screen.getByText(/API: live/)).toHaveTextContent(
      "http://localhost:8000",
    );
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});
