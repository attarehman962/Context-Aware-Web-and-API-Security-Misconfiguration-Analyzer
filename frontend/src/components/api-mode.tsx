import { FlaskConical, Radio } from "lucide-react";

import { publicEnv } from "@/lib/env";
import { cn } from "@/lib/utils";

/**
 * Mock vs live API, shown in the footer (and as a banner in mock mode) so
 * sample data is never demoed as a real scan by mistake.
 */
export function ApiModeIndicator({ className }: { className?: string }) {
  if (publicEnv.useMock) {
    return (
      <span
        data-api-mode="mock"
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md border border-sev-medium-solid bg-sev-medium-bg px-2 py-0.5 font-medium text-sev-medium",
          className,
        )}
      >
        <FlaskConical aria-hidden className="size-3.5" />
        API: mock data
      </span>
    );
  }
  return (
    <span
      data-api-mode="live"
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border border-sev-success-solid bg-sev-success-bg px-2 py-0.5 font-medium text-sev-success",
        className,
      )}
    >
      <Radio aria-hidden className="size-3.5" />
      API: live
      <span className="font-mono text-xs font-normal">{publicEnv.apiUrl}</span>
    </span>
  );
}

/** Full-width warning strip; renders nothing against the live API. */
export function MockModeBanner() {
  if (!publicEnv.useMock) return null;
  return (
    <div
      role="note"
      className="flex items-center justify-center gap-2 border-b border-sev-medium-solid bg-sev-medium-bg px-4 py-1.5 text-center text-sm font-medium text-sev-medium"
    >
      <FlaskConical aria-hidden className="size-4 shrink-0" />
      Mock mode: every result is sample data, not a real scan.
    </div>
  );
}
