"use client";

import {
  CircleX,
  RotateCw,
  SearchX,
  ServerCrash,
  WifiOff,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import type { ApiError } from "@/lib/api";
import { ApiRequestError } from "@/lib/query-client";
import { cn } from "@/lib/utils";

export interface ErrorStateProps {
  /** An `ApiError`, an `ApiRequestError` from a query, or any thrown value. */
  error: unknown;
  /** Overrides the title derived from the error. */
  title?: string;
  /** Overrides the message derived from the error. */
  message?: string;
  /** Shows a "Try again" button. */
  onRetry?: () => void;
  /** Another way forward, e.g. a link. */
  action?: ReactNode;
  className?: string;
}

/** What went wrong, in words the user can act on; never internals. */
export function ErrorState({
  error,
  title,
  message,
  onRetry,
  action,
  className,
}: ErrorStateProps) {
  const view = describe(error);
  const Icon = view.icon;
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center gap-3 rounded-xl border border-sev-critical-solid/40 px-6 py-12 text-center",
        className,
      )}
    >
      <Icon aria-hidden className="size-10 text-sev-critical" />
      <h2 className="font-heading text-lg font-semibold">
        {title ?? view.title}
      </h2>
      <p className="max-w-md text-sm text-muted-foreground">
        {message ?? view.message}
      </p>
      {view.code && (
        <p className="font-mono text-xs text-muted-foreground">{view.code}</p>
      )}
      {(onRetry || action) && (
        <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
          {onRetry && (
            <Button variant="outline" onClick={onRetry}>
              <RotateCw aria-hidden />
              Try again
            </Button>
          )}
          {action}
        </div>
      )}
    </div>
  );
}

interface ErrorView {
  title: string;
  message: string;
  icon: LucideIcon;
  code?: string;
}

function describe(error: unknown): ErrorView {
  const apiError = toApiError(error);
  if (!apiError) {
    return {
      title: "Something went wrong",
      message: "An unexpected error occurred. Try again.",
      icon: CircleX,
    };
  }
  if (apiError.kind === "network") {
    return {
      title: "Can't reach the API",
      message: apiError.message,
      icon: WifiOff,
    };
  }
  const code = apiError.code === "UNKNOWN" ? undefined : apiError.code;
  if (apiError.kind === "server") {
    return {
      title: "The API ran into a problem",
      message: apiError.message,
      icon: ServerCrash,
      code: code ?? `HTTP ${apiError.status}`,
    };
  }
  if (apiError.code === "NOT_FOUND") {
    return {
      title: "Not found",
      message: apiError.message,
      icon: SearchX,
      code,
    };
  }
  return {
    title: "Request not accepted",
    message: apiError.message,
    icon: CircleX,
    code: code ?? `HTTP ${apiError.status}`,
  };
}

function toApiError(error: unknown): ApiError | null {
  if (error instanceof ApiRequestError) return error.error;
  if (
    typeof error === "object" &&
    error !== null &&
    "kind" in error &&
    "message" in error
  ) {
    return error as ApiError;
  }
  return null;
}
