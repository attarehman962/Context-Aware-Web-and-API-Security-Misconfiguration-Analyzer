import {
  CircleCheck,
  CircleX,
  Clock,
  LoaderCircle,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";
import type { ScanState } from "@/lib/api-types";

const STATUS: Record<
  ScanState,
  { label: string; icon: LucideIcon; className: string; spin?: boolean }
> = {
  QUEUED: {
    label: "Queued",
    icon: Clock,
    className: "text-sev-none bg-sev-none-bg border-sev-none-solid",
  },
  RUNNING: {
    label: "Running",
    icon: LoaderCircle,
    className: "text-sev-low bg-sev-low-bg border-sev-low-solid",
    spin: true,
  },
  DONE: {
    label: "Done",
    icon: CircleCheck,
    className: "text-sev-success bg-sev-success-bg border-sev-success-solid",
  },
  FAILED: {
    label: "Failed",
    icon: CircleX,
    className: "text-sev-critical bg-sev-critical-bg border-sev-critical-solid",
  },
};

export interface StatusPillProps {
  status: ScanState;
  /** Shown while RUNNING, e.g. "Running 45%". */
  progress?: number;
  className?: string;
}

/** Scan status as icon + label + colour. */
export function StatusPill({ status, progress, className }: StatusPillProps) {
  const { label, icon: Icon, className: tone, spin } = STATUS[status];
  return (
    <span
      data-status={status}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-sm font-medium whitespace-nowrap",
        tone,
        className,
      )}
    >
      <Icon
        aria-hidden
        className={cn(
          "size-3.5",
          spin && "animate-spin motion-reduce:animate-none",
        )}
      />
      {label}
      {status === "RUNNING" && progress !== undefined && (
        <span className="tabular-nums">{Math.round(progress)}%</span>
      )}
    </span>
  );
}
