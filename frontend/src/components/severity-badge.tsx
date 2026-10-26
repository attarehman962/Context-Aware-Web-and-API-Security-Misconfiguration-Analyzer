import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/api-types";
import { SEVERITY } from "@/lib/severity";

export interface SeverityBadgeProps {
  severity: Severity;
  size?: "sm" | "md";
  className?: string;
}

/** Severity as icon + label + colour; readable without the colour. */
export function SeverityBadge({
  severity,
  size = "md",
  className,
}: SeverityBadgeProps) {
  const token = SEVERITY[severity];
  const Icon = token.icon;
  return (
    <span
      data-severity={severity}
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-md border font-medium whitespace-nowrap",
        size === "sm" ? "px-1.5 py-0.5 text-xs" : "px-2 py-0.5 text-sm",
        token.text,
        token.bg,
        token.border,
        className,
      )}
    >
      <Icon aria-hidden className={size === "sm" ? "size-3" : "size-3.5"} />
      <span className="sr-only">Severity: </span>
      {token.label}
    </span>
  );
}
