import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export interface LoadingSkeletonProps {
  /** `lines`: a paragraph; `card`: a summary card; `table`: findings rows. */
  variant?: "lines" | "card" | "table";
  /** Number of lines or table rows. */
  rows?: number;
  /** Announced to screen readers. */
  label?: string;
  className?: string;
}

/** Placeholder shapes while data loads; motion stops for reduced-motion users. */
export function LoadingSkeleton({
  variant = "lines",
  rows = 3,
  label = "Loading…",
  className,
}: LoadingSkeletonProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn("flex flex-col gap-3", className)}
    >
      <span className="sr-only">{label}</span>
      {variant === "card" && (
        <div className="flex flex-col gap-3 rounded-xl border p-4">
          <Skeleton className="h-5 w-1/3 motion-reduce:animate-none" />
          <Skeleton className="h-8 w-1/2 motion-reduce:animate-none" />
          <Skeleton className="h-4 w-full motion-reduce:animate-none" />
        </div>
      )}
      {variant === "table" &&
        Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-4">
            <Skeleton className="h-6 w-20 motion-reduce:animate-none" />
            <Skeleton className="h-4 flex-1 motion-reduce:animate-none" />
            <Skeleton className="h-6 w-16 motion-reduce:animate-none" />
          </div>
        ))}
      {variant === "lines" &&
        Array.from({ length: rows }, (_, i) => (
          <Skeleton
            key={i}
            className={cn(
              "h-4 motion-reduce:animate-none",
              i === rows - 1 ? "w-2/3" : "w-full",
            )}
          />
        ))}
    </div>
  );
}
