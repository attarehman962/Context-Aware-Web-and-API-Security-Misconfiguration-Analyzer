"use client";

import {
  ChevronLeft,
  ChevronRight,
  History,
  RotateCcw,
  Search,
  SearchX,
} from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { formatDuration } from "@/components/results/scan-summary";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusPill } from "@/components/status-pill";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { ScanStatus, Severity } from "@/lib/api-types";
import {
  paginate,
  parseHistoryView,
  rescanHref,
  scanDuration,
  searchScans,
  serializeHistoryView,
  type HistoryView,
} from "@/lib/history";
import { useScanHistory } from "@/lib/queries";
import { SEVERITY_ORDER } from "@/lib/severity";

const SEARCH_DEBOUNCE_MS = 250;

/**
 * Past scans, newest first: search by target, 20 per page. Search and page
 * live in the URL. A row opens the stored results; Re-scan opens the
 * new-scan form pre-filled (authorisation must be confirmed again).
 */
export function ScanHistory() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const view = parseHistoryView(new URLSearchParams(searchParams.toString()));
  const history = useScanHistory();

  const setView = (next: HistoryView) =>
    router.replace(`/history${serializeHistoryView(next)}`, { scroll: false });

  if (history.isPending) {
    return (
      <LoadingSkeleton variant="table" rows={8} label="Loading scan history…" />
    );
  }
  if (history.isError) {
    return (
      <ErrorState error={history.error} onRetry={() => history.refetch()} />
    );
  }
  if (history.data.length === 0) {
    return (
      <EmptyState
        icon={History}
        title="No scans yet"
        description="Scans you start appear here with their results."
        action={
          <Button nativeButton={false} render={<Link href="/" />}>
            Start a new scan
          </Button>
        }
      />
    );
  }

  const matching = searchScans(history.data, view.query);
  const page = paginate(matching, view.page);

  return (
    <div className="flex min-w-0 flex-col gap-4">
      <SearchBox
        value={view.query}
        onChange={(query) => setView({ query, page: 1 })}
      />

      {page.total === 0 ? (
        <EmptyState
          icon={SearchX}
          title="No scans match this search"
          description={`No target contains “${view.query.trim()}”.`}
          action={
            <Button
              variant="outline"
              onClick={() => setView({ query: "", page: 1 })}
            >
              Clear search
            </Button>
          }
        />
      ) : (
        <>
          <HistoryTable
            scans={page.items}
            onOpen={(id) => router.push(`/scans/${id}`)}
          />
          <nav
            aria-label="History pages"
            className="flex flex-wrap items-center justify-between gap-3 text-sm"
          >
            <p aria-live="polite" className="text-muted-foreground">
              Showing {page.from}–{page.to} of {page.total} scan
              {page.total === 1 ? "" : "s"}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page.page <= 1}
                onClick={() => setView({ ...view, page: page.page - 1 })}
              >
                <ChevronLeft aria-hidden />
                Previous
              </Button>
              <span className="tabular-nums">
                Page {page.page} of {page.pages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page.page >= page.pages}
                onClick={() => setView({ ...view, page: page.page + 1 })}
              >
                Next
                <ChevronRight aria-hidden />
              </Button>
            </div>
          </nav>
        </>
      )}
    </div>
  );
}

function HistoryTable({
  scans,
  onOpen,
}: {
  scans: ScanStatus[];
  onOpen: (scanId: string) => void;
}) {
  // relative: the cells' sr-only labels are absolutely positioned; without a
  // positioned wrapper they escape the scroll box and widen the page.
  return (
    <div className="relative w-full min-w-0 overflow-x-auto rounded-xl border">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Past scans, newest first</caption>
        <thead className="border-b bg-muted/50 text-muted-foreground">
          <tr>
            <Th>Started</Th>
            <Th>Target</Th>
            <Th>Status</Th>
            <Th>Findings</Th>
            <Th>Duration</Th>
            <Th>
              <span className="sr-only">Actions</span>
            </Th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.scan_id}
              data-scan-id={scan.scan_id}
              // The target link is the keyboard/screen-reader way in; the
              // whole row is a bigger click target for the mouse.
              onClick={(event) => {
                if ((event.target as HTMLElement).closest("a, button")) return;
                onOpen(scan.scan_id);
              }}
              className="cursor-pointer border-b last:border-0 hover:bg-muted/50"
            >
              {/* On phones the date may wrap, so the target column gets the room. */}
              <td className="px-3 py-2 whitespace-nowrap tabular-nums max-sm:whitespace-normal">
                {new Date(scan.created_at).toLocaleString(undefined, {
                  dateStyle: "medium",
                  timeStyle: "short",
                })}
              </td>
              <td className="max-w-xs px-3 py-2 max-sm:min-w-44">
                <Link
                  href={`/scans/${scan.scan_id}`}
                  className="font-medium wrap-anywhere underline-offset-4 hover:underline"
                >
                  {scan.url}
                </Link>
              </td>
              <td className="px-3 py-2">
                <StatusPill status={scan.status} />
              </td>
              <td className="px-3 py-2">
                <SeverityCounts scan={scan} />
              </td>
              <td className="px-3 py-2 whitespace-nowrap tabular-nums">
                {durationText(scan)}
              </td>
              <td className="px-3 py-2 text-right">
                <Button
                  variant="ghost"
                  size="sm"
                  nativeButton={false}
                  render={<Link href={rescanHref(scan)} />}
                  aria-label={`Re-scan ${scan.url}`}
                >
                  <RotateCcw aria-hidden />
                  Re-scan
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th scope="col" className="px-3 py-2 font-medium whitespace-nowrap">
      {children}
    </th>
  );
}

function SeverityCounts({ scan }: { scan: ScanStatus }) {
  if (scan.status !== "DONE") {
    return <span className="text-muted-foreground">—</span>;
  }
  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: countOf(scan, severity),
  })).filter((c) => c.count > 0);
  if (counts.length === 0) {
    return <span className="text-muted-foreground">None</span>;
  }
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label="Findings per severity">
      {counts.map(({ severity, count }) => (
        <li
          key={severity}
          data-severity-count={severity}
          className="inline-flex items-center gap-1"
        >
          <SeverityBadge severity={severity} size="sm" />
          <span className="tabular-nums">{count}</span>
        </li>
      ))}
    </ul>
  );
}

function countOf(scan: ScanStatus, severity: Severity): number {
  return scan.severity_counts[
    severity.toLowerCase() as keyof ScanStatus["severity_counts"]
  ];
}

function durationText(scan: ScanStatus): string {
  const seconds = scanDuration(scan);
  if (seconds === null) {
    return scan.status === "QUEUED"
      ? "waiting"
      : scan.status === "RUNNING"
        ? "running"
        : "—";
  }
  return formatDuration(seconds);
}

/** Search box: types at once, updates the URL after a pause. */
function SearchBox({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const [text, setText] = useState(value);
  const [synced, setSynced] = useState(value);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  if (value !== synced) {
    setSynced(value);
    setText(value);
  }
  useEffect(() => () => clearTimeout(timer.current), []);

  return (
    <div className="flex max-w-md flex-col gap-1.5">
      <label htmlFor="history-search" className="text-sm font-medium">
        Search by target
      </label>
      <div className="relative">
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          id="history-search"
          type="search"
          value={text}
          placeholder="shop.example.com"
          onChange={(event) => {
            const next = event.target.value;
            setText(next);
            clearTimeout(timer.current);
            timer.current = setTimeout(() => {
              setSynced(next);
              onChange(next);
            }, SEARCH_DEBOUNCE_MS);
          }}
          className="pl-8"
        />
      </div>
    </div>
  );
}
