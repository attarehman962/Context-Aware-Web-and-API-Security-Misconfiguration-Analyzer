/**
 * Scan history (/history) and re-scan: search, paging, duration, and the
 * new-scan form link that re-runs a past scan.
 *
 * GET /api/scans pages by page/limit but has no search parameter, so the
 * history page loads every page once and searches and pages on the client.
 */

import type { ScanOptions, ScanStatus } from "./api-types";
import { DEFAULT_SCAN_FORM, type ScanFormValues } from "./scan-form";

export const HISTORY_PAGE_SIZE = 20;

export interface HistoryView {
  query: string;
  page: number;
}

export function parseHistoryView(params: URLSearchParams): HistoryView {
  const page = Number(params.get("page") ?? 1);
  return {
    query: params.get("q") ?? "",
    page: Number.isInteger(page) && page >= 1 ? page : 1,
  };
}

export function serializeHistoryView(view: HistoryView): string {
  const params = new URLSearchParams();
  if (view.query.trim()) params.set("q", view.query.trim());
  if (view.page > 1) params.set("page", String(view.page));
  const search = params.toString();
  return search ? `?${search}` : "";
}

/** Scans whose target contains `query` (case-insensitive), newest first. */
export function searchScans(scans: ScanStatus[], query: string): ScanStatus[] {
  const needle = query.trim().toLowerCase();
  const matching = needle
    ? scans.filter((s) => s.url.toLowerCase().includes(needle))
    : scans;
  return [...matching].sort(
    (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
  );
}

export interface HistoryPage {
  items: ScanStatus[];
  /** 1-based, clamped to the pages that exist. */
  page: number;
  pages: number;
  total: number;
  /** 1-based positions of the first and last item shown (0 when empty). */
  from: number;
  to: number;
}

export function paginate(
  scans: ScanStatus[],
  page: number,
  size = HISTORY_PAGE_SIZE,
): HistoryPage {
  const total = scans.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const current = Math.min(Math.max(1, page), pages);
  const start = (current - 1) * size;
  const items = scans.slice(start, start + size);
  return {
    items,
    page: current,
    pages,
    total,
    from: items.length ? start + 1 : 0,
    to: start + items.length,
  };
}

/** Seconds from start to finish, or null while it has not finished. */
export function scanDuration(scan: ScanStatus): number | null {
  if (!scan.completed_at) return null;
  const start = scan.started_at ?? scan.created_at;
  return Math.max(
    0,
    (Date.parse(scan.completed_at) - Date.parse(start)) / 1000,
  );
}

/**
 * The new-scan form, pre-filled with a past scan's target and options.
 * Authorisation is deliberately not carried over: the user confirms again.
 */
export function rescanHref(scan: Pick<ScanStatus, "url" | "options">): string {
  const params = new URLSearchParams({
    url: scan.url,
    crawl_depth: String(scan.options.crawl_depth),
    use_wordlist: scan.options.use_wordlist ? "1" : "0",
    passive_only: scan.options.passive_only ? "1" : "0",
  });
  return `/?${params.toString()}`;
}

/** Form values from a re-scan link; anything missing or invalid keeps its default. */
export function prefillFromParams(params: URLSearchParams): ScanFormValues {
  const flag = (key: keyof ScanOptions, fallback: boolean) => {
    const value = params.get(key);
    return value === "1" ? true : value === "0" ? false : fallback;
  };
  const depth = Number(params.get("crawl_depth"));
  return {
    ...DEFAULT_SCAN_FORM,
    url: params.get("url") ?? "",
    authorisation_confirmed: false,
    crawl_depth:
      depth === 1 || depth === 2 ? depth : DEFAULT_SCAN_FORM.crawl_depth,
    use_wordlist: flag("use_wordlist", DEFAULT_SCAN_FORM.use_wordlist),
    passive_only: flag("passive_only", DEFAULT_SCAN_FORM.passive_only),
  };
}

/** True when the link carries a past scan's settings. */
export function isRescan(params: URLSearchParams): boolean {
  return params.has("url");
}
