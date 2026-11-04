/**
 * Report export: the formats on offer and the downloaded file's name. The
 * API names every file cawasma-{scan_id}.{format}; the page names it after
 * the target and date instead, which is what people look for in Downloads.
 */

import type { ExportFormat, ScanStatus } from "./api-types";

export const EXPORT_FORMATS: {
  format: ExportFormat;
  label: string;
  description: string;
}[] = [
  { format: "pdf", label: "PDF report", description: "Printable report" },
  {
    format: "html",
    label: "HTML report",
    description: "Same report, in a browser",
  },
  { format: "json", label: "JSON", description: "Full results, for tools" },
  { format: "csv", label: "CSV", description: "One row per finding" },
];

/**
 * cawasma-<target>-<date>.<ext>: the target's host (and port, if any) and
 * the scan's finish date (UTC), e.g. cawasma-shop.example.com-2026-10-20.pdf.
 */
export function exportFileName(
  scan: Pick<ScanStatus, "url" | "completed_at" | "created_at">,
  format: ExportFormat,
): string {
  return `cawasma-${targetSlug(scan.url)}-${(scan.completed_at ?? scan.created_at).slice(0, 10)}.${format}`;
}

function targetSlug(url: string): string {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    host = url;
  }
  const slug = host
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "");
  return slug || "scan";
}

/** Hands a Blob to the browser as a download with the given name. */
export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  // Let the click start the download before the URL goes away.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
