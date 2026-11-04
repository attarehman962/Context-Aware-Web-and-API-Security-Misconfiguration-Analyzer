"use client";

import { ChevronDown, Download, LoaderCircle, RotateCw } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { fetchExport } from "@/lib/api";
import type { ExportFormat, ScanStatus } from "@/lib/api-types";
import { EXPORT_FORMATS, exportFileName, saveBlob } from "@/lib/export";

type ExportState =
  | { kind: "idle" }
  | { kind: "pending"; format: ExportFormat }
  | { kind: "done"; fileName: string }
  | { kind: "error"; format: ExportFormat; message: string };

/**
 * Export the results as PDF, HTML, JSON or CSV. Disabled until the scan is
 * DONE. The file is fetched rather than linked, so the page can show that a
 * PDF is being generated, explain a failure, and name the file
 * cawasma-<target>-<date>.<ext>.
 */
export function ExportMenu({ scan }: { scan: ScanStatus }) {
  const [state, setState] = useState<ExportState>({ kind: "idle" });
  const abort = useRef<AbortController | null>(null);
  const statusId = useId();
  const done = scan.status === "DONE";
  useEffect(() => () => abort.current?.abort(), []);

  async function download(format: ExportFormat) {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setState({ kind: "pending", format });
    try {
      const result = await fetchExport(scan.scan_id, format, {
        signal: controller.signal,
      });
      if (!result.ok) {
        setState({ kind: "error", format, message: result.error.message });
        return;
      }
      const fileName = exportFileName(scan, format);
      saveBlob(result.data, fileName);
      setState({ kind: "done", fileName });
    } catch {
      // Aborted: the user cancelled or left the page.
      if (!controller.signal.aborted) {
        setState({ kind: "error", format, message: "The download failed." });
      }
    }
  }

  const pending = state.kind === "pending";
  const label = (format: ExportFormat) =>
    EXPORT_FORMATS.find((f) => f.format === format)?.label ?? format;

  return (
    <div className="flex flex-col items-start gap-2">
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="outline"
              disabled={!done || pending}
              aria-describedby={statusId}
            />
          }
        >
          <Download aria-hidden />
          Export
          <ChevronDown aria-hidden />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          {EXPORT_FORMATS.map(({ format, label, description }) => (
            <DropdownMenuItem
              key={format}
              onClick={() => void download(format)}
              className="flex flex-col items-start gap-0"
            >
              <span>{label}</span>
              <span className="text-xs text-muted-foreground">
                {description}
              </span>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      <div id={statusId} aria-live="polite" className="text-sm">
        {!done && (
          <p className="text-muted-foreground">
            Export is available when the scan is done.
          </p>
        )}
        {state.kind === "pending" && (
          <p className="flex items-center gap-2" role="status">
            <LoaderCircle
              aria-hidden
              className="size-4 animate-spin motion-reduce:animate-none"
            />
            {state.format === "pdf"
              ? "Generating the PDF report… this can take a few seconds."
              : `Preparing ${label(state.format)}…`}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                abort.current?.abort();
                setState({ kind: "idle" });
              }}
            >
              Cancel
            </Button>
          </p>
        )}
        {state.kind === "done" && (
          <p className="text-muted-foreground">Saved {state.fileName}</p>
        )}
      </div>
      {state.kind === "error" && (
        <div
          role="alert"
          className="flex flex-wrap items-center gap-2 rounded-lg border border-sev-critical-solid bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
        >
          <span>
            <span className="font-medium">
              {label(state.format)} export failed:
            </span>{" "}
            {state.message}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void download(state.format)}
          >
            <RotateCw aria-hidden />
            Try again
          </Button>
        </div>
      )}
    </div>
  );
}
