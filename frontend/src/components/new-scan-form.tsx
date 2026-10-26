"use client";

import { ChevronRight, CircleAlert, Play } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, type FormEvent, type ReactNode } from "react";

import { StatusPill } from "@/components/status-pill";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { ScanStatus } from "@/lib/api-types";
import { useCreateScan } from "@/lib/queries";
import { ApiRequestError } from "@/lib/query-client";
import {
  DEFAULT_SCAN_FORM,
  submitErrors,
  toScanRequest,
  validateTargetUrl,
  type ScanFormValues,
  type SubmitErrors,
} from "@/lib/scan-form";

export const AUTHORISATION_LABEL =
  "I own this target or have written permission to test it.";

/** Start a scan: target URL, authorisation, advanced options. */
export function NewScanForm() {
  const router = useRouter();
  const createScan = useCreateScan();
  const ids = useIds();
  const urlInput = useRef<HTMLInputElement>(null);

  const [values, setValues] = useState<ScanFormValues>(DEFAULT_SCAN_FORM);
  const [urlTouched, setUrlTouched] = useState(false);
  const [serverErrors, setServerErrors] = useState<SubmitErrors>({
    fields: {},
  });
  const [queued, setQueued] = useState<ScanStatus | null>(null);

  const urlError =
    serverErrors.fields.url ??
    (urlTouched ? validateTargetUrl(values.url) : null);
  const optionErrors = (
    ["crawl_depth", "use_wordlist", "passive_only"] as const
  )
    .map((field) => serverErrors.fields[field])
    .filter(Boolean);
  const canStart = values.authorisation_confirmed && !createScan.isPending;

  function update<K extends keyof ScanFormValues>(
    field: K,
    value: ScanFormValues[K],
  ) {
    setValues((v) => ({ ...v, [field]: value }));
    setServerErrors({ fields: {} });
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    setUrlTouched(true);
    if (validateTargetUrl(values.url) || !values.authorisation_confirmed) {
      urlInput.current?.focus();
      return;
    }
    setServerErrors({ fields: {} });
    createScan.mutate(toScanRequest(values), {
      onSuccess: (scan) => {
        setQueued(scan);
        router.push(`/scans/${scan.scan_id}`);
      },
      onError: (error) => {
        const errors =
          error instanceof ApiRequestError
            ? submitErrors(error.error)
            : {
                fields: {},
                form: {
                  title: "Something went wrong",
                  message: "The scan was not started. Try again.",
                },
              };
        setServerErrors(errors);
        if (errors.fields.url) urlInput.current?.focus();
      },
    });
  }

  if (queued) {
    return (
      <div
        role="status"
        className="flex flex-col items-start gap-3 rounded-xl border p-6"
      >
        <StatusPill status={queued.status} />
        <p className="font-medium">
          Scan queued for <span className="break-all">{queued.url}</span>
        </p>
        <p className="text-sm text-muted-foreground">
          Opening the scan page…{" "}
          <Link
            href={`/scans/${queued.scan_id}`}
            className="underline underline-offset-4"
          >
            Open it now
          </Link>
        </p>
      </div>
    );
  }

  return (
    <form noValidate onSubmit={onSubmit} className="flex flex-col gap-6">
      <div className="flex flex-col gap-2">
        <Label htmlFor={ids.url}>Target URL</Label>
        <Input
          ref={urlInput}
          id={ids.url}
          name="url"
          type="text"
          inputMode="url"
          autoComplete="url"
          spellCheck={false}
          placeholder="https://shop.example.com"
          value={values.url}
          onChange={(e) => update("url", e.target.value)}
          onBlur={() => values.url && setUrlTouched(true)}
          aria-invalid={urlError ? true : undefined}
          aria-describedby={urlError ? ids.urlError : ids.urlHint}
          className="h-10 text-base"
        />
        {urlError ? (
          <p
            id={ids.urlError}
            className="flex items-start gap-1.5 text-sm text-sev-critical"
          >
            <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
            {urlError}
          </p>
        ) : (
          <p id={ids.urlHint} className="text-sm text-muted-foreground">
            The start page of the web app or API. HTTPS only.
          </p>
        )}
      </div>

      <div className="flex flex-col gap-1.5">
        <label className="flex items-start gap-3 text-sm font-medium">
          <input
            type="checkbox"
            name="authorisation_confirmed"
            required
            checked={values.authorisation_confirmed}
            onChange={(e) =>
              update("authorisation_confirmed", e.target.checked)
            }
            aria-describedby={ids.authHint}
            className="mt-0.5 size-4 shrink-0 accent-primary"
          />
          {AUTHORISATION_LABEL}
        </label>
        <p id={ids.authHint} className="pl-7 text-sm text-muted-foreground">
          Required. Scanning systems without permission may be illegal.
        </p>
        {serverErrors.fields.authorisation_confirmed && (
          <p className="pl-7 text-sm text-sev-critical">
            {serverErrors.fields.authorisation_confirmed}
          </p>
        )}
      </div>

      <details className="group rounded-xl border">
        <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium select-none [&::-webkit-details-marker]:hidden">
          <ChevronRight
            aria-hidden
            className="size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none"
          />
          Advanced options
        </summary>
        <div className="flex flex-col gap-5 border-t px-4 py-4">
          <fieldset className="flex flex-col gap-2">
            <legend className="mb-1 text-sm font-medium">Crawl depth</legend>
            {(
              [
                [1, "1: the start page and the links on it."],
                [2, "2: also follow those links one level further (default)."],
              ] as const
            ).map(([depth, text]) => (
              <label key={depth} className="flex items-center gap-3 text-sm">
                <input
                  type="radio"
                  name="crawl_depth"
                  value={depth}
                  checked={values.crawl_depth === depth}
                  onChange={() => update("crawl_depth", depth)}
                  className="size-4 accent-primary"
                />
                {text}
              </label>
            ))}
          </fieldset>

          <Toggle
            name="use_wordlist"
            label="Use wordlist"
            checked={values.use_wordlist}
            onChange={(on) => update("use_wordlist", on)}
          >
            Also probe common hidden paths such as /.env and /admin.
          </Toggle>

          <Toggle
            name="passive_only"
            label="Passive-only mode"
            checked={values.passive_only}
            onChange={(on) => update("passive_only", on)}
          >
            No active probes: skips the TLS protocol probe, rate-limit burst and
            redirect check.
          </Toggle>

          {optionErrors.map((message) => (
            <p key={message} className="text-sm text-sev-critical">
              {message}
            </p>
          ))}
        </div>
      </details>

      {serverErrors.form && (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-xl border border-sev-critical-solid bg-sev-critical-bg p-4 text-sev-critical"
        >
          <CircleAlert aria-hidden className="mt-0.5 size-5 shrink-0" />
          <div className="flex flex-col gap-1">
            <p className="font-medium">{serverErrors.form.title}</p>
            <p className="text-sm">{serverErrors.form.message}</p>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Button
          type="submit"
          size="lg"
          disabled={!canStart}
          aria-describedby={
            values.authorisation_confirmed ? undefined : ids.startHint
          }
          className="px-4"
        >
          <Play aria-hidden />
          {createScan.isPending ? "Starting…" : "Start scan"}
        </Button>
        {!values.authorisation_confirmed && (
          <p id={ids.startHint} className="text-sm text-muted-foreground">
            Confirm authorisation to start.
          </p>
        )}
      </div>
    </form>
  );
}

function Toggle({
  name,
  label,
  checked,
  onChange,
  children,
}: {
  name: string;
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  children: ReactNode;
}) {
  const hint = `${useId()}-hint`;
  return (
    <div className="flex flex-col gap-1">
      <label className="flex items-center gap-3 text-sm font-medium">
        <input
          type="checkbox"
          role="switch"
          name={name}
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          aria-describedby={hint}
          className="size-4 accent-primary"
        />
        {label}
        <span className="text-xs font-normal text-muted-foreground">
          {checked ? "On" : "Off"}
        </span>
      </label>
      <p id={hint} className="pl-7 text-sm text-muted-foreground">
        {children}
      </p>
    </div>
  );
}

function useIds() {
  const base = useId();
  return {
    url: `${base}-url`,
    urlHint: `${base}-url-hint`,
    urlError: `${base}-url-error`,
    authHint: `${base}-auth-hint`,
    startHint: `${base}-start-hint`,
  };
}
