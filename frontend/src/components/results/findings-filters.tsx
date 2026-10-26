"use client";

import { Search, X } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Severity } from "@/lib/api-types";
import {
  NO_FILTERS,
  categoryLabel,
  hasFilters,
  type FindingFilters,
  type RankBy,
} from "@/lib/findings";
import { SEVERITY_ORDER } from "@/lib/severity";
import { cn } from "@/lib/utils";

const SEARCH_DEBOUNCE_MS = 250;

export interface FindingsFiltersProps {
  filters: FindingFilters;
  onFiltersChange: (filters: FindingFilters) => void;
  rankBy: RankBy;
  onRankByChange: (rankBy: RankBy) => void;
  options: { categories: string[]; owasp: string[]; hasChains: boolean };
  /** Findings shown after filtering, and in the scan. */
  shown: number;
  total: number;
}

/** Ranking toggle and filters for the findings list. */
export function FindingsFilters({
  filters,
  onFiltersChange,
  rankBy,
  onRankByChange,
  options,
  shown,
  total,
}: FindingsFiltersProps) {
  const id = useId();
  const update = (patch: Partial<FindingFilters>) =>
    onFiltersChange({ ...filters, ...patch });

  function toggleSeverity(severity: Severity) {
    const has = filters.severities.includes(severity);
    update({
      severities: has
        ? filters.severities.filter((s) => s !== severity)
        : [...filters.severities, severity],
    });
  }

  return (
    <div className="flex flex-col gap-4 rounded-xl border p-4">
      <RankToggle rankBy={rankBy} onChange={onRankByChange} />

      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-sm font-medium">
          Severity{" "}
          <span className="font-normal text-muted-foreground">
            (context-aware)
          </span>
        </legend>
        <div className="flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((severity) => {
            const checked = filters.severities.includes(severity);
            return (
              <label
                key={severity}
                className={cn(
                  "flex cursor-pointer items-center gap-2 rounded-lg border px-2 py-1 text-sm has-focus-visible:ring-3 has-focus-visible:ring-ring/50",
                  checked ? "border-foreground" : "opacity-80",
                )}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleSeverity(severity)}
                  className="size-4 accent-primary"
                />
                <SeverityBadge severity={severity} size="sm" />
              </label>
            );
          })}
        </div>
      </fieldset>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Select
          id={`${id}-category`}
          label="Category"
          value={filters.category}
          values={options.categories}
          format={categoryLabel}
          onChange={(category) => update({ category })}
        />
        <Select
          id={`${id}-owasp`}
          label="OWASP"
          value={filters.owasp}
          values={options.owasp}
          onChange={(owasp) => update({ owasp })}
        />
        <EndpointSearch
          id={`${id}-endpoint`}
          value={filters.endpoint}
          onChange={(endpoint) => update({ endpoint })}
        />
        <label className="flex items-center gap-2 self-end pb-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={filters.chainsOnly}
            onChange={(e) => update({ chainsOnly: e.target.checked })}
            disabled={!options.hasChains && !filters.chainsOnly}
            className="size-4 accent-primary"
          />
          Only findings in attack chains
        </label>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
        <p aria-live="polite" className="text-muted-foreground">
          Showing {shown} of {total} finding{total === 1 ? "" : "s"}
        </p>
        {hasFilters(filters) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onFiltersChange(NO_FILTERS)}
          >
            <X aria-hidden />
            Clear filters
          </Button>
        )}
      </div>
    </div>
  );
}

function RankToggle({
  rankBy,
  onChange,
}: {
  rankBy: RankBy;
  onChange: (rankBy: RankBy) => void;
}) {
  const choices: [RankBy, string, string][] = [
    ["final", "Context-aware score", "CAWASMA's final score"],
    ["base", "Base score", "official CVSS v3.1 base score"],
  ];
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1 text-sm font-medium">Rank by</legend>
      <div className="inline-flex w-fit rounded-lg border p-0.5">
        {choices.map(([value, label, hint]) => (
          <label
            key={value}
            title={hint}
            className="cursor-pointer rounded-md px-3 py-1.5 text-sm font-medium text-muted-foreground has-checked:bg-primary has-checked:text-primary-foreground has-focus-visible:ring-3 has-focus-visible:ring-ring/50"
          >
            <input
              type="radio"
              name="rank-by"
              value={value}
              checked={rankBy === value}
              onChange={() => onChange(value)}
              className="sr-only"
            />
            {label}
          </label>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        {rankBy === "final"
          ? "Ranked by where each issue occurs and what the endpoint returns. Switch to base score to see the plain CVSS order."
          : "Ranked by the official CVSS v3.1 base score alone, ignoring context. Compare with the context-aware ranking."}
      </p>
    </fieldset>
  );
}

function Select({
  id,
  label,
  value,
  values,
  format = (v) => v,
  onChange,
}: {
  id: string;
  label: string;
  value: string | null;
  values: string[];
  format?: (value: string) => string;
  onChange: (value: string | null) => void;
}) {
  // Keep a value from the URL selectable even if this scan lacks it.
  const all = value && !values.includes(value) ? [value, ...values] : values;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <select
        id={id}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || null)}
        className="h-8 rounded-lg border border-input bg-background px-2 text-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        <option value="">All</option>
        {all.map((v) => (
          <option key={v} value={v}>
            {format(v)}
          </option>
        ))}
      </select>
    </div>
  );
}

/** Typing updates the input at once and the filter (URL) after a pause. */
function EndpointSearch({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
}) {
  const [text, setText] = useState(value);
  const [synced, setSynced] = useState(value);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  // The URL changed from elsewhere (Clear filters, back/forward).
  if (value !== synced) {
    setSynced(value);
    setText(value);
  }

  useEffect(() => () => clearTimeout(timer.current), []);

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        Endpoint contains
      </label>
      <div className="relative">
        <Search
          aria-hidden
          className="pointer-events-none absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          id={id}
          type="search"
          value={text}
          placeholder="/api/admin"
          onChange={(e) => {
            const next = e.target.value;
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
