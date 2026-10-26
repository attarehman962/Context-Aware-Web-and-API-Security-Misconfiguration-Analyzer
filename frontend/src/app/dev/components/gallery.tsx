"use client";

import { ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

import { EmptyState } from "@/components/empty-state";
import { ErrorState } from "@/components/error-state";
import { LoadingSkeleton } from "@/components/loading-skeleton";
import { ScoreDisplay } from "@/components/score-display";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusPill } from "@/components/status-pill";
import { Button } from "@/components/ui/button";
import type { ApiError } from "@/lib/api";
import type { Severity } from "@/lib/api-types";
import { SEVERITY, SEVERITY_ORDER } from "@/lib/severity";
import { cn } from "@/lib/utils";

const SCORE_CASES: {
  label: string;
  base: number;
  final: number;
  severity: Severity;
}[] = [
  { label: "Raised by context", base: 4.3, final: 8.6, severity: "HIGH" },
  { label: "Raised to critical", base: 7.5, final: 10.0, severity: "CRITICAL" },
  { label: "Lowered by context", base: 5.3, final: 3.2, severity: "LOW" },
  { label: "Unchanged", base: 5.3, final: 5.3, severity: "MEDIUM" },
  { label: "None (0.0)", base: 3.1, final: 0.0, severity: "INFO" },
];

const ERROR_CASES: { label: string; error: unknown }[] = [
  {
    label: "Network",
    error: {
      kind: "network",
      message: "Could not reach the CAWASMA API. Check that it is running.",
    } satisfies ApiError,
  },
  {
    label: "Server (5xx)",
    error: {
      kind: "server",
      status: 500,
      code: "INTERNAL_ERROR",
      message: "An internal error occurred.",
    } satisfies ApiError,
  },
  {
    label: "Not found (404)",
    error: {
      kind: "client",
      status: 404,
      code: "NOT_FOUND",
      message: "Scan not found.",
    } satisfies ApiError,
  },
  {
    label: "Rejected (400)",
    error: {
      kind: "client",
      status: 400,
      code: "INVALID_TARGET",
      message: "Only HTTPS targets are allowed.",
    } satisfies ApiError,
  },
  { label: "Unknown thrown value", error: new Error("boom") },
];

export function ComponentGallery() {
  return (
    <div className="flex flex-col gap-10">
      <header className="flex flex-col gap-2">
        <h1 className="font-heading text-2xl font-semibold tracking-tight">
          Components
        </h1>
        <p className="text-muted-foreground">
          Every shared component in every state. Switch light / dark with the
          theme button in the header; check each state still reads in greyscale
          (icon + label, not colour alone).
        </p>
      </header>

      <Section title="Severity tokens" source="src/lib/severity.ts">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-muted-foreground">
              <tr>
                <th className="py-2 pr-4 font-medium">Contract value</th>
                <th className="py-2 pr-4 font-medium">Badge</th>
                <th className="py-2 pr-4 font-medium">Small</th>
                <th className="py-2 pr-4 font-medium">Text on page</th>
                <th className="py-2 font-medium">Fill</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITY_ORDER.map((severity) => {
                const token = SEVERITY[severity];
                const Icon = token.icon;
                return (
                  <tr key={severity} className="border-t">
                    <td className="py-2 pr-4 font-mono text-xs">{severity}</td>
                    <td className="py-2 pr-4">
                      <SeverityBadge severity={severity} />
                    </td>
                    <td className="py-2 pr-4">
                      <SeverityBadge severity={severity} size="sm" />
                    </td>
                    <td className={cn("py-2 pr-4 font-medium", token.text)}>
                      <span className="inline-flex items-center gap-1">
                        <Icon aria-hidden className="size-4" />
                        {token.label}
                      </span>
                    </td>
                    <td className="py-2">
                      <span
                        aria-hidden
                        className={cn(
                          "block h-3 w-16 rounded-full",
                          token.fill,
                        )}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="ScoreDisplay" source="src/components/score-display.tsx">
        <Grid>
          {SCORE_CASES.map((c) => (
            <Case key={c.label} label={c.label}>
              <ScoreDisplay
                base={c.base}
                final={c.final}
                severity={c.severity}
              />
            </Case>
          ))}
          {SCORE_CASES.slice(0, 3).map((c) => (
            <Case key={`compact-${c.label}`} label={`${c.label}, compact`}>
              <ScoreDisplay
                base={c.base}
                final={c.final}
                severity={c.severity}
                compact
              />
            </Case>
          ))}
        </Grid>
      </Section>

      <Section title="StatusPill" source="src/components/status-pill.tsx">
        <div className="flex flex-wrap items-center gap-3">
          <StatusPill status="QUEUED" />
          <StatusPill status="RUNNING" />
          <StatusPill status="RUNNING" progress={45} />
          <StatusPill status="DONE" />
          <StatusPill status="FAILED" />
        </div>
      </Section>

      <Section title="EmptyState" source="src/components/empty-state.tsx">
        <Grid>
          <Case label="Title only">
            <EmptyState title="No findings" />
          </Case>
          <Case label="With description, icon and action">
            <EmptyState
              icon={ShieldCheck}
              title="No misconfigurations found"
              description="The scan finished without findings on the checked endpoints."
              action={<Button variant="outline">Start another scan</Button>}
            />
          </Case>
        </Grid>
      </Section>

      <Section title="ErrorState" source="src/components/error-state.tsx">
        <Grid>
          {ERROR_CASES.map((c, i) => (
            <Case key={c.label} label={c.label}>
              <ErrorState
                error={c.error}
                onRetry={i % 2 === 0 ? () => {} : undefined}
              />
            </Case>
          ))}
        </Grid>
      </Section>

      <Section
        title="LoadingSkeleton"
        source="src/components/loading-skeleton.tsx"
      >
        <Grid>
          <Case label="lines">
            <LoadingSkeleton />
          </Case>
          <Case label="card">
            <LoadingSkeleton variant="card" />
          </Case>
          <Case label="table">
            <LoadingSkeleton variant="table" rows={4} />
          </Case>
        </Grid>
      </Section>
    </div>
  );
}

function Section({
  title,
  source,
  children,
}: {
  title: string;
  source: string;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b pb-2">
        <h2 className="font-heading text-lg font-semibold">{title}</h2>
        <code className="text-xs text-muted-foreground">{source}</code>
      </div>
      {children}
    </section>
  );
}

function Grid({ children }: { children: ReactNode }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{children}</div>
  );
}

function Case({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}
