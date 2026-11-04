"use client";

import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  ExternalLink,
  Link2,
} from "lucide-react";
import type { ReactNode } from "react";

import { ErrorState } from "@/components/error-state";
import { ScoreDisplay } from "@/components/score-display";
import { SeverityBadge } from "@/components/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import type {
  Chain,
  ChainEvidence,
  Finding,
  FindingDetail as FindingDetailData,
} from "@/lib/api-types";
import { SENSITIVITY, SIGNALS } from "@/lib/context";
import {
  compareVectors,
  firstCalculatorUrl,
  parseVector,
  type MetricRow,
} from "@/lib/cvss";
import { bodyExcerpt, evidenceEntries, httpSnippet } from "@/lib/evidence";
import { displayEndpoint } from "@/lib/findings";
import { useFindingDetail } from "@/lib/queries";
import { scoreStory } from "@/lib/score-story";
import { severityFromScore } from "@/lib/severity";
import { cweLink, owaspLink } from "@/lib/standards";
import { cn } from "@/lib/utils";

export interface FindingDetailProps {
  id: string;
  scanId: string;
  finding: Finding;
  /** All chains of the scan (detail chains are used once loaded). */
  chains: Chain[];
  /** Every finding of the scan, to name and link other chain members. */
  findingsById: Map<string, Finding>;
  targetUrl: string;
  /** Show (expand, scroll to, focus) another finding. */
  onShowFinding: (findingId: string) => void;
}

/**
 * Why a finding scored as it did. Everything that comes with the findings
 * list (score story, vector, standards, chains) shows at once; the endpoint
 * details, check text and evidence snippet load from the finding-detail
 * endpoint.
 */
export function FindingDetail({
  id,
  scanId,
  finding,
  chains,
  findingsById,
  targetUrl,
  onShowFinding,
}: FindingDetailProps) {
  const detail = useFindingDetail(scanId, finding.id);
  const data = detail.data;
  const findingChains =
    data?.chains ?? chains.filter((c) => finding.chain_ids.includes(c.id));

  return (
    <div
      id={id}
      className="grid gap-x-6 gap-y-5 border-t bg-muted/30 p-3 sm:p-4 lg:grid-cols-2"
    >
      <ScoreStorySection finding={finding} />

      {detail.isError && (
        <div className="lg:col-span-2">
          <ErrorState
            error={detail.error}
            title="Could not load the full details"
            onRetry={() => detail.refetch()}
            className="py-6"
          />
        </div>
      )}

      <AboutSection
        finding={finding}
        detail={data}
        loading={detail.isPending}
      />
      <VectorSection finding={finding} />
      <ContextSection
        finding={finding}
        detail={data}
        loading={detail.isPending}
        chains={findingChains}
        findingsById={findingsById}
        targetUrl={targetUrl}
        onShowFinding={onShowFinding}
      />
      <StandardsSection finding={finding} references={data?.references} />
      <EvidenceSection
        finding={finding}
        detail={data}
        loading={detail.isPending}
      />
    </div>
  );
}

// ------------------------------------------------------------- sections

function Section({
  title,
  children,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <section
      className={cn("flex min-w-0 flex-col gap-2", wide && "lg:col-span-2")}
    >
      <h3 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {title}
      </h3>
      {children}
    </section>
  );
}

function ScoreStorySection({ finding }: { finding: Finding }) {
  const story = scoreStory(finding);
  const Icon =
    story.direction === "up"
      ? ArrowUp
      : story.direction === "down"
        ? ArrowDown
        : ArrowRight;
  const baseSeverity = severityFromScore(finding.base_score);
  return (
    <Section title="Score story" wide>
      <div className="flex flex-col gap-3 rounded-xl border bg-card p-3 sm:flex-row sm:items-center sm:gap-4">
        <ScoreDisplay
          base={finding.base_score}
          final={finding.final_score}
          severity={finding.severity_bucket}
        />
        <div className="flex min-w-0 flex-col gap-1.5">
          <p
            data-testid="score-story"
            className="flex items-start gap-2 font-medium"
          >
            <Icon aria-hidden className="mt-0.5 size-4 shrink-0" />
            {story.sentence}
          </p>
          <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <SeverityBadge severity={baseSeverity} size="sm" />
            <ArrowRight aria-hidden className="size-3" />
            <SeverityBadge severity={finding.severity_bucket} size="sm" />
            <span>
              {story.method === "environmental"
                ? "CVSS v3.1 environmental score (CR/IR/AR from context)."
                : "Interim formula; not an official CVSS score."}
            </span>
          </p>
        </div>
      </div>
    </Section>
  );
}

function AboutSection({
  finding,
  detail,
  loading,
}: {
  finding: Finding;
  detail?: FindingDetailData;
  loading: boolean;
}) {
  return (
    <Section title="What it is">
      {loading ? (
        <TextSkeleton />
      ) : (
        // Skip a description that only repeats the evidence line below.
        detail?.description &&
        detail.description !== finding.evidence.text && (
          <p className="text-sm">{detail.description}</p>
        )
      )}
      {detail?.impact && (
        <p className="text-sm">
          <span className="font-medium">Impact: </span>
          {detail.impact}
        </p>
      )}
      {finding.recommendation && (
        <p className="text-sm">
          <span className="font-medium">Fix: </span>
          {finding.recommendation}
        </p>
      )}
      {finding.limitation && (
        <p className="rounded-lg border border-sev-medium-solid bg-sev-medium-bg px-3 py-2 text-sm text-sev-medium">
          <span className="font-medium">Limitation: </span>
          {finding.limitation}
        </p>
      )}
    </Section>
  );
}

function VectorSection({ finding }: { finding: Finding }) {
  const base = parseVector(finding.cvss_vector);
  const context = finding.final_vector
    ? parseVector(finding.final_vector)
    : null;
  const rows = base.ok
    ? compareVectors(base.metrics, context?.ok ? context.metrics : null)
    : [];

  return (
    <Section title="CVSS v3.1 vector">
      {!base.ok && <VectorError vector={base.vector} error={base.error} />}
      {context && !context.ok && (
        <VectorError vector={context.vector} error={context.error} />
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">
              CVSS metrics of the base vector and of the context-aware vector
            </caption>
            <thead className="border-b text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Metric
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  Base
                </th>
                <th scope="col" className="px-2 py-1.5 font-medium">
                  With context
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <VectorRow
                  key={row.code}
                  row={row}
                  hasContext={!!context?.ok}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!finding.final_vector && (
        <p className="text-xs text-muted-foreground">
          No context-aware vector: this check is still scored by the interim
          formula, not CVSS environmental metrics.
        </p>
      )}
      <ul className="flex flex-col gap-1 text-sm">
        <li>
          <CalculatorLink
            vector={finding.cvss_vector}
            label="Verify the base score"
          />
        </li>
        {finding.final_vector && (
          <li>
            <CalculatorLink
              vector={finding.final_vector}
              label="Verify the context-aware score"
            />
          </li>
        )}
      </ul>
    </Section>
  );
}

function VectorRow({
  row,
  hasContext,
}: {
  row: MetricRow;
  hasContext: boolean;
}) {
  return (
    <tr
      data-metric={row.code}
      data-changed={row.changed || undefined}
      className={cn(
        "border-b last:border-0",
        row.changed && "bg-sev-medium-bg font-medium text-sev-medium",
      )}
    >
      <th scope="row" className="px-2 py-1 font-normal">
        <span className="font-mono text-xs">{row.code}</span>{" "}
        <span className="text-muted-foreground">{row.name}</span>
      </th>
      <td className="px-2 py-1">{row.base ?? "—"}</td>
      <td className="px-2 py-1">
        {hasContext ? (row.context ?? row.base ?? "—") : "—"}
        {row.changed && (
          <span className="ml-1.5 inline-flex items-center gap-0.5 text-xs">
            {/* Only High weighs impact more than Not Defined (1.5 vs 1.0). */}
            {row.context === "High" && (
              <ArrowUp aria-hidden className="size-3" />
            )}
            set by context
          </span>
        )}
      </td>
    </tr>
  );
}

function VectorError({ vector, error }: { vector: string; error: string }) {
  return (
    <div
      role="note"
      className="rounded-lg border border-sev-critical-solid bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
    >
      <p className="font-medium">This vector could not be read: {error}</p>
      <p className="font-mono text-xs break-all">{vector || "(empty)"}</p>
    </div>
  );
}

function CalculatorLink({ vector, label }: { vector: string; label: string }) {
  if (!parseVector(vector).ok) return null;
  return (
    <a
      href={firstCalculatorUrl(vector)}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 underline underline-offset-4"
    >
      {label} on the FIRST CVSS v3.1 calculator
      <ExternalLink aria-hidden className="size-3.5" />{" "}
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

function ContextSection({
  finding,
  detail,
  loading,
  chains,
  findingsById,
  targetUrl,
  onShowFinding,
}: {
  finding: Finding;
  detail?: FindingDetailData;
  loading: boolean;
  chains: Chain[];
  findingsById: Map<string, Finding>;
  targetUrl: string;
  onShowFinding: (findingId: string) => void;
}) {
  const cls = finding.sensitivity_class;
  const endpoint = detail?.endpoint;
  const excerpt = bodyExcerpt(finding.evidence);
  return (
    <Section title="Context">
      <div className="flex flex-col gap-1 text-sm">
        <p className="font-medium">Endpoint sensitivity</p>
        {cls ? (
          <>
            <p>
              <span className="font-medium">{SENSITIVITY[cls].label}</span>{" "}
              <span className="text-muted-foreground">
                ({cls.toLowerCase()})
              </span>
              : {SENSITIVITY[cls].definition}
            </p>
            <p className="text-xs text-muted-foreground">
              {SENSITIVITY[cls].requirements}
            </p>
            {loading ? (
              <Skeleton className="h-4 w-2/3 motion-reduce:animate-none" />
            ) : (
              endpoint &&
              endpoint.sensitivity_reason.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  Classifier: {endpoint.sensitivity_reason.join("; ")}
                  {endpoint.sensitivity_confidence !== null &&
                    ` (confidence ${Math.round(endpoint.sensitivity_confidence * 100)}%)`}
                </p>
              )
            )}
          </>
        ) : (
          <p className="text-muted-foreground">
            None: a host-level finding (no single endpoint).
          </p>
        )}
      </div>

      <div className="flex flex-col gap-1 text-sm">
        <p className="font-medium">Sensitive data in the response</p>
        {finding.body_signals.length === 0 ? (
          <p className="text-muted-foreground">None detected.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {finding.body_signals.map((signal) => (
              <li key={signal}>
                <span className="font-medium">{SIGNALS[signal].label}</span>:{" "}
                {SIGNALS[signal].definition}
              </li>
            ))}
          </ul>
        )}
        {finding.body_signals.length > 0 && excerpt && (
          <CodeBlock label="Redacted response excerpt">{excerpt}</CodeBlock>
        )}
      </div>

      <div className="flex flex-col gap-2 text-sm">
        <p className="font-medium">Attack chains</p>
        {chains.length === 0 ? (
          <p className="text-muted-foreground">Not part of an attack chain.</p>
        ) : (
          chains.map((chain) => (
            <ChainCard
              key={chain.id}
              chain={chain}
              finding={finding}
              findingsById={findingsById}
              targetUrl={targetUrl}
              onShowFinding={onShowFinding}
            />
          ))
        )}
      </div>
    </Section>
  );
}

function ChainCard({
  chain,
  finding,
  findingsById,
  targetUrl,
  onShowFinding,
}: {
  chain: Chain;
  finding: Finding;
  findingsById: Map<string, Finding>;
  targetUrl: string;
  onShowFinding: (findingId: string) => void;
}) {
  const others = chain.finding_ids.filter((id) => id !== finding.id);
  const evidence = (chain.evidence ?? {}) as ChainEvidence;
  return (
    <div
      data-chain={chain.chain_code}
      className="flex flex-col gap-1.5 rounded-lg border border-sev-critical-solid/50 bg-card p-3"
    >
      <p className="flex flex-wrap items-center gap-2">
        <Link2 aria-hidden className="size-4 text-sev-critical" />
        <span className="font-mono text-xs">{chain.chain_code}</span>
        <span className="font-medium">{chain.name}</span>
      </p>
      <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <SeverityBadge severity={chain.severity} size="sm" />
        Chain score {chain.composite_score.toFixed(1)}
        {evidence.scope && <span>· scope: {evidence.scope.kind}</span>}
      </p>
      {chain.description && <p className="text-xs">{chain.description}</p>}
      {others.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          This finding is the only member
          {evidence.context?.body_signals?.length
            ? `; the chain fires because the response also contains ${evidence.context.body_signals
                .map((s) => SIGNALS[s]?.phrase ?? s)
                .join(" and ")}`
            : ""}
          .
        </p>
      ) : (
        <div className="flex flex-col gap-1">
          <p className="text-xs text-muted-foreground">With:</p>
          <ul className="flex flex-col gap-1">
            {others.map((otherId) => {
              const other = findingsById.get(otherId);
              return (
                <li key={otherId}>
                  <a
                    href={`#finding-${otherId}`}
                    data-chain-link={otherId}
                    onClick={(event) => {
                      event.preventDefault();
                      onShowFinding(otherId);
                    }}
                    className="text-xs underline underline-offset-4"
                  >
                    {other ? (
                      <>
                        <span className="font-mono">{other.check_id}</span>{" "}
                        {other.title}
                        {other.endpoint_url
                          ? ` on ${displayEndpoint(other.endpoint_url, targetUrl)}`
                          : " (whole host)"}
                      </>
                    ) : (
                      "A finding not in this list"
                    )}
                  </a>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}

function StandardsSection({
  finding,
  references,
}: {
  finding: Finding;
  references?: string[];
}) {
  const links = [
    ...finding.owasp_map.map((id) => ({ ...owaspLink(id), kind: "OWASP" })),
    ...finding.cwe_map.map((id) => ({ ...cweLink(id), kind: "CWE" })),
  ];
  return (
    <Section title="Standards">
      {links.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No OWASP or CWE mapping.
        </p>
      ) : (
        <ul className="flex flex-col gap-1 text-sm">
          {links.map((link) => (
            <li key={link.id}>
              {link.url ? (
                <a
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 underline underline-offset-4"
                >
                  <span className="font-mono text-xs">{link.id}</span>
                  {link.name && " "}
                  {link.name && <span>{link.name}</span>}
                  <ExternalLink aria-hidden className="size-3.5" />{" "}
                  <span className="sr-only">(opens in a new tab)</span>
                </a>
              ) : (
                <span className="font-mono text-xs">{link.id}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {references && references.length > 0 && (
        <ul className="flex flex-col gap-1 text-xs">
          {references.map((url) => (
            <li key={url}>
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="break-all underline underline-offset-4"
              >
                {url}
              </a>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function EvidenceSection({
  finding,
  detail,
  loading,
}: {
  finding: Finding;
  detail?: FindingDetailData;
  loading: boolean;
}) {
  const entries = evidenceEntries(finding.evidence);
  const snippet = detail
    ? httpSnippet(detail.endpoint, finding.evidence)
    : null;
  const text = finding.evidence.text;
  return (
    <Section title="Evidence" wide>
      {typeof text === "string" && <p className="text-sm">{text}</p>}
      {entries.length > 0 && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
          {entries.map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="font-mono text-xs text-muted-foreground">{key}</dt>
              <dd className="font-mono text-xs break-all">{value}</dd>
            </div>
          ))}
        </dl>
      )}
      {loading ? (
        <Skeleton className="h-24 w-full motion-reduce:animate-none" />
      ) : snippet ? (
        <>
          <CodeBlock label="Request and response">{snippet}</CodeBlock>
          <p className="text-xs text-muted-foreground">
            Rebuilt from what the scanner recorded. Secrets are redacted and
            cookie values are never stored.
          </p>
        </>
      ) : (
        detail &&
        !detail.endpoint && (
          <p className="text-xs text-muted-foreground">
            Host-level finding: no single request and response.
          </p>
        )
      )}
    </Section>
  );
}

/** Scrollable, keyboard-focusable code block. */
function CodeBlock({ label, children }: { label: string; children: string }) {
  return (
    <pre
      tabIndex={0}
      role="region"
      aria-label={label}
      className="max-h-72 overflow-auto rounded-lg border bg-card p-3 font-mono text-xs leading-relaxed whitespace-pre outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
    >
      <code>{children}</code>
    </pre>
  );
}

function TextSkeleton() {
  return (
    <div className="flex flex-col gap-1.5">
      <Skeleton className="h-4 w-full motion-reduce:animate-none" />
      <Skeleton className="h-4 w-4/5 motion-reduce:animate-none" />
    </div>
  );
}
