import { ScoreDisplay } from "@/components/score-display";
import { SeverityBadge } from "@/components/severity-badge";
import type { Finding } from "@/lib/api-types";

/** Basic ranked list of findings: severity, score, check, endpoint. */
export function FindingsTable({
  findings,
  targetUrl,
}: {
  findings: Finding[];
  /** Endpoints on the target's origin are shown as paths. */
  targetUrl: string;
}) {
  return (
    <div className="overflow-x-auto rounded-xl border">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">
          Findings, ranked by context-aware score, highest first
        </caption>
        <thead className="border-b bg-muted/50 text-muted-foreground">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">
              Severity
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Score
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Check
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Endpoint
            </th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.id}
              data-check-id={f.check_id}
              className="border-b last:border-0"
            >
              <td className="px-3 py-2 align-top">
                <SeverityBadge severity={f.severity_bucket} size="sm" />
              </td>
              <td className="px-3 py-2 align-top">
                <ScoreDisplay
                  base={f.base_score}
                  final={f.final_score}
                  severity={f.severity_bucket}
                  compact
                />
              </td>
              <td className="px-3 py-2 align-top">
                <div className="font-mono text-xs text-muted-foreground">
                  {f.check_id}
                </div>
                <div className="font-medium">{f.title}</div>
              </td>
              <td className="px-3 py-2 align-top">
                {f.endpoint_url ? (
                  <span
                    className="font-mono text-xs break-all"
                    title={f.endpoint_url}
                  >
                    {displayEndpoint(f.endpoint_url, targetUrl)}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Whole host</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Path (+ query) when the endpoint is on the target's origin, else the URL. */
export function displayEndpoint(
  endpointUrl: string,
  targetUrl: string,
): string {
  try {
    const endpoint = new URL(endpointUrl);
    if (endpoint.origin === new URL(targetUrl).origin) {
      return endpoint.pathname + endpoint.search;
    }
  } catch {
    // Not a URL we can parse: show it as sent.
  }
  return endpointUrl;
}
