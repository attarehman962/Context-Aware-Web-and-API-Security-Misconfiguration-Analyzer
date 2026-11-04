import { Legend } from "./chart-card";

export interface BarSeries {
  key: string;
  label: string;
  /** A CSS colour, e.g. "var(--viz-1)". */
  color: string;
}

export interface BarGroup {
  label: string;
  /** One value per series key; null draws no bar and says why. */
  values: Record<string, number | null>;
}

/**
 * Horizontal grouped bars: one block per group, one thin bar per series,
 * each with its value printed at the end (identity never by colour alone).
 * Horizontal so the labels stay readable at phone width.
 */
export function GroupedBars({
  label,
  series,
  groups,
  max,
  format = (v) => v.toFixed(2),
  missing = "no result",
}: {
  label: string;
  series: BarSeries[];
  groups: BarGroup[];
  max: number;
  format?: (v: number) => string;
  missing?: string;
}) {
  return (
    <div className="flex flex-col gap-3">
      <Legend items={series} />
      <dl aria-label={label} className="flex flex-col gap-3">
        {groups.map((g) => (
          <div
            key={g.label}
            className="grid grid-cols-[6.5rem_1fr] items-start gap-x-3 sm:grid-cols-[8rem_1fr]"
          >
            <dt className="pt-0.5 text-sm font-medium">{g.label}</dt>
            <dd className="flex min-w-0 flex-col gap-0.5">
              {series.map((s) => {
                const v = g.values[s.key];
                const text = v == null ? missing : format(v);
                return (
                  <div
                    key={s.key}
                    className="flex h-4 items-center gap-1.5"
                    title={`${g.label} · ${s.label}: ${text}`}
                  >
                    <span className="sr-only">{s.label}: </span>
                    {v == null ? null : (
                      <span
                        aria-hidden
                        className="h-3 rounded-r-[4px]"
                        style={{
                          width: `${Math.max((v / max) * 85, v > 0 ? 0.75 : 0)}%`,
                          background: s.color,
                        }}
                        data-value={v}
                      />
                    )}
                    <span className="text-xs text-muted-foreground tabular-nums">
                      {text}
                    </span>
                  </div>
                );
              })}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
