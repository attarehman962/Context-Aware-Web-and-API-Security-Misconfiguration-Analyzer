import type { ReactNode } from "react";

/**
 * One chart: title, the one-line takeaway, the chart, and the same numbers
 * as a table behind a disclosure (for screen readers and exact values).
 */
export function ChartCard({
  id,
  title,
  takeaway,
  children,
  table,
  note,
}: {
  id: string;
  title: string;
  takeaway: string;
  children: ReactNode;
  table?: ReactNode;
  note?: ReactNode;
}) {
  return (
    <figure
      aria-labelledby={`${id}-title`}
      className="flex min-w-0 flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5"
      data-chart={id}
    >
      <div className="flex flex-col gap-1">
        <h3 id={`${id}-title`} className="font-heading text-base font-semibold">
          {title}
        </h3>
        <figcaption className="text-sm" data-testid="takeaway">
          {takeaway}
        </figcaption>
      </div>
      {children}
      {note ? <p className="text-xs text-muted-foreground">{note}</p> : null}
      {table ? (
        <details className="text-sm">
          <summary className="w-fit cursor-pointer rounded py-1 text-muted-foreground outline-none hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50">
            Show the numbers
          </summary>
          <div className="relative mt-3 w-full min-w-0 overflow-x-auto">
            {table}
          </div>
        </details>
      ) : null}
    </figure>
  );
}

/** A plain numeric table for the "Show the numbers" disclosure. */
export function DataTable({
  caption,
  columns,
  rows,
}: {
  caption: string;
  columns: string[];
  rows: (string | number)[][];
}) {
  return (
    <table className="w-full text-left text-xs tabular-nums">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr className="border-b">
          {columns.map((c) => (
            <th key={c} scope="col" className="px-2 py-1.5 font-medium">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-b last:border-0">
            {r.map((cell, j) =>
              j === 0 ? (
                <th key={j} scope="row" className="px-2 py-1.5 font-medium">
                  {cell}
                </th>
              ) : (
                <td key={j} className="px-2 py-1.5">
                  {cell}
                </td>
              ),
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Legend({
  items,
}: {
  items: { label: string; color: string }[];
}) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs" aria-label="Legend">
      {items.map((i) => (
        <li key={i.label} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className="size-2.5 rounded-sm"
            style={{ background: i.color }}
          />
          {i.label}
        </li>
      ))}
    </ul>
  );
}
