import { CLASSES, type SensitivityClass } from "@/lib/evaluation";
import { cn } from "@/lib/utils";

/**
 * Hand label (rows) against the classifier (columns). Cell shade is one hue,
 * light to dark with the count (capped so the printed count keeps its
 * contrast in both themes); the diagonal (correct) cells are outlined.
 */
export function ConfusionMatrix({
  rows,
  max,
}: {
  rows: { truth: SensitivityClass; cells: number[] }[];
  max: number;
}) {
  return (
    <div className="relative w-full min-w-0 overflow-x-auto">
      <table className="w-full min-w-[20rem] border-separate border-spacing-0.5 text-sm tabular-nums">
        <caption className="sr-only">
          Confusion matrix: rows are the hand label, columns the classifier
        </caption>
        <thead>
          <tr>
            <th
              scope="col"
              className="p-1 text-left text-xs font-normal text-muted-foreground"
            >
              Label ↓ / predicted →
            </th>
            {CLASSES.map((c) => (
              <th key={c} scope="col" className="p-1 text-xs font-medium">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.truth}>
              <th scope="row" className="p-1 text-left text-xs font-medium">
                {r.truth}
              </th>
              {r.cells.map((n, i) => {
                const share = max ? n / max : 0;
                const correct = CLASSES[i] === r.truth;
                return (
                  <td
                    key={i}
                    title={`${r.truth} classed ${CLASSES[i]}: ${n}`}
                    data-cell={`${r.truth}-${CLASSES[i]}`}
                    className={cn(
                      "h-11 rounded-md text-center font-semibold text-foreground",
                      correct && "ring-2 ring-foreground ring-inset",
                    )}
                    style={{
                      background: `color-mix(in oklch, var(--viz-1) ${Math.round(
                        8 + share * 62,
                      )}%, var(--background))`,
                    }}
                  >
                    {n}
                    {correct ? (
                      <span className="sr-only"> (correct)</span>
                    ) : null}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
