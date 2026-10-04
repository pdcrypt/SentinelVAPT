import { COMPARISON_STATES, SEVERITIES, type LineageEntry } from "@/lib/api/types";
import { humanize, visibleText } from "@/lib/text";

// Server-rendered SVG charts (ADR 0013): no client chart library, no inline
// scripts or styles (colours come from CSS classes), accessible titles,
// descriptions and text labels. They only display counts and relationships
// the API returns; nothing is classified or recomputed here.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type Bar = { key: string; label: string; value: number; cls: string };

function BarChart({
  id,
  title,
  bars,
  testId,
}: {
  id: string;
  title: string;
  bars: Bar[];
  testId: string;
}) {
  const rowHeight = 24;
  const labelWidth = 130;
  const barMax = 300;
  const width = labelWidth + barMax + 60;
  const height = bars.length * rowHeight + 8;
  const top = Math.max(1, ...bars.map((b) => b.value));
  const total = bars.reduce((sum, b) => sum + b.value, 0);
  const description = bars.map((b) => `${b.label}: ${b.value}`).join("; ");
  return (
    <svg
      className="chart"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-labelledby={`${id}-title ${id}-desc`}
      data-testid={testId}
    >
      <title id={`${id}-title`}>{`${title} (total ${total})`}</title>
      <desc id={`${id}-desc`}>{description}</desc>
      <line className="axis" x1={labelWidth} y1={0} x2={labelWidth} y2={height} />
      {bars.map((bar, index) => {
        const y = 4 + index * rowHeight;
        const w = Math.round((bar.value / top) * barMax);
        return (
          <g key={bar.key} data-key={bar.key} data-value={bar.value}>
            <text x={labelWidth - 8} y={y + 13} textAnchor="end">
              {bar.label}
            </text>
            <rect className={bar.cls} x={labelWidth} y={y} width={w} height={16} rx={2} />
            <text x={labelWidth + w + 6} y={y + 13}>
              {bar.value}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/** Findings by severity, from the API's finding summary (rule-engine
 *  results). Unknown severity keys are shown after the known ones. */
export function SeverityChart({ counts }: { counts: Record<string, unknown> }) {
  const value = (key: string) => (typeof counts[key] === "number" ? (counts[key] as number) : 0);
  const known: readonly string[] = SEVERITIES;
  const extra = Object.keys(counts)
    .filter((k) => !known.includes(k))
    .sort();
  const bars: Bar[] = [...SEVERITIES, ...extra].map((key) => ({
    key,
    label: visibleText(humanize(key), 16),
    value: value(key),
    cls: known.includes(key) ? `bar-sev-${key}` : "bar-sev-informational",
  }));
  return (
    <BarChart id="severity" title="Findings by severity" bars={bars} testId="severity-chart" />
  );
}

/** Records per persisted comparison state, from the comparison's stored
 *  summary. Labels are the stored state names in upper case. */
export function StateChart({ counts }: { counts: Record<string, unknown> }) {
  const bars: Bar[] = COMPARISON_STATES.map((state) => ({
    key: state,
    label: state.toUpperCase(),
    value: typeof counts[state] === "number" ? (counts[state] as number) : 0,
    cls: `bar-state-${state}`,
  }));
  return <BarChart id="states" title="Comparison states" bars={bars} testId="state-chart" />;
}

/** The retest chain A → B → C as the API's lineage endpoint returns it. */
export function LineageChart({
  entries,
  currentId,
}: {
  entries: LineageEntry[];
  currentId: string;
}) {
  const nodeWidth = 170;
  const gap = 46;
  const height = 92;
  const width = Math.max(1, entries.length) * (nodeWidth + gap);
  const description = entries
    .map(
      (e) =>
        `${e.position}: ${visibleText(e.name, 60)} (${e.status}, ${e.comparisons.length} comparison${e.comparisons.length === 1 ? "" : "s"})`,
    )
    .join(" → ");
  return (
    <svg
      className="chart"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-labelledby="lineage-title lineage-desc"
      data-testid="lineage-chart"
    >
      <title id="lineage-title">Retest lineage</title>
      <desc id="lineage-desc">{description}</desc>
      {entries.map((entry, index) => {
        const x = index * (nodeWidth + gap) + 2;
        const isCurrent = entry.assessment_id === currentId;
        const label = visibleText(entry.name, 22);
        const node = (
          <>
            <rect
              className={isCurrent ? "node node-current" : "node"}
              x={x}
              y={10}
              width={nodeWidth}
              height={66}
              rx={6}
            />
            <text x={x + 10} y={30}>
              {index === 0 ? "Original" : `Retest ${index}`}
            </text>
            <text x={x + 10} y={48}>
              {label}
            </text>
            <text x={x + 10} y={66} className="muted-text">
              {`${humanize(entry.status)} · ${entry.comparisons.length} cmp`}
            </text>
          </>
        );
        return (
          <g key={entry.assessment_id} data-position={entry.position}>
            {index > 0 && <path className="edge" d={`M ${x - gap + 2} 43 L ${x - 2} 43`} />}
            {UUID.test(entry.assessment_id) ? (
              <a
                href={`/${index === 0 ? "assessments" : "retests"}/${entry.assessment_id}`}
                aria-label={`${label} (${entry.status})`}
              >
                {node}
              </a>
            ) : (
              node
            )}
          </g>
        );
      })}
    </svg>
  );
}
