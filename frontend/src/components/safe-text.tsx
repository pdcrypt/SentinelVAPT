import { segmentText } from "@/lib/text";

// Untrusted text from the API. React escapes it (markup is inert); <bdi>
// isolates its direction from the surrounding UI; control, bidi and
// invisible characters appear as visible ⟨U+XXXX⟩ markers (lib/text.ts).

export function SafeText({
  value,
  multiline = false,
  className,
}: {
  value: string | null | undefined;
  multiline?: boolean;
  className?: string;
}) {
  if (value === null || value === undefined || value === "") {
    return <span className="muted">—</span>;
  }
  return (
    <bdi className={className}>
      {segmentText(value, multiline).map((segment, index) =>
        segment.kind === "text" ? (
          segment.value
        ) : (
          <span key={index} className="ctl" aria-label={`control character ${segment.code}`}>
            {`⟨${segment.code}⟩`}
          </span>
        ),
      )}
    </bdi>
  );
}

/** A URL or host from the API, shown as text. Never a link: target-controlled
 *  URLs are not made clickable (ADR 0013). */
export function SafeUrl({ value }: { value: string | null | undefined }) {
  return <SafeText value={value} className="url mono" />;
}

/** Multi-line captured content (response excerpts): inert text in a <pre>. */
export function SafeBlock({ value, label }: { value: string | null | undefined; label: string }) {
  return (
    <pre className="block" aria-label={label}>
      <SafeText value={value} multiline />
    </pre>
  );
}
