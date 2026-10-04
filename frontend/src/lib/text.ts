// Visible handling of characters that can hide or reorder text (ADR 0013).
//
// Every value from the API is untrusted. React already escapes it, so markup
// is inert; this module deals with the characters that are dangerous even as
// plain text: bidirectional overrides (U+202E can make "exe.txt" read as
// "txt.exe"), NUL and other control characters, and invisible formatting
// characters. They are not removed (evidence must stay faithful): each one is
// rendered as a visible ⟨U+XXXX⟩ marker instead.

export type Segment = { kind: "text"; value: string } | { kind: "control"; code: string };

const NAMES: Record<number, string> = {
  0x00: "NUL",
  0x1b: "ESC",
  0x7f: "DEL",
  0x200b: "ZWSP",
  0x200c: "ZWNJ",
  0x200d: "ZWJ",
  0x200e: "LRM",
  0x200f: "RLM",
  0x202a: "LRE",
  0x202b: "RLE",
  0x202c: "PDF",
  0x202d: "LRO",
  0x202e: "RLO",
  0x2066: "LRI",
  0x2067: "RLI",
  0x2068: "FSI",
  0x2069: "PDI",
  0x061c: "ALM",
  0xfeff: "BOM",
};

/** Whether a code point must be shown as a marker. Tab, line feed and
 *  carriage return are kept as-is only in multi-line text. */
export function isHiddenCodePoint(cp: number, multiline: boolean): boolean {
  if (multiline && (cp === 0x09 || cp === 0x0a || cp === 0x0d)) return false;
  return (
    cp <= 0x1f ||
    (cp >= 0x7f && cp <= 0x9f) ||
    cp === 0xad ||
    cp === 0x061c ||
    (cp >= 0x200b && cp <= 0x200f) ||
    (cp >= 0x2028 && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x2069) ||
    cp === 0xfeff ||
    (cp >= 0xfff9 && cp <= 0xfffb)
  );
}

export function codeLabel(cp: number): string {
  const hex = cp.toString(16).toUpperCase().padStart(4, "0");
  const name = NAMES[cp];
  return name ? `U+${hex} ${name}` : `U+${hex}`;
}

export function segmentText(value: string, multiline = false): Segment[] {
  const out: Segment[] = [];
  let buffer = "";
  for (const char of value) {
    const cp = char.codePointAt(0) ?? 0;
    if (isHiddenCodePoint(cp, multiline)) {
      if (buffer) out.push({ kind: "text", value: buffer });
      buffer = "";
      out.push({ kind: "control", code: codeLabel(cp) });
    } else {
      buffer += char;
    }
  }
  if (buffer) out.push({ kind: "text", value: buffer });
  return out;
}

/** The same text as a plain string with visible markers, for places that
 *  cannot hold markup (SVG <text>, attributes). Optionally shortened. */
export function visibleText(value: string, maxLength?: number): string {
  const out = segmentText(value)
    .map((s) => (s.kind === "text" ? s.value : `⟨${s.code}⟩`))
    .join("");
  if (maxLength === undefined || [...out].length <= maxLength) return out;
  return `${[...out].slice(0, maxLength - 1).join("")}…`;
}

export function hasHiddenCharacters(value: string): boolean {
  return segmentText(value).some((segment) => segment.kind === "control");
}

/** A short, stable form of a long identifier for tables (the full value is
 *  shown on detail pages). */
export function shortId(value: string): string {
  return value.length > 12 ? value.slice(0, 8) : value;
}

/** "still_open" → "Still open": labels for enum values the API defines. */
export function humanize(value: string): string {
  const text = value.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d+Z$/, " UTC");
}
