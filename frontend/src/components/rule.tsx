import { SafeText, SafeUrl } from "@/components/safe-text";
import { KeyValues } from "@/components/ui";

// Rule metadata as the API returns it. Shown as text (references are not
// links), like every other API value.

function str(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (typeof value === "number") return String(value);
  return null;
}

function listOf(value: unknown, prefix = ""): string {
  if (!Array.isArray(value) || value.length === 0) return "";
  return value
    .map((v) => str(v))
    .filter((v): v is string => v !== null)
    .map((v) => `${prefix}${v}`)
    .join(", ");
}

export function RuleView({ rule }: { rule: Record<string, unknown> }) {
  const references = Array.isArray(rule.references)
    ? rule.references.map(str).filter((v): v is string => v !== null)
    : [];
  return (
    <KeyValues
      rows={[
        [
          "Rule",
          <SafeText
            key="r"
            value={`${str(rule.id) ?? "?"} v${str(rule.version) ?? "?"} · ${str(rule.title) ?? ""}`}
          />,
        ],
        ["Description", <SafeText key="d" value={str(rule.description)} />],
        ["What the evidence proves", <SafeText key="p" value={str(rule.proves)} />],
        ["What it does not prove", <SafeText key="n" value={str(rule.does_not_prove)} />],
        ["Remediation", <SafeText key="m" value={str(rule.remediation)} />],
        ["OWASP Top 10", <SafeText key="o" value={listOf(rule.owasp_top10)} />],
        ["CWE", <SafeText key="c" value={listOf(rule.cwe, "CWE-")} />],
        ["OWASP WSTG", <SafeText key="w" value={listOf(rule.wstg)} />],
        [
          "References (not links)",
          references.length === 0 ? (
            <span key="x" className="muted">
              None
            </span>
          ) : (
            <ul key="x" className="small">
              {references.map((ref, i) => (
                <li key={i}>
                  <SafeUrl value={ref} />
                </li>
              ))}
            </ul>
          ),
        ],
      ]}
    />
  );
}
