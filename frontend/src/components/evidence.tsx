import { SafeBlock, SafeText, SafeUrl } from "@/components/safe-text";
import { AppLink, KeyValues, Mono } from "@/components/ui";
import type { Evidence } from "@/lib/api/types";
import { formatTime, shortId } from "@/lib/text";

// Captured, redacted HTTP evidence. Everything here came from the target, so
// it is shown as inert text only: headers as a table, the body excerpt in a
// <pre>, URLs as text (never links), control characters as visible markers.

function HeaderTable({ headers, label }: { headers: string[][]; label: string }) {
  if (headers.length === 0) return <p className="muted small">No {label.toLowerCase()}.</p>;
  return (
    <table className="table compact" aria-label={label}>
      <thead>
        <tr>
          <th scope="col">Header</th>
          <th scope="col">Value</th>
        </tr>
      </thead>
      <tbody>
        {headers.map((pair, index) => (
          <tr key={index}>
            <td className="mono">
              <SafeText value={pair[0]} />
            </td>
            <td className="mono wrap">
              <SafeText value={pair[1]} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EvidenceView({ evidence }: { evidence: Evidence }) {
  return (
    <article className="evidence" id={`ev-${evidence.id}`} aria-label="Captured evidence">
      <KeyValues
        rows={[
          ["Evidence", <Mono key="id">{evidence.id}</Mono>],
          [
            "Request",
            <span key="req">
              <Mono>{evidence.method}</Mono> <SafeUrl value={evidence.url} />
            </span>,
          ],
          ["Status", <Mono key="st">{evidence.status_code}</Mono>],
          ["Peer", <SafeText key="peer" value={evidence.peer} className="mono" />],
          ["Captured", formatTime(evidence.created_at)],
          [
            "Body",
            <span key="body">
              {evidence.body_bytes_captured} bytes captured
              {evidence.truncated ? " (truncated)" : ""} · SHA-256{" "}
              <Mono>{evidence.body_sha256}</Mono>
            </span>,
          ],
          [
            "Redactions",
            evidence.redactions.length > 0 ? (
              <SafeText key="red" value={evidence.redactions.join(", ")} />
            ) : (
              "None"
            ),
          ],
        ]}
      />
      <h4>Request headers (sent by the scanner)</h4>
      <HeaderTable headers={evidence.request_headers} label="Request headers" />
      <h4>Response headers</h4>
      <HeaderTable headers={evidence.response_headers} label="Response headers" />
      <h4>Body excerpt (redacted, shown as text)</h4>
      <SafeBlock value={evidence.body_excerpt} label="Body excerpt" />
    </article>
  );
}

/** A list of evidence identifiers linking to the evidence page. */
export function EvidenceLinks({ ids }: { ids: readonly string[] }) {
  if (ids.length === 0) return <span className="muted">None</span>;
  return (
    <span className="id-list">
      {ids.map((evidenceId) => (
        <AppLink key={evidenceId} href={`/evidence/${evidenceId}`}>
          <Mono>E-{shortId(evidenceId)}</Mono>
        </AppLink>
      ))}
    </span>
  );
}
