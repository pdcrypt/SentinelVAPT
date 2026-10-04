import { StatusBadge } from "@/components/badges";
import { CheckboxField, DateTimeField, TextArea, TextField } from "@/components/fields";
import { SafeText, SafeUrl } from "@/components/safe-text";
import { Actor, KeyValues, Mono, Notice } from "@/components/ui";
import type { Target, TargetAuthorization } from "@/lib/api/types";
import { toDateTimeLocal } from "@/lib/actions/state";
import { formatTime } from "@/lib/text";

export function AuthorizationDisclaimer() {
  return (
    <Notice tone="warn">
      <strong>Authorization is recorded, not verified.</strong> SentinelVAPT stores who you say
      authorized testing, the reference and the window, and enforces that window and the scope on
      every scan. It cannot check that the authorization is genuine, and there is no platform login
      yet: the names you enter are self-asserted. Only test systems you are explicitly authorized to
      test, in a local lab.
    </Notice>
  );
}

/** Fields for a new authorization record (target creation, re-authorization). */
export function AuthorizationFields() {
  const now = new Date();
  const inThirtyDays = new Date(now.getTime() + 30 * 24 * 3600 * 1000);
  return (
    <fieldset>
      <legend>Authorization</legend>
      <AuthorizationDisclaimer />
      <TextField
        name="authorized_by"
        label="Authorized by"
        required
        hint="Who authorized this testing (e.g. the lab owner)."
      />
      <TextField
        name="reference"
        label="Reference"
        required
        hint="A ticket, letter or agreement reference."
      />
      <TextArea name="notes" label="Notes" maxLength={2000} />
      <DateTimeField name="valid_from" label="Valid from" defaultValue={toDateTimeLocal(now)} />
      <DateTimeField
        name="valid_until"
        label="Valid until"
        defaultValue={toDateTimeLocal(inThirtyDays)}
      />
      <TextField
        name="acknowledged_by"
        label="Acknowledged by"
        required
        hint="Your name (self-asserted: there is no platform login yet)."
      />
      <CheckboxField name="acknowledge" required>
        I confirm this testing is explicitly authorized for the scope above, and that I will only
        test it within the stated window.
      </CheckboxField>
    </fieldset>
  );
}

export function ScopeView({
  scope,
}: {
  scope: Pick<
    Target,
    | "base_url"
    | "environment"
    | "in_scope_hosts"
    | "allowed_ports"
    | "in_scope_path_prefixes"
    | "excluded_paths"
  >;
}) {
  const items = (values: readonly (string | number)[]) =>
    values.length === 0 ? (
      <span className="muted">None</span>
    ) : (
      <span className="id-list">
        {values.map((v, i) => (
          <SafeText key={i} value={String(v)} className="mono pill" />
        ))}
      </span>
    );
  return (
    <KeyValues
      rows={[
        ["Base URL", <SafeUrl key="u" value={scope.base_url} />],
        [
          "Environment",
          <span key="e">
            <Mono>{scope.environment}</Mono>
            {scope.environment !== "local_lab" && (
              <span className="muted"> · scans of this environment are refused</span>
            )}
          </span>,
        ],
        ["In-scope hosts", items(scope.in_scope_hosts)],
        ["Allowed ports", items(scope.allowed_ports)],
        ["In-scope path prefixes", items(scope.in_scope_path_prefixes)],
        ["Excluded paths", items(scope.excluded_paths)],
      ]}
    />
  );
}

export function AuthorizationSummaryView({
  auth,
}: {
  auth: Pick<
    TargetAuthorization,
    | "version"
    | "status"
    | "authorized_by"
    | "reference"
    | "notes"
    | "valid_from"
    | "valid_until"
    | "acknowledged_by"
    | "acknowledged_at"
  >;
}) {
  return (
    <KeyValues
      rows={[
        [
          "Version / status",
          <span key="v">
            v{auth.version} <StatusBadge status={auth.status} />
          </span>,
        ],
        ["Window (UTC)", `${formatTime(auth.valid_from)} → ${formatTime(auth.valid_until)}`],
        ["Authorized by", <Actor key="a" name={auth.authorized_by} />],
        ["Reference", <SafeText key="r" value={auth.reference} />],
        ["Notes", <SafeText key="n" value={auth.notes} />],
        ["Acknowledged by", <Actor key="k" name={auth.acknowledged_by} />],
        ["Acknowledged at", formatTime(auth.acknowledged_at)],
      ]}
    />
  );
}
