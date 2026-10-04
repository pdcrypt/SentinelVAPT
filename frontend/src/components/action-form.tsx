"use client";

import { useActionState, type ReactNode } from "react";

import { ErrorPanel } from "@/components/ui";
import { IDLE, type ActionState } from "@/lib/actions/state";

// A form bound to a Server Action. The action runs on the Next.js server
// (which calls the API); the browser only ever posts to this origin, and the
// action checks Host and Origin before doing anything (ADR 0013).

export function ActionForm({
  action,
  submitLabel,
  pendingLabel = "Working…",
  children,
  className = "form",
  variant = "primary",
  testId,
}: {
  action: (state: ActionState, form: FormData) => Promise<ActionState>;
  submitLabel: string;
  pendingLabel?: string;
  children?: ReactNode;
  className?: string;
  variant?: "primary" | "secondary" | "danger";
  testId?: string;
}) {
  const [state, formAction, pending] = useActionState(action, IDLE);
  const buttonClass =
    variant === "primary" ? "btn" : variant === "danger" ? "btn btn-danger" : "btn btn-secondary";
  return (
    <form action={formAction} className={className} data-testid={testId}>
      {children}
      <div className="actions">
        <button type="submit" className={buttonClass} disabled={pending}>
          {pending ? pendingLabel : submitLabel}
        </button>
      </div>
      {state.status === "error" && <ErrorPanel error={state.error} />}
      {state.status === "ok" && (
        <p className="result-ok" role="status">
          {state.message}
        </p>
      )}
    </form>
  );
}
