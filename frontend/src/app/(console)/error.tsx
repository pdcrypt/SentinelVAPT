"use client";

// Last-resort error boundary. The error's message is never shown: it could
// carry internal details. Next.js gives a digest that matches the server log.
export default function Error({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  return (
    <div className="panel panel-error" role="alert">
      <strong>This page could not be displayed.</strong>
      <p>Nothing from the failure is shown here; check the frontend and backend logs.</p>
      {error.digest && (
        <p className="muted small">
          Reference: <code>{error.digest}</code>
        </p>
      )}
      <button type="button" className="btn" onClick={() => retry()}>
        Try again
      </button>
    </div>
  );
}
