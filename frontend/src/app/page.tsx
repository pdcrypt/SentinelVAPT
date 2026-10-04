import { getApiStatus } from "@/lib/api/health";

// Render per request so the API status is live, not baked in at build time.
export const dynamic = "force-dynamic";

export default async function HomePage() {
  const status = await getApiStatus();

  return (
    <main className="container">
      <h1>SentinelVAPT</h1>
      <p className="lede">
        Authorized web application security assessment and reporting, for local labs and explicitly
        authorized targets only.
      </p>

      <section aria-label="System status" className="card">
        <h2>System status</h2>
        <p data-testid="api-status">
          API:{" "}
          {status.reachable ? (
            <span className="ok">online (v{status.version})</span>
          ) : (
            <span className="bad">unavailable</span>
          )}
        </p>
      </section>
    </main>
  );
}
