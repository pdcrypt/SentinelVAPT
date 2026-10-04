import { notFound } from "next/navigation";

import { ErrorPanel } from "@/components/ui";
import type { UiError } from "@/lib/api/errors";

/** The page's main record could not be loaded: a real 404 for missing
 *  records, otherwise the mapped error. */
export function PageError({ error }: { error: UiError }) {
  if (error.status === 404) notFound();
  return <ErrorPanel error={error} />;
}
