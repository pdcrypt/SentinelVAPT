import "server-only";

import { allPages, listAuthorizations } from "@/lib/api/endpoints";
import type { Assessment, TargetAuthorization } from "@/lib/api/types";

/** The authorization records (with their exact scopes) a baseline assessment
 *  and its retest were planned under. Both belong to the same target. */
export async function retestScopes(
  baseline: Assessment,
  retest: Assessment,
): Promise<{ baseline: TargetAuthorization; retest: TargetAuthorization } | null> {
  const records = await allPages(() => listAuthorizations(retest.target_id), 1);
  const b = records.find((r) => r.id === baseline.authorization_id);
  const r = records.find((x) => x.id === retest.authorization_id);
  return b && r ? { baseline: b, retest: r } : null;
}
