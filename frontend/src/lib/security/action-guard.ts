import "server-only";

import { headers } from "next/headers";

import { allowedHosts, checkRequest } from "@/lib/security/request-guard";

export class WriteRefusedError extends Error {
  constructor(readonly reason: string) {
    super("This request was refused.");
  }
}

/** First statement of every Server Action: the same Host/Origin decision the
 *  proxy makes, repeated here so a matcher change or a moved action can never
 *  silently remove it (Server Actions are POSTs to the page route). */
export async function assertWriteAllowed(): Promise<void> {
  const decision = checkRequest("POST", await headers(), allowedHosts());
  if (!decision.ok) throw new WriteRefusedError(decision.reason);
}
