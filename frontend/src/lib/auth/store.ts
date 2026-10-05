import "server-only";

import { createHash, randomBytes } from "node:crypto";

// Browser sessions held by the Next.js server (ADR 0014, Phase 9 M8).
//
// The browser's cookie carries a random 256-bit id. This store maps it to the
// API's bearer token, which therefore never leaves this process: not in a
// cookie, not in HTML, not in client JavaScript. Entries are keyed by the
// SHA-256 of the id, so the map never holds a usable cookie value.
//
// The store is in memory: the console is a single local Next.js process
// (ADR 0005). Restarting it signs everyone out; the orphaned API sessions
// then expire on their idle timeout, and nobody holds their tokens. The API
// stays the authority: an entry here only says which token to present, and
// every request is validated by the API again.

export type StoredSession = {
  readonly token: string;
  /** The API session's absolute expiry (epoch ms). */
  readonly expiresAt: number;
};

const ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const MAX_SESSIONS = 1000;

function key(id: string): string {
  return createHash("sha256").update(id).digest("hex");
}

export class SessionStore {
  private readonly entries = new Map<string, StoredSession>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly max: number = MAX_SESSIONS,
  ) {}

  get size(): number {
    return this.entries.size;
  }

  /** Stores a token under a fresh random id and returns the id. Ids are never
   *  chosen by the client and never reused (no session fixation). */
  create(token: string, expiresAt: number): string {
    this.prune();
    while (this.entries.size >= this.max) {
      // Evict the session closest to its absolute expiry.
      let victim: string | null = null;
      let soonest = Infinity;
      for (const [k, entry] of this.entries) {
        if (entry.expiresAt < soonest) [victim, soonest] = [k, entry.expiresAt];
      }
      if (victim === null) break;
      this.entries.delete(victim);
    }
    const id = randomBytes(32).toString("base64url");
    this.entries.set(key(id), { token, expiresAt });
    return id;
  }

  get(id: string | null | undefined): StoredSession | null {
    if (!id || !ID_PATTERN.test(id)) return null;
    const k = key(id);
    const entry = this.entries.get(k);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(k);
      return null;
    }
    return entry;
  }

  delete(id: string | null | undefined): StoredSession | null {
    if (!id || !ID_PATTERN.test(id)) return null;
    const k = key(id);
    const entry = this.entries.get(k) ?? null;
    this.entries.delete(k);
    return entry;
  }

  private prune(): void {
    const now = this.now();
    for (const [k, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(k);
    }
  }
}

// One store per server process, shared by every route bundle (Next.js may
// load a module once per route, so a module-level instance would not be).
const GLOBAL_KEY = Symbol.for("sentinelvapt.browserSessions");

export function sessionStore(): SessionStore {
  const holder = globalThis as unknown as Record<symbol, SessionStore | undefined>;
  holder[GLOBAL_KEY] ??= new SessionStore();
  return holder[GLOBAL_KEY];
}
