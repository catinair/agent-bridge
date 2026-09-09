/**
 * In-memory KV implementation mirroring Cloudflare KV's TTL semantics
 * (expirationTtl in seconds, lazy purge on read). Used by unit tests and the
 * local dev server so the exact Worker code runs unchanged on Node.
 */
import type { KVLike } from '../worker/env.js';

interface Entry {
  value: string;
  expiresAt: number | null;
}

export class InMemoryKV implements KVLike {
  private store = new Map<string, Entry>();

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number; metadata?: unknown },
  ): Promise<void> {
    const ttl = opts?.expirationTtl;
    this.store.set(key, {
      value,
      expiresAt: ttl && ttl > 0 ? Date.now() + ttl * 1000 : null,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}
