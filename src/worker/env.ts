/**
 * Minimal KV surface actually used by the Worker. Cloudflare's KVNamespace
 * satisfies this structurally; tests use an in-memory implementation.
 */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    opts?: { expirationTtl?: number; metadata?: unknown },
  ): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface Env {
  HANDOFFS: KVLike;
  /** set via `wrangler secret put BRIDGE_UPLOAD_TOKEN`; missing => uploads fail closed */
  BRIDGE_UPLOAD_TOKEN?: string;
  /** optional override for read rate limit (requests per minute per IP) */
  RATE_LIMIT_PER_MIN?: string;
  /** read lease in seconds after first claim (default 60, clamped 30..3600) */
  READ_LEASE_SECONDS?: string;
}
