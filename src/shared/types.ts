/**
 * Wire format shared by CLI (encrypt), Worker (validate/store) and the
 * browser viewer / any reasoning agent (decrypt).
 */

import { isValidBase64 } from './codec.js';

export interface HandoffEnvelope {
  /** protocol self-description; always "agent-handoff" */
  protocol?: 'agent-handoff';
  v: 1;
  algorithm: 'AES-256-GCM';
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  /** base64 */
  salt: string;
  /** base64, 12 bytes for GCM */
  iv: string;
  /** base64, ciphertext + 16-byte GCM tag */
  ciphertext: string;
  content_type: string;
  /** plaintext encoding, e.g. "utf-8" */
  encoding?: string;
  /** how the secret is displayed, e.g. "base32-crockford-grouped-4" */
  secret_encoding?: string;
  /** how to turn the displayed secret into KDF input */
  secret_normalization?: string;
  /** server-assigned ISO timestamps */
  created_at?: string;
  expires_at?: string;
}

export interface CreateHandoffRequest extends HandoffEnvelope {
  /** seconds, server clamps/validates; never stored with the envelope */
  expires_in?: number;
}

export interface CreateHandoffResponse {
  id: string;
  url: string;
  api_url: string;
  created_at: string;
  expires_at: string;
}

export const LIMITS = {
  /** KV requires >= 60s TTL; spec default is 300s */
  minTtlSeconds: 60,
  maxTtlSeconds: 3600,
  defaultTtlSeconds: 300,
  /** single-document plaintext cap enforced client-side before encryption */
  maxPlaintextBytes: 2_000_000,
  /** context-bundle total plaintext cap enforced client-side */
  maxBundleBytes: 4_000_000,
  /** ciphertext cap accepted by the server (largest plaintext mode + GCM tag headroom) */
  maxCiphertextBytes: 4_400_000,
  /** raw POST body cap (base64 inflation of the largest ciphertext + JSON) */
  maxEnvelopeJsonBytes: 8_000_000,
  minIterations: 100_000,
  maxIterations: 2_000_000,
} as const;

export const DEFAULT_CONTENT_TYPE = 'text/markdown';
export const ALGORITHM = 'AES-256-GCM';
export const KDF = 'PBKDF2-SHA256';

export function validateEnvelope(value: unknown):
  | { ok: true; envelope: HandoffEnvelope; expires_in: number }
  | { ok: false; error: string } {
  if (typeof value !== 'object' || value === null) {
    return { ok: false, error: 'body must be a JSON object' };
  }
  const v = value as Record<string, unknown>;

  if (v.v !== 1) return { ok: false, error: 'unsupported envelope version' };
  if (v.algorithm !== ALGORITHM) return { ok: false, error: 'unsupported algorithm' };
  if (v.kdf !== KDF) return { ok: false, error: 'unsupported kdf' };

  const iterations = v.iterations;
  if (typeof iterations !== 'number' || !Number.isInteger(iterations) ||
      iterations < LIMITS.minIterations || iterations > LIMITS.maxIterations) {
    return { ok: false, error: `iterations must be an integer in [${LIMITS.minIterations}, ${LIMITS.maxIterations}]` };
  }

  if (typeof v.salt !== 'string' || !isValidBase64(v.salt, 64)) {
    return { ok: false, error: 'salt must be valid base64 (<= 64 bytes)' };
  }
  if (typeof v.iv !== 'string' || !isValidBase64(v.iv, 64)) {
    return { ok: false, error: 'iv must be valid base64' };
  }
  if (base64ToBytesLen(v.iv) !== 12) {
    return { ok: false, error: 'iv must be 12 bytes' };
  }
  if (typeof v.ciphertext !== 'string' || !isValidBase64(v.ciphertext, LIMITS.maxCiphertextBytes)) {
    return { ok: false, error: 'ciphertext missing or too large' };
  }
  if (base64ToBytesLen(v.ciphertext) < 17) {
    return { ok: false, error: 'ciphertext too short' };
  }

  let contentType = DEFAULT_CONTENT_TYPE;
  if (v.content_type !== undefined) {
    if (typeof v.content_type !== 'string' || v.content_type.length > 100 ||
        !/^[\w.+-]+\/[\w.+-]+$/.test(v.content_type)) {
      return { ok: false, error: 'invalid content_type' };
    }
    contentType = v.content_type;
  }

  // --- protocol self-description (V2, optional for backward compatibility) ---
  if (v.protocol !== undefined && v.protocol !== 'agent-handoff') {
    return { ok: false, error: 'unknown protocol' };
  }
  let encoding = 'utf-8';
  if (v.encoding !== undefined) {
    if (typeof v.encoding !== 'string' || !/^[a-z0-9_-]{1,32}$/.test(v.encoding)) {
      return { ok: false, error: 'invalid encoding' };
    }
    encoding = v.encoding;
  }
  let secretEncoding = 'base32-crockford-grouped-4';
  if (v.secret_encoding !== undefined) {
    if (typeof v.secret_encoding !== 'string' || !/^[a-z0-9_-]{1,64}$/.test(v.secret_encoding)) {
      return { ok: false, error: 'invalid secret_encoding' };
    }
    secretEncoding = v.secret_encoding;
  }
  let secretNormalization = 'strip-hyphens-whitespace-uppercase';
  if (v.secret_normalization !== undefined) {
    if (typeof v.secret_normalization !== 'string' || !/^[a-z0-9_-]{1,64}$/.test(v.secret_normalization)) {
      return { ok: false, error: 'invalid secret_normalization' };
    }
    secretNormalization = v.secret_normalization;
  }

  let expiresIn: number = LIMITS.defaultTtlSeconds;
  if (v.expires_in !== undefined) {
    if (typeof v.expires_in !== 'number' || !Number.isInteger(v.expires_in) ||
        v.expires_in < LIMITS.minTtlSeconds || v.expires_in > LIMITS.maxTtlSeconds) {
      return { ok: false, error: `expires_in must be an integer in [${LIMITS.minTtlSeconds}, ${LIMITS.maxTtlSeconds}] seconds` };
    }
    expiresIn = v.expires_in;
  }

  return {
    ok: true,
    envelope: {
      protocol: 'agent-handoff',
      v: 1,
      algorithm: ALGORITHM,
      kdf: KDF,
      iterations,
      salt: v.salt as string,
      iv: v.iv as string,
      ciphertext: v.ciphertext as string,
      content_type: contentType,
      encoding,
      secret_encoding: secretEncoding,
      secret_normalization: secretNormalization,
    },
    expires_in: expiresIn,
  };
}

function base64ToBytesLen(b64: string): number {
  try {
    return atob(b64).length;
  } catch {
    return -1;
  }
}
