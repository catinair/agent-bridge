/**
 * Client-side end-to-end encryption for handoffs.
 *
 * - secret: 160 bits of CSPRNG output, displayed as Crockford base32
 *   in `XXXX-XXXX-...` groups (8 groups, 32 chars).
 * - key: PBKDF2-SHA256(secret, 16-byte salt, iterations) -> 256-bit AES-GCM key.
 *   PBKDF2 is the deliberate choice over Argon2id: it is the only modern KDF
 *   available in both Node and browser WebCrypto without native/WASM deps,
 *   which the zero-knowledge browser viewer requires.
 * - payload: AES-256-GCM, 12-byte random IV. Wrong secret fails GCM auth.
 *
 * Runs unchanged on Node (>=18 webcrypto), Cloudflare Workers and browsers.
 */

import {
  base32CrockfordEncode,
  base64ToBytes,
  bytesToBase64,
  normalizeBase32,
} from './codec.js';
import {
  ALGORITHM,
  DEFAULT_CONTENT_TYPE,
  HandoffEnvelope,
  KDF,
  LIMITS,
} from './types.js';

export const DEFAULT_ITERATIONS = 600_000;

export function generateSecret(): string {
  const bytes = new Uint8Array(20); // 160 bits >= required 128
  crypto.getRandomValues(bytes);
  const encoded = base32CrockfordEncode(bytes); // 32 chars
  return (encoded.match(/.{4}/g) ?? []).join('-');
}

export function normalizeSecret(input: string): string {
  return normalizeBase32(input);
}

export async function deriveKey(
  secret: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(normalizeSecret(secret)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface EncryptResult {
  secret: string;
  envelope: HandoffEnvelope;
}

export async function encryptHandoff(
  plaintext: string,
  opts: { iterations?: number; contentType?: string } = {},
): Promise<EncryptResult> {
  const iterations = opts.iterations ?? DEFAULT_ITERATIONS;
  if (iterations < LIMITS.minIterations || iterations > LIMITS.maxIterations) {
    throw new Error(`iterations out of range [${LIMITS.minIterations}, ${LIMITS.maxIterations}]`);
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const secret = generateSecret();
  const key = await deriveKey(secret, salt, iterations);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    new TextEncoder().encode(plaintext),
  );
  return {
    secret,
    envelope: {
      protocol: 'agent-handoff',
      v: 1,
      algorithm: ALGORITHM,
      kdf: KDF,
      iterations,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
      content_type: opts.contentType ?? DEFAULT_CONTENT_TYPE,
      encoding: 'utf-8',
      secret_encoding: 'base32-crockford-grouped-4',
      secret_normalization: 'strip-hyphens-whitespace-uppercase',
    },
  };
}

export class DecryptionError extends Error {
  constructor(message = 'decryption failed (wrong password or corrupted payload)') {
    super(message);
    this.name = 'DecryptionError';
  }
}

export async function decryptHandoff(
  envelope: HandoffEnvelope,
  secret: string,
): Promise<string> {
  if (envelope.algorithm !== ALGORITHM || envelope.kdf !== KDF || envelope.v !== 1) {
    throw new DecryptionError('unsupported envelope');
  }
  let key: CryptoKey;
  try {
    key = await deriveKey(
      secret,
      base64ToBytes(envelope.salt),
      envelope.iterations,
    );
  } catch {
    throw new DecryptionError('invalid secret or envelope parameters');
  }
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(envelope.iv) as BufferSource },
      key,
      base64ToBytes(envelope.ciphertext) as BufferSource,
    );
  } catch {
    throw new DecryptionError();
  }
  return new TextDecoder().decode(plaintext);
}
