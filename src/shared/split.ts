/**
 * Split transport for Context Bundles (v1.3).
 *
 * Web-retrieval agents cannot reliably consume one giant ciphertext as a
 * precise byte stream, so the transport now matches the bundle abstraction:
 * the manifest and every file are encrypted as independent objects with the
 * same handoff secret (single PBKDF2-derived key, per-object random IV) and
 * AES-GCM additionalData binding `agent-handoff/v2/<handoffId>/<objectId>`,
 * which prevents an untrusted relay from reordering, renaming or splicing
 * objects. Agents read the manifest first, then fetch + decrypt exactly the
 * files they need.
 *
 * The handoff id is generated client-side (still 130-bit, non-enumerable) so
 * it can be bound into the AAD before upload; the server only checks format
 * and collisions.
 */
import { base32CrockfordEncode, bytesToBase64, base64ToBytes } from './codec.js';

export const SPLIT_LAYOUT = 'split';
export const MANIFEST_OBJECT_ID = 'manifest';
export const AAD_PREFIX = 'agent-handoff/v2';

export interface SplitObject {
  object_id: string;
  iv: string;
  ciphertext: string;
}

export interface SplitManifestFile {
  object_id: string;
  path: string;
  media_type: string;
  size: number;
  sha256: string;
}

export interface SplitManifest {
  protocol: 'agent-context-bundle';
  version: number;
  request: { prompt: string };
  notes?: string;
  generated_at: string;
  generator: string;
  files: SplitManifestFile[];
}

export interface SplitRecord {
  protocol: 'agent-handoff';
  v: 1;
  layout: typeof SPLIT_LAYOUT;
  id: string;
  algorithm: 'AES-256-GCM';
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  content_type: string;
  encoding: string;
  secret_encoding: string;
  secret_normalization: string;
  objects: SplitObject[];
  created_at?: string;
  expires_at?: string;
}

export function aadFor(handoffId: string, objectId: string): Uint8Array {
  return new TextEncoder().encode(`${AAD_PREFIX}/${handoffId}/${objectId}`);
}

export function generateHandoffId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(17));
  return base32CrockfordEncode(bytes).slice(0, 26);
}

export function isValidHandoffId(id: string): boolean {
  return /^[A-Za-z0-9]{16,64}$/.test(id);
}

export function isManifestObject(objectId: string): boolean {
  return objectId === MANIFEST_OBJECT_ID;
}

export function fileObjectId(index: number): string {
  return `f${index + 1}`;
}

/**
 * Derive the object key once per handoff and reuse it across objects; every
 * object gets a fresh random 96-bit IV and an AAD binding to its id, which
 * keeps GCM usage sound for bundle-sized object counts.
 */
export async function buildSplitRecord(opts: {
  handoffId: string;
  secret: string;
  iterations: number;
  manifest: SplitManifest;
  fileTexts: Array<{ objectId: string; text: string }>;
  contentType: string;
}): Promise<SplitRecord> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromSecret(opts.secret, salt, opts.iterations);
  const objects: SplitObject[] = [];

  objects.push({
    object_id: MANIFEST_OBJECT_ID,
    ...(await encryptObject(key, opts.handoffId, MANIFEST_OBJECT_ID, JSON.stringify(opts.manifest, null, 2))),
  });

  for (const file of opts.fileTexts) {
    objects.push({
      object_id: file.objectId,
      ...(await encryptObject(key, opts.handoffId, file.objectId, file.text)),
    });
  }

  return {
    protocol: 'agent-handoff',
    v: 1,
    layout: SPLIT_LAYOUT,
    id: opts.handoffId,
    algorithm: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: opts.iterations,
    salt: bytesToBase64(salt),
    content_type: opts.contentType,
    encoding: 'utf-8',
    secret_encoding: 'base32-crockford-grouped-4',
    secret_normalization: 'strip-hyphens-whitespace-uppercase',
    objects,
  };
}

async function encryptObject(
  key: CryptoKey,
  handoffId: string,
  objectId: string,
  plaintext: string,
): Promise<{ iv: string; ciphertext: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource, additionalData: aadFor(handoffId, objectId) as BufferSource },
    key,
    new TextEncoder().encode(plaintext) as BufferSource,
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

/** Decrypt one object of a split record; throws on wrong secret or tampering. */
export async function decryptSplitObject(record: {
  salt: string;
  iterations: number;
}, secret: string, handoffId: string, objectId: string, ivB64: string, ciphertextB64: string): Promise<string> {
  const key = await deriveKeyFromSecret(secret, base64ToBytes(record.salt), record.iterations);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(ivB64) as BufferSource,
      additionalData: aadFor(handoffId, objectId) as BufferSource,
    },
    key,
    base64ToBytes(ciphertextB64) as BufferSource,
  );
  return new TextDecoder().decode(plaintext);
}

async function deriveKeyFromSecret(secret: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(normalize(secret)),
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

function normalize(secret: string): string {
  return secret.replace(/[\s-]/g, '').toUpperCase();
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text) as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
