/**
 * Portable byte<->text codecs used by CLI, Worker and the browser viewer.
 * Only Web-standard globals (btoa/atob) so the same code runs everywhere.
 */

const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const CROCKFORD_DECODE = new Map<string, number>(
  CROCKFORD_ALPHABET.split('').map((ch, i) => [ch, i]),
);
// Crockford: visually ambiguous letters map to their digit counterparts.
for (const [ch, digit] of [
  ['I', 1],
  ['i', 1],
  ['L', 1],
  ['l', 1],
  ['O', 0],
  ['o', 0],
] as const) {
  CROCKFORD_DECODE.set(ch, digit);
}

export function base32CrockfordEncode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += CROCKFORD_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

export function base32CrockfordDecode(input: string): Uint8Array {
  const clean = normalizeBase32(input);
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const digit = CROCKFORD_DECODE.get(ch);
    if (digit === undefined) {
      throw new Error(`invalid base32 character: ${JSON.stringify(ch)}`);
    }
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function normalizeBase32(input: string): string {
  return input.replace(/[\s-]/g, '').toUpperCase();
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function isValidBase64(s: string, maxBytes?: number): boolean {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return false;
  try {
    const bytes = base64ToBytes(s);
    return maxBytes === undefined || bytes.length <= maxBytes;
  } catch {
    return false;
  }
}

/** Constant-time string comparison (for hash digests of secrets). */
export function constantTimeEqual(a: string, b: string): boolean {
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) | 0) ^ (b.charCodeAt(i) | 0);
  }
  return diff === 0;
}
