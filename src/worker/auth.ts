import { constantTimeEqual } from '../shared/codec.js';

export const DATA_PREFIX = 'h:';

/** SHA-256 hex digest; used to hash secrets/tokens before comparison. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(input) as BufferSource,
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Token check without leaking timing: hash both sides first, then
 * constant-time compare the uniform digests.
 */
export async function verifyBearerToken(request: Request, expected: string | undefined): Promise<boolean> {
  if (!expected) return false; // fail closed when the secret is not configured
  const header = request.headers.get('Authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) return false;
  const got = (match[1] ?? '').trim();
  if (got.length === 0) return false;
  return constantTimeEqual(await sha256Hex(got), await sha256Hex(expected));
}
