import { base32CrockfordEncode, isValidBase64 } from '../shared/codec.js';
import type { Env } from './env.js';
import { DATA_PREFIX, sha256Hex, verifyBearerToken } from './auth.js';
import { DEFAULT_CONTENT_TYPE, LIMITS, validateEnvelope } from '../shared/types.js';
import { renderViewerPage } from './page.js';
import { renderCreatePage } from './new-page.js';
import {
  AAD_PREFIX,
  SPLIT_LAYOUT,
  isValidHandoffId,
  type SplitObject,
} from '../shared/split.js';

const ID_LENGTH = 26; // 26 x 5 bits = 130 bits of entropy, non-enumerable

function genId(): string {
  const bytes = new Uint8Array(17);
  crypto.getRandomValues(bytes);
  return base32CrockfordEncode(bytes).slice(0, ID_LENGTH);
}

function baseHeaders(extra: Record<string, string> = {}): Headers {
  const h = new Headers(extra);
  h.set('Cache-Control', 'no-store');
  h.set('X-Robots-Tag', 'noindex, nofollow');
  h.set('Referrer-Policy', 'no-referrer');
  h.set('X-Content-Type-Options', 'nosniff');
  return h;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: baseHeaders({ 'Content-Type': 'application/json; charset=utf-8' }),
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: baseHeaders({ 'Content-Type': 'text/html; charset=utf-8' }),
  });
}

function error(status: number, code: string, message?: string): Response {
  return json({ error: code, message: message ?? code }, status);
}

/**
 * Best-effort per-IP fixed-window rate limiter on KV. KV is eventually
 * consistent, so counts are approximate under contention — adequate for V1
 * abuse damping (enumeration throttling), not a hard guarantee.
 */
async function rateLimit(
  env: Env,
  request: Request,
  kind: string,
  limit: number,
): Promise<boolean> {
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const ipHash = (await sha256Hex(ip)).slice(0, 32);
  const window = Math.floor(Date.now() / 60_000);
  const key = `rl:${kind}:${ipHash}:${window}`;
  const parsed = parseInt((await env.HANDOFFS.get(key)) ?? '0', 10);
  const current = Number.isFinite(parsed) ? parsed : 0;
  if (current >= limit) return false;
  await env.HANDOFFS.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}

/** Object ids of a split record (plaintext by design); [] for single-doc / missing. */
async function listObjectIds(env: Env, id: string): Promise<string[]> {
  const stored = await env.HANDOFFS.get(DATA_PREFIX + id);
  if (stored === null) return [];
  try {
    const record = JSON.parse(stored) as { layout?: string; objects?: Array<{ object_id: string }> };
    if (record.layout !== SPLIT_LAYOUT || !Array.isArray(record.objects)) return [];
    return record.objects.map((o) => o.object_id);
  } catch {
    return [];
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    // treat HEAD as GET; the runtime strips the body for HEAD responses
    const method = request.method === 'HEAD' ? 'GET' : request.method;

    if (path === '/health') {
      return json({ ok: true });
    }

    if (method === 'POST' && path === '/v1/handoffs') {
      return createHandoff(request, env, url);
    }

    const manifestMatch = /^\/v1\/handoffs\/([A-Za-z0-9]+)\/manifest\.txt$/.exec(path);
    if (manifestMatch && method === 'GET') {
      return objectResponse(env, manifestMatch[1] ?? '', request, 'manifest', true);
    }

    const fileMatch = /^\/v1\/handoffs\/([A-Za-z0-9]+)\/files\/([a-z0-9_]{1,32})(\.txt)?$/.exec(path);
    if (fileMatch && method === 'GET') {
      return objectResponse(env, fileMatch[1] ?? '', request, fileMatch[2] ?? '', fileMatch[3] === '.txt');
    }

    const apiMatch = /^\/v1\/handoffs\/([A-Za-z0-9]+)(\.txt)?$/.exec(path);
    if (apiMatch) {
      const id = apiMatch[1] ?? '';
      const asText = apiMatch[2] === '.txt';
      if (method === 'GET') return readHandoff(env, id, request, asText);
      if (method === 'DELETE') return deleteHandoff(request, env, id);
      return error(405, 'method_not_allowed');
    }

    const viewMatch = /^\/h\/([A-Za-z0-9]+)$/.exec(path);
    if (viewMatch && method === 'GET') {
      const id = viewMatch[1] ?? '';
      const objectIds = await listObjectIds(env, id);
      return html(renderViewerPage(id, url.origin, objectIds));
    }

    if (path === '/new' && method === 'GET') {
      return html(renderCreatePage());
    }

    if (path === '/' && method === 'GET') {
      return html(LANDING_PAGE_HTML);
    }

    return error(404, 'not_found');
  },
};

async function createHandoff(request: Request, env: Env, url: URL): Promise<Response> {
  if (!(await verifyBearerToken(request, env.BRIDGE_UPLOAD_TOKEN))) {
    return error(401, 'unauthorized', 'missing or invalid upload token');
  }
  if (!(await rateLimit(env, request, 'upload', 20))) {
    return error(429, 'rate_limited', 'too many uploads from this address');
  }

  const raw = await request.text();
  if (raw.length > LIMITS.maxEnvelopeJsonBytes) {
    return error(413, 'payload_too_large');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return error(400, 'invalid_json');
  }

  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    (parsed as Record<string, unknown>).layout === 'split'
  ) {
    return createSplitHandoff(request, parsed as Record<string, unknown>, env, url);
  }

  const result = validateEnvelope(parsed);
  if (!result.ok) {
    return error(400, 'invalid_envelope', result.error);
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + result.expires_in * 1000);
  const record = JSON.stringify({
    ...result.envelope,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  });

  // KV expirationTtl takes whole seconds and hard-deletes the value.
  let id = genId();
  for (let attempt = 0; attempt < 3; attempt++) {
    if ((await env.HANDOFFS.get(DATA_PREFIX + id)) === null) break;
    id = genId();
  }
  await env.HANDOFFS.put(DATA_PREFIX + id, record, {
    expirationTtl: result.expires_in,
  });

  return json({
    id,
    url: `${url.origin}/h/${id}`,
    api_url: `${url.origin}/v1/handoffs/${id}`,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  });
}

const MAX_OBJECTS = 104; // manifest + up to ~100 files + slack

async function createSplitHandoff(
  request: Request,
  parsed: Record<string, unknown>,
  env: Env,
  url: URL,
): Promise<Response> {
  if (!(await verifyBearerToken(request, env.BRIDGE_UPLOAD_TOKEN))) {
    return error(401, 'unauthorized', 'missing or invalid upload token');
  }

  const id = String(parsed.id ?? '');
  if (!isValidHandoffId(id)) {
    return error(400, 'invalid_id', 'split handoffs require a client-generated id (16-64 url-safe chars)');
  }
  if ((await env.HANDOFFS.get(DATA_PREFIX + id)) !== null) {
    return error(409, 'conflict', 'handoff id already exists; regenerate and retry');
  }

  const objects = parsed.objects;
  if (!Array.isArray(objects) || objects.length < 2 || objects.length > MAX_OBJECTS) {
    return error(400, 'invalid_objects', 'objects must be an array of 2..104 entries');
  }

  let totalCiphertextBytes = 0;
  const seen = new Set<string>();
  const cleanObjects: SplitObject[] = [];
  for (const raw of objects) {
    if (typeof raw !== 'object' || raw === null) return error(400, 'invalid_object');
    const o = raw as Record<string, unknown>;
    const objectId = o.object_id;
    if (typeof objectId !== 'string' || !/^[a-z0-9_]{1,32}$/.test(objectId) || seen.has(objectId)) {
      return error(400, 'invalid_object', 'object ids must be unique lowercase ids');
    }
    seen.add(objectId);
    if (typeof o.iv !== 'string' || !isValidBase64(o.iv, 64) || atob(o.iv).length !== 12) {
      return error(400, 'invalid_object', 'each object needs a 12-byte base64 iv');
    }
    if (typeof o.ciphertext !== 'string' || !isValidBase64(o.ciphertext, 4_100_000)) {
      return error(400, 'invalid_object', 'each object needs valid base64 ciphertext (<= 4.1 MB)');
    }
    totalCiphertextBytes += atob(o.ciphertext).length;
    cleanObjects.push({ object_id: objectId, iv: o.iv, ciphertext: o.ciphertext });
  }
  if (totalCiphertextBytes > LIMITS.maxCiphertextBytes) {
    return error(413, 'payload_too_large', 'total ciphertext exceeds the bundle cap');
  }

  const salt = parsed.salt;
  if (typeof salt !== 'string' || !isValidBase64(salt, 64)) {
    return error(400, 'invalid_envelope', 'salt must be valid base64 (<= 64 bytes)');
  }
  const iterations = parsed.iterations;
  if (typeof iterations !== 'number' || !Number.isInteger(iterations) ||
      iterations < LIMITS.minIterations || iterations > LIMITS.maxIterations) {
    return error(400, 'invalid_envelope', 'iterations out of range');
  }
  let contentType = DEFAULT_CONTENT_TYPE;
  if (parsed.content_type !== undefined) {
    if (typeof parsed.content_type !== 'string' || parsed.content_type.length > 100 ||
        !/^[\w.+-]+\/[\w.+-]+$/.test(parsed.content_type)) {
      return error(400, 'invalid_envelope', 'invalid content_type');
    }
    contentType = parsed.content_type;
  }
  let expiresIn: number = LIMITS.defaultTtlSeconds;
  if (parsed.expires_in !== undefined) {
    if (typeof parsed.expires_in !== 'number' || !Number.isInteger(parsed.expires_in) ||
        parsed.expires_in < LIMITS.minTtlSeconds || parsed.expires_in > LIMITS.maxTtlSeconds) {
      return error(400, 'invalid_envelope', 'expires_in out of range');
    }
    expiresIn = parsed.expires_in;
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresIn * 1000);
  const record = {
    protocol: 'agent-handoff',
    v: 1,
    layout: SPLIT_LAYOUT,
    id,
    algorithm: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt,
    content_type: contentType,
    encoding: typeof parsed.encoding === 'string' ? parsed.encoding : 'utf-8',
    secret_encoding: typeof parsed.secret_encoding === 'string' ? parsed.secret_encoding : 'base32-crockford-grouped-4',
    secret_normalization: typeof parsed.secret_normalization === 'string'
      ? parsed.secret_normalization
      : 'strip-hyphens-whitespace-uppercase',
    objects: cleanObjects,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };

  await env.HANDOFFS.put(DATA_PREFIX + id, JSON.stringify(record), { expirationTtl: expiresIn });
  return json({
    id,
    url: `${url.origin}/h/${id}`,
    api_url: `${url.origin}/v1/handoffs/${id}`,
    manifest_url: `${url.origin}/v1/handoffs/${id}/manifest.txt`,
    created_at: record.created_at,
    expires_at: record.expires_at,
  });
}

/** One object of a split record, as JSON or as the flat text envelope. */
async function objectResponse(env: Env, id: string, request: Request, objectId: string, asText: boolean): Promise<Response> {
  const record = await readRecordForTransfer(env, id, request);
  if (typeof record === 'number') {
    return record === 429
      ? error(429, 'rate_limited', 'too many requests from this address')
      : error(404, 'not_found', 'handoff not found or expired');
  }
  if (record.layout !== SPLIT_LAYOUT) return error(404, 'not_found', 'handoff not found or expired');

  const objects = record.objects as SplitObject[];
  const obj = objects.find((o) => o.object_id === objectId);
  if (!obj) return error(404, 'not_found', 'object not found');

  const origin = new URL(request.url).origin;
  const objectRecord: Record<string, unknown> = {
    object_id: objectId,
    algorithm: record.algorithm,
    kdf: record.kdf,
    iterations: record.iterations,
    salt: record.salt,
    encoding: record.encoding,
    secret_encoding: record.secret_encoding,
    secret_normalization: record.secret_normalization,
    iv: obj.iv,
    aad: `${AAD_PREFIX}/${record.id}/file/${objectId}`,
    ciphertext: obj.ciphertext,
    content_type: record.content_type,
    created_at: record.created_at,
    expires_at: record.expires_at,
  };

  if (asText) {
    const lines = [envelopeToText(objectRecord)];
    // server-rendered discovery links (object ids only — paths stay encrypted)
    lines.push('# object links');
    for (const o of objects) {
      lines.push(`${origin}/v1/handoffs/${id}/files/${o.object_id}.txt`);
    }
    return new Response(lines.join('\n'), {
      status: 200,
      headers: baseHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }),
    });
  }
  return json(objectRecord);
}

/**
 * Fetch + validate a record for transfer; returns the parsed record or an
 * HTTP status number (404 expired/missing, 429 rate limited).
 */
async function readRecordForTransfer(env: Env, id: string, request: Request): Promise<Record<string, unknown> | number> {
  const perMin = parseInt(env.RATE_LIMIT_PER_MIN ?? '60', 10);
  const limit = Number.isFinite(perMin) && perMin > 0 ? perMin : 60;
  if (!(await rateLimit(env, request, 'read', limit))) return 429;

  const stored = await env.HANDOFFS.get(DATA_PREFIX + id);
  if (stored === null) return 404;
  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return 404;
  }
  const expiresAt = Date.parse(String(record.expires_at ?? ''));
  if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) {
    await env.HANDOFFS.delete(DATA_PREFIX + id);
    return 404;
  }
  return record;
}

async function readHandoff(env: Env, id: string, request: Request, asText = false): Promise<Response> {
  const record = await readRecordForTransfer(env, id, request);
  if (typeof record === 'number') {
    return record === 429
      ? error(429, 'rate_limited', 'too many requests from this address')
      : error(404, 'not_found', 'handoff not found or expired');
  }

  if (asText) {
    // Plain-text fallback: some web-retrieval layers swallow raw JSON bodies.
    // Same ciphertext fields as the JSON endpoint, flat key: value lines,
    // nothing secret added - the password still never touches the server.
    // For split bundles this is the manifest object (the discovery entry point).
    if (record.layout === SPLIT_LAYOUT) {
      return objectResponse(env, id, request, 'manifest', true);
    }
    return new Response(envelopeToText(record), {
      status: 200,
      headers: baseHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }),
    });
  }
  return json(record);
}

const TEXT_FIELD_ORDER = [
  'object_id',
  'protocol',
  'v',
  'algorithm',
  'kdf',
  'iterations',
  'salt',
  'iv',
  'aad',
  'ciphertext',
  'content_type',
  'encoding',
  'secret_encoding',
  'secret_normalization',
  'created_at',
  'expires_at',
];

/**
 * Web-retrieval layers truncate very long single lines, so the base64
 * ciphertext is emitted as an ordered chunk list (~600 chars each).
 * Receivers concatenate in order without separators, then base64-decode.
 */
const CIPHERTEXT_CHUNK_CHARS = 600;

function envelopeToText(record: Record<string, unknown>): string {
  const lines = [
    '# agent-handoff envelope - ciphertext only; decrypt locally with the password provided separately',
    '# ciphertext_chunks are ordered: concatenate without separators, then base64-decode',
  ];
  for (const key of TEXT_FIELD_ORDER) {
    if (record[key] === undefined) continue;
    if (key === 'ciphertext') {
      const value = String(record[key]);
      lines.push('ciphertext_encoding: base64');
      lines.push('ciphertext_chunks:');
      for (let i = 0; i < value.length; i += CIPHERTEXT_CHUNK_CHARS) {
        lines.push(`  - ${value.slice(i, i + CIPHERTEXT_CHUNK_CHARS)}`);
      }
      continue;
    }
    lines.push(`${key}: ${String(record[key])}`);
  }
  return lines.join('\n') + '\n';
}

async function deleteHandoff(request: Request, env: Env, id: string): Promise<Response> {
  if (!(await verifyBearerToken(request, env.BRIDGE_UPLOAD_TOKEN))) {
    return error(401, 'unauthorized', 'missing or invalid upload token');
  }
  await env.HANDOFFS.delete(DATA_PREFIX + id);
  return json({ ok: true });
}

const LANDING_PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Agent Handoff Bridge</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0f1115; color: #e6e6e6;
         display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
  .card { max-width: 36rem; padding: 2.5rem; line-height: 1.65; }
  h1 { font-size: 1.3rem; margin: 0 0 0.4rem; }
  .tag { color: #c7cdd8; font-size: 0.95rem; margin: 0 0 1.25rem; }
  .pill { display: inline-block; font-size: 0.75rem; color: #8b93a3; border: 1px solid #2c3442;
          border-radius: 99px; padding: 0.15rem 0.6rem; margin: 0 0.35rem 0.35rem 0; }
  p { color: #8b93a3; font-size: 0.88rem; }
  a.btn { display: inline-block; background: #4c8dff; color: #fff; text-decoration: none;
          padding: 0.65rem 1.1rem; border-radius: 8px; font-size: 0.95rem; margin: 1rem 0.5rem 0 0; }
  a.ghost { background: #2c3442; }
  code { background: #1c2029; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
</style>
</head>
<body>
  <div class="card">
    <h1>Give AI agents context, not access.</h1>
    <p class="tag">Securely hand off local project context to ChatGPT, Claude, or any remote
       agent — without exposing your machine or repository.</p>
    <div>
      <span class="pill">Client-side encrypted</span>
      <span class="pill">5-minute expiry</span>
      <span class="pill">Self-hosted</span>
      <span class="pill">Zero-knowledge server</span>
    </div>
    <p style="margin-top:1.25rem">Drop a few files into the browser, write one sentence about what
       the AI should do, and paste the generated link + password into any chat. The files are
       screened and encrypted locally; this server only ever stores ciphertext and hard-deletes
       it after five minutes. Agents can also push programmatically via the
       <code>/v1</code> API (see the repository README).</p>
    <a class="btn" href="/new">Create a secure handoff →</a>
    <a class="btn ghost" href="/health">Status</a>
    <p style="margin-top:1.5rem">Received a link? Open it and enter the password you received
       separately: <code>/h/&lt;id&gt;</code>. The password never reaches this server.</p>
  </div>
</body>
</html>`;
