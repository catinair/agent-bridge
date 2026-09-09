import { base32CrockfordEncode } from '../shared/codec.js';
import type { Env } from './env.js';
import { DATA_PREFIX, sha256Hex, verifyBearerToken } from './auth.js';
import { LIMITS, validateEnvelope } from '../shared/types.js';
import { renderViewerPage } from './page.js';

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method;

    if (path === '/health') {
      return json({ ok: true });
    }

    if (method === 'POST' && path === '/v1/handoffs') {
      return createHandoff(request, env, url);
    }

    const apiMatch = /^\/v1\/handoffs\/([A-Za-z0-9]+)$/.exec(path);
    if (apiMatch) {
      const id = apiMatch[1] ?? '';
      if (method === 'GET') return readHandoff(env, id, request);
      if (method === 'DELETE') return deleteHandoff(request, env, id);
      return error(405, 'method_not_allowed');
    }

    const viewMatch = /^\/h\/([A-Za-z0-9]+)$/.exec(path);
    if (viewMatch && method === 'GET') {
      const id = viewMatch[1] ?? '';
      return html(renderViewerPage(id, url.origin));
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

async function readHandoff(env: Env, id: string, request: Request): Promise<Response> {
  const perMin = parseInt(env.RATE_LIMIT_PER_MIN ?? '60', 10);
  const limit = Number.isFinite(perMin) && perMin > 0 ? perMin : 60;
  if (!(await rateLimit(env, request, 'read', limit))) {
    return error(429, 'rate_limited', 'too many requests from this address');
  }

  const stored = await env.HANDOFFS.get(DATA_PREFIX + id);
  if (stored === null) {
    return error(404, 'not_found', 'handoff not found or expired');
  }

  let record: Record<string, unknown>;
  try {
    record = JSON.parse(stored) as Record<string, unknown>;
  } catch {
    return error(404, 'not_found', 'handoff not found or expired');
  }

  const expiresAt = Date.parse(String(record.expires_at ?? ''));
  if (Number.isFinite(expiresAt) && expiresAt <= Date.now()) {
    await env.HANDOFFS.delete(DATA_PREFIX + id);
    return error(404, 'not_found', 'handoff not found or expired');
  }

  return json(record);
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
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #0f1115; color: #e6e6e6;
         display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
  .card { max-width: 34rem; padding: 2rem; line-height: 1.6; }
  code { background: #1c2029; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
</style>
</head>
<body>
  <div class="card">
    <h1>Agent Handoff Bridge</h1>
    <p>This is a zero-knowledge, self-destructing relay for AI-agent handoff documents.
       The server stores only encrypted payloads for a few minutes.</p>
    <p>Handoff pages live at <code>/h/&lt;id&gt;</code> and require the one-time password
       provided separately by the sender. The password never reaches this server.</p>
  </div>
</body>
</html>`;
