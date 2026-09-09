import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/worker/index.js';
import type { Env } from '../src/worker/env.js';
import { InMemoryKV } from '../src/local-dev/kv.js';
import { decryptHandoff, encryptHandoff, generateSecret } from '../src/shared/handoff-crypto.js';
import { bytesToBase64 } from '../src/shared/codec.js';

const TOKEN = 'test-upload-token';

function makeEnv(overrides: Partial<Env> = {}): Env {
  return { HANDOFFS: new InMemoryKV(), BRIDGE_UPLOAD_TOKEN: TOKEN, ...overrides };
}

function req(path: string, init: RequestInit = {}): Request {
  return new Request('https://bridge.example.com' + path, init);
}

async function createHandoff(env: Env, plaintext = 'hello bridge', extra: object = {}) {
  const { envelope } = await encryptHandoff(plaintext);
  return worker.fetch(
    req('/v1/handoffs', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...envelope, expires_in: 300, ...extra }),
    }),
    env,
  );
}

describe('worker', () => {
  let env: Env;
  beforeEach(() => {
    env = makeEnv();
  });

  it('reports health', async () => {
    const res = await worker.fetch(req('/health'), env);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('rejects uploads without or with a wrong bearer token', async () => {
    const { envelope } = await encryptHandoff('x');
    const body = JSON.stringify({ ...envelope, expires_in: 300 });
    const noAuth = await worker.fetch(
      req('/v1/handoffs', { method: 'POST', body }),
      env,
    );
    expect(noAuth.status).toBe(401);

    const badAuth = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer wrong-token' },
        body,
      }),
      env,
    );
    expect(badAuth.status).toBe(401);
  });

  it('fails closed when the upload token is not configured', async () => {
    const noSecretEnv = makeEnv({ BRIDGE_UPLOAD_TOKEN: undefined });
    const res = await createHandoff(noSecretEnv);
    expect(res.status).toBe(401);
  });

  it('stores and serves a ciphertext envelope with hardening headers', async () => {
    const plaintext = '# HANDOFF\n\n机密上下文';
    const created = await createHandoff(env, plaintext);
    expect(created.status).toBe(200);

    const data = (await created.json()) as {
      id: string;
      url: string;
      api_url: string;
      expires_at: string;
    };
    expect(data.id).toMatch(/^[0-9A-Z]{26}$/);
    expect(data.url).toBe('https://bridge.example.com/h/' + data.id);
    expect(new Date(data.expires_at).getTime()).toBeGreaterThan(Date.now());

    const read = await worker.fetch(req('/v1/handoffs/' + data.id), env);
    expect(read.status).toBe(200);
    expect(read.headers.get('Cache-Control')).toBe('no-store');
    const envelope = (await read.json()) as Record<string, unknown>;
    expect(envelope.ciphertext).toBeTruthy();
    expect(envelope.created_at).toBeTruthy();
    expect(envelope.algorithm).toBe('AES-256-GCM');

    const viewer = await worker.fetch(req('/h/' + data.id), env);
    expect(viewer.status).toBe(200);
    expect(viewer.headers.get('Content-Type')).toContain('text/html');
    expect(viewer.headers.get('X-Robots-Tag')).toBe('noindex, nofollow');
    expect(viewer.headers.get('Cache-Control')).toBe('no-store');
    const pageHtml = await viewer.text();
    // machine discovery: real <a> + <link rel="alternate"> server-rendered into the raw HTML
    expect(pageHtml).toContain(`href="https://bridge.example.com/v1/handoffs/${data.id}"`);
    expect(pageHtml).toContain('rel="alternate" type="application/vnd.agent-handoff+json"');
    expect(pageHtml).toContain('bridgeDecrypt');
  });

  it('serves a text/plain envelope fallback at :id.txt (discovery + retrieval)', async () => {
    // large enough to force multiple ciphertext_chunks
    const created = await createHandoff(env, '# chunked\n' + 'A'.repeat(1500));
    const { id } = (await created.json()) as { id: string };

    const res = await worker.fetch(req('/v1/handoffs/' + id + '.txt'), env);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/plain');
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const text = await res.text();
    expect(text).toContain('algorithm: AES-256-GCM');
    expect(text).toContain('kdf: PBKDF2-SHA256');
    expect(text).toContain('ciphertext_encoding: base64');
    expect(text).toContain('ciphertext_chunks:');
    expect(text).toContain('expires_at: ');
    expect(text.toLowerCase()).not.toContain('password:');

    // chunked ciphertext must reassemble to exactly the JSON endpoint's value
    const jsonRes = await worker.fetch(req('/v1/handoffs/' + id), env);
    const expected = String(((await jsonRes.json()) as Record<string, unknown>).ciphertext);
    const chunks = [...text.matchAll(/^  - (.+)$/gm)].map((m) => m[1] ?? '');
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) expect(c.length).toBeLessThanOrEqual(600);
    expect(chunks.join('')).toBe(expected);

    // the viewer page server-renders the text-envelope discovery link
    const page = await worker.fetch(req('/h/' + id), env);
    const html = await page.text();
    expect(html).toContain(`href="https://bridge.example.com/v1/handoffs/${id}.txt"`);
    expect(html).toContain('text envelope');
  });

  it('returns 404 (not distinguishable from expired) for unknown ids', async () => {
    const res = await worker.fetch(req('/v1/handoffs/AAAAAAAAAAAAAAAAAAAAAAAAAA'), env);
    expect(res.status).toBe(404);
  });

  it('refuses and deletes records already past their expires_at', async () => {
    const created = await createHandoff(env);
    const { id } = (await created.json()) as { id: string };
    // age the stored record artificially
    const stored = await env.HANDOFFS.get('h:' + id);
    const record = JSON.parse(stored as string) as Record<string, unknown>;
    record.expires_at = new Date(Date.now() - 1000).toISOString();
    await env.HANDOFFS.put('h:' + id, JSON.stringify(record));

    const res = await worker.fetch(req('/v1/handoffs/' + id), env);
    expect(res.status).toBe(404);
    expect(await env.HANDOFFS.get('h:' + id)).toBeNull();
  });

  it('validates the envelope strictly', async () => {
    const { envelope } = await encryptHandoff('x');
    const badIterations = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN },
        body: JSON.stringify({ ...envelope, iterations: 1000, expires_in: 300 }),
      }),
      env,
    );
    expect(badIterations.status).toBe(400);

    const badTtl = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN },
        body: JSON.stringify({ ...envelope, expires_in: 10 }),
      }),
      env,
    );
    expect(badTtl.status).toBe(400);

    const oversized = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN },
        body: JSON.stringify({
          ...envelope,
          ciphertext: bytesToBase64(new Uint8Array(4_600_000)),
          expires_in: 300,
        }),
      }),
      env,
    );
    expect(oversized.status).toBe(400);
  });

  it('rejects malformed json bodies', async () => {
    const res = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN },
        body: 'not json',
      }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it('requires the upload token for early deletion', async () => {
    const created = await createHandoff(env);
    const { id } = (await created.json()) as { id: string };

    const noAuth = await worker.fetch(req('/v1/handoffs/' + id, { method: 'DELETE' }), env);
    expect(noAuth.status).toBe(401);

    const ok = await worker.fetch(
      req('/v1/handoffs/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + TOKEN } }),
      env,
    );
    expect(ok.status).toBe(200);
    expect(await worker.fetch(req('/v1/handoffs/' + id), env)).toHaveProperty('status', 404);
  });

  it('rate-limits reads per address', async () => {
    const limited = makeEnv({ RATE_LIMIT_PER_MIN: '2' });
    for (let i = 0; i < 2; i++) {
      const res = await worker.fetch(req('/v1/handoffs/AAAAAAAAAAAAAAAAAAAAAAAAAA'), limited);
      expect(res.status).toBe(404);
    }
    const third = await worker.fetch(req('/v1/handoffs/AAAAAAAAAAAAAAAAAAAAAAAAAA'), limited);
    expect(third.status).toBe(429);
  });

  it('stores ciphertext only: neither the secret nor plaintext ever reaches KV', async () => {
    const { envelope, secret } = await encryptHandoff('context');
    const created = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN },
        body: JSON.stringify({ ...envelope, expires_in: 300 }),
      }),
      env,
    );
    const { id } = (await created.json()) as { id: string };
    const stored = (await env.HANDOFFS.get('h:' + id)) as string;
    expect(stored).not.toContain(secret);
    expect(stored).not.toContain('context');
  });
});
