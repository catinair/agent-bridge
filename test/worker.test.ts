import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/worker/index.js';
import type { Env } from '../src/worker/env.js';
import { InMemoryKV } from '../src/local-dev/kv.js';
import { decryptHandoff, encryptHandoff, generateSecret } from '../src/shared/handoff-crypto.js';
import { bytesToBase64 } from '../src/shared/codec.js';
import {
  buildSplitRecord,
  generateHandoffId,
  fileObjectId,
} from '../src/shared/split.js';
import { generateSecret } from '../src/shared/handoff-crypto.js';

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

  it('accepts split-layout bundles and serves manifest / per-file text envelopes', async () => {
    const secret = generateSecret();
    const id = generateHandoffId();
    const manifest = {
      protocol: 'agent-context-bundle' as const,
      version: 1,
      request: { prompt: 'e2e split' },
      generated_at: new Date().toISOString(),
      generator: 'test',
      files: [
        { object_id: fileObjectId(0), path: 'AGENTS.md', media_type: 'text/markdown', size: 9, sha256: 'a'.repeat(64) },
        { object_id: fileObjectId(1), path: 'models.yaml', media_type: 'application/yaml', size: 24, sha256: 'b'.repeat(64) },
      ],
    };
    const record = await buildSplitRecord({
      handoffId: id,
      secret,
      iterations: 600_000,
      manifest,
      fileTexts: [
        { objectId: fileObjectId(0), text: '# 规则\n' },
        { objectId: fileObjectId(1), text: 'default: gpt-5-mini\n' },
      ],
      contentType: 'application/vnd.agent-context-bundle+json',
    });

    const created = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...record, expires_in: 300 }),
      }),
      env,
    );
    expect(created.status).toBe(200);
    const data = (await created.json()) as { id: string; manifest_url: string };
    expect(data.id).toBe(id);
    expect(data.manifest_url).toContain('/manifest.txt');

    const manifestRes = await worker.fetch(req('/v1/handoffs/' + id + '/manifest.txt'), env);
    expect(manifestRes.status).toBe(200);
    expect(manifestRes.headers.get('Content-Type')).toContain('text/plain');
    expect(await manifestRes.text()).toContain('object_id: manifest');

    const fileRes = await worker.fetch(req('/v1/handoffs/' + id + '/files/f2.txt'), env);
    expect(fileRes.status).toBe(200);
    expect(await fileRes.text()).toContain('object_id: f2');

    // the whole-record JSON endpoint also serves split records
    const full = await worker.fetch(req('/v1/handoffs/' + id), env);
    const fullRecord = (await full.json()) as { layout: string; objects: unknown[] };
    expect(fullRecord.layout).toBe('split');
    expect(fullRecord.objects).toHaveLength(3);
  });

  it('rejects duplicate and malformed split ids', async () => {
    const secret = generateSecret();
    const id = generateHandoffId();
    const record = await buildSplitRecord({
      handoffId: id,
      secret,
      iterations: 600_000,
      manifest: {
        protocol: 'agent-context-bundle',
        version: 1,
        request: { prompt: '' },
        generated_at: new Date().toISOString(),
        generator: 'test',
        files: [{ object_id: 'f1', path: 'a.md', media_type: 'text/markdown', size: 2, sha256: 'c'.repeat(64) }],
      },
      fileTexts: [{ objectId: 'f1', text: 'hi' }],
      contentType: 'application/vnd.agent-context-bundle+json',
    });

    const post = () =>
      worker.fetch(
        req('/v1/handoffs', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...record, expires_in: 300 }),
        }),
        env,
      );
    expect((await post()).status).toBe(200);
    expect((await post()).status).toBe(409); // same id twice

    const badId = await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...record, id: 'bad id!', expires_in: 300 }),
      }),
      env,
    );
    expect(badId.status).toBe(400);
  });

  it('server-renders per-object discovery links into /h/:id for split records', async () => {
    const secret = generateSecret();
    const id = generateHandoffId();
    const manifest = {
      protocol: 'agent-context-bundle' as const,
      version: 1,
      request: { prompt: 'links' },
      generated_at: new Date().toISOString(),
      generator: 'test',
      files: [
        { object_id: fileObjectId(0), path: 'AGENTS.md', media_type: 'text/markdown', size: 9, sha256: 'a'.repeat(64) },
        { object_id: fileObjectId(1), path: 'models.yaml', media_type: 'application/yaml', size: 24, sha256: 'b'.repeat(64) },
      ],
    };
    const record = await buildSplitRecord({
      handoffId: id,
      secret,
      iterations: 600_000,
      manifest,
      fileTexts: [
        { objectId: fileObjectId(0), text: '# 规则\n' },
        { objectId: fileObjectId(1), text: 'default: gpt-5-mini\n' },
      ],
      contentType: 'application/vnd.agent-context-bundle+json',
    });
    await worker.fetch(
      req('/v1/handoffs', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...record, expires_in: 300 }),
      }),
      env,
    );

    const page = await worker.fetch(req('/h/' + id), env);
    const html = await page.text();
    expect(html).toContain('aria-label="Agent object endpoints"');
    expect(html).toContain(`href="https://bridge.example.com/v1/handoffs/${id}/files/manifest.txt">manifest</a>`);
    expect(html).toContain(`href="https://bridge.example.com/v1/handoffs/${id}/files/f1.txt">object f1</a>`);
    expect(html).toContain(`href="https://bridge.example.com/v1/handoffs/${id}/files/f2.txt">object f2</a>`);
    // no plaintext paths leak into the link section
    expect(html).not.toContain('AGENTS.md');
  });

  it('lifecycle: anonymous read claims; lease expiry burns (410) with tombstone', async () => {
    const created = await createHandoff(env);
    const { id } = (await created.json()) as { id: string };

    // sender-authenticated read does NOT claim
    await worker.fetch(
      req('/v1/handoffs/' + id, { headers: { Authorization: 'Bearer ' + TOKEN } }),
      env,
    );
    let stored = JSON.parse((await env.HANDOFFS.get('h:' + id)) as string);
    expect(stored.claimed_at).toBeUndefined();

    // first anonymous read claims (60s read lease, hard KV TTL)
    const r1 = await worker.fetch(req('/v1/handoffs/' + id), env);
    expect(r1.status).toBe(200);
    stored = JSON.parse((await env.HANDOFFS.get('h:' + id)) as string);
    expect(typeof stored.claimed_at).toBe('string');

    // status endpoint reflects claimed state without claiming others
    const st = await worker.fetch(req('/v1/handoffs/' + id + '/status'), env);
    const stBody = (await st.json()) as { status: string; lease_remaining_seconds: number };
    expect(stBody.status).toBe('claimed');
    expect(stBody.lease_remaining_seconds).toBeGreaterThan(0);

    // simulate lease expiry: age claimed_at beyond the lease
    stored.claimed_at = new Date(Date.now() - 61_000).toISOString();
    await env.HANDOFFS.put('h:' + id, JSON.stringify(stored));
    const burned = await worker.fetch(req('/v1/handoffs/' + id), env);
    expect(burned.status).toBe(410);
    expect(((await burned.json()) as { error: string }).error).toBe('burned');

    // tombstone keeps answering 410 (distinct from never-existing 404)
    expect((await worker.fetch(req('/v1/handoffs/' + id), env)).status).toBe(410);

    // KV TTL may delete the data before anyone reads again: the claim sidecar
    // alone must still produce a stable 410 (lazy tombstone)
    await env.HANDOFFS.put('c:' + id, JSON.stringify({ claimed_at: new Date().toISOString(), lease_until: new Date(Date.now() - 1000).toISOString() }), { expirationTtl: 3600 });
    expect((await worker.fetch(req('/v1/handoffs/' + id), env)).status).toBe(410);
    const st2 = await worker.fetch(req('/v1/handoffs/' + id + '/status'), env);
    expect(((await st2.json()) as { status: string }).status).toBe('burned');
  });

  it('status endpoint reports unclaimed before any read', async () => {
    const created = await createHandoff(env);
    const { id } = (await created.json()) as { id: string };
    const st = await worker.fetch(req('/v1/handoffs/' + id + '/status'), env);
    const body = (await st.json()) as { status: string; expires_if_unread_in_seconds: number };
    expect(body.status).toBe('unclaimed');
    expect(body.expires_if_unread_in_seconds).toBeGreaterThan(0);
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
