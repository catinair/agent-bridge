/**
 * Black-box consumer compatibility test.
 *
 * Inputs: a human URL and a password. Nothing else.
 * The consumer discovers links from the page HTML, reads manifest.txt, and
 * decrypts using ONLY the fields the envelope declares (aad, salt, iv,
 * iterations, secret_normalization, ciphertext_chunks) — implemented
 * independently with node:crypto so it cannot share state with the project's
 * own crypto helpers. If the envelope's self-description ever drifts from
 * what the encryptor actually does, this test fails.
 */
import { execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const runCliRaw = promisify(execFile);
import { startDevServer, type DevServer } from '../src/local-dev/server.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function normalizeSecret(s: string): string {
  return s.replace(/[\s-]/g, '').toUpperCase();
}

/** Strictly follows the self-described text envelope format. */
function parseTextEnvelope(text: string): Record<string, string> & { ciphertext: string } {
  const fields: Record<string, string> = {};
  const chunks: string[] = [];
  let inChunks = false;
  for (const line of text.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;
    const chunk = /^  - (.+)$/.exec(line);
    if (inChunks && chunk) {
      chunks.push(chunk[1] ?? '');
      continue;
    }
    if (line.startsWith('ciphertext_chunks:')) {
      inChunks = true;
      continue;
    }
    const kv = /^([a-z_0-9]+): (.*)$/.exec(line);
    if (kv) fields[kv[1] ?? ''] = kv[2] ?? '';
  }
  if (!inChunks) throw new Error('envelope does not declare ciphertext_chunks');
  fields.ciphertext = chunks.join('');
  return fields as Record<string, string> & { ciphertext: string };
}

function discoverLinks(html: string, baseUrl: string): string[] {
  return [...html.matchAll(/href="([^"]+)"/g)].map((m) => new URL(m[1] ?? '', baseUrl).href);
}

async function decryptObject(fields: Record<string, string>, password: string): Promise<string> {
  const key = pbkdf2Sync(
    Buffer.from(normalizeSecret(password), 'utf8'),
    Buffer.from(fields.salt ?? '', 'base64'),
    Number(fields.iterations),
    32,
    'sha256',
  );
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(fields.iv ?? '', 'base64'));
  decipher.setAAD(Buffer.from(fields.aad ?? '', 'utf8'));
  const ct = Buffer.from(fields.ciphertext, 'base64');
  decipher.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]).toString('utf8');
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

let server: DevServer;
beforeAll(async () => {
  server = await startDevServer();
});
afterAll(async () => {
  await server.close();
});

async function runCli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout } = await runCliRaw('npx', ['tsx', 'src/cli/index.ts', ...args], {
      cwd: PROJECT_ROOT,
      env: { ...process.env, BRIDGE_URL: `http://127.0.0.1:${server.port}`, BRIDGE_TOKEN: server.token },
      maxBuffer: 16 * 1024 * 1024,
    });
    return { stdout, stderr: '', code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? String(err),
      code: typeof e.code === 'number' ? e.code : 1,
    };
  }
}

describe('black-box consumer: only a human URL and a password', () => {
  it('discovers links from the page, follows the manifest, and decrypts files', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'bridge-blackbox-'));
    const agentsMd = path.join(dir, 'AGENTS.md');
    const routing = path.join(dir, 'docs/model-routing.md');
    fs.mkdirSync(path.dirname(routing), { recursive: true });
    writeFileSync(agentsMd, '# 规则\n第三方消费者按协议读取本文件。\n');
    writeFileSync(routing, '# 模型路由\nsimple → mini, complex → flagship\n');

    const pushed = await runCli(['push', agentsMd, routing, '--prompt', '请阅读原始文件后评审模型路由']);
    expect(pushed.code).toBe(0);
    const url = /URL:\s+(\S+)/.exec(pushed.stdout)?.[1] ?? '';
    const password = /Password:\s+(\S+)/.exec(pushed.stdout)?.[1] ?? '';
    expect(url).toBeTruthy();

    // 1. the only input is the human URL
    const html = await (await fetch(url)).text();
    const links = discoverLinks(html, url);

    // 2. the page must expose the manifest envelope as a real link
    const manifestLink = links.find((l) => l.endsWith('/files/manifest.txt'));
    expect(manifestLink).toBeTruthy();

    // 3. manifest envelope is self-describing: decrypt with its own fields
    const manifestFields = parseTextEnvelope(await (await fetch(manifestLink!)).text());
    expect(manifestFields.aad).toMatch(/\/manifest$/);
    const manifestJson = await decryptObject(manifestFields, password);
    const manifest = JSON.parse(manifestJson) as {
      protocol: string;
      request: { prompt: string };
      files: Array<{ object_id: string; path: string; sha256: string; href: string }>;
    };
    expect(manifest.protocol).toBe('agent-context-bundle');
    expect(manifest.request.prompt).toContain('模型路由');

    // 4. follow each file href from the manifest and decrypt independently
    const contents: Array<{ path: string; text: string }> = [];
    for (const f of manifest.files) {
      expect(f.href).toMatch(/\.txt$/);
      const fields = parseTextEnvelope(await (await fetch(f.href)).text());
      expect(fields.aad).toBe(`agent-handoff/v2/${new URL(url).pathname.split('/').pop()}/file/${f.object_id}`);
      console.log('DBG file:', f.object_id, f.path, '| aad:', fields.aad, '| sha:', f.sha256.slice(0, 12), '| ctLen:', fields.ciphertext.length);
      let text = '';
      try {
        text = await decryptObject(fields, password);
      } catch (e) {
        console.log('DBG decrypt failed:', (e as Error).message);
        console.log('DBG fields:', JSON.stringify(fields, null, 1).slice(0, 600));
        throw e;
      }
      expect(sha256(text)).toBe(f.sha256);
      contents.push({ path: f.path, text });
    }
    expect(contents.find((c) => c.path.endsWith('model-routing.md'))?.text).toContain('flagship');

    // 5. negative: a tampered aad must fail authentication
    const tampered = { ...manifestFields, aad: manifestFields.aad + 'x' };
    await expect(decryptObject(tampered, password)).rejects.toThrow();
  }, 90_000);
});
