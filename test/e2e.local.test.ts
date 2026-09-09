import { execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startDevServer, type DevServer } from '../src/local-dev/server.js';
import { decryptHandoff } from '../src/shared/handoff-crypto.js';
import { decryptSplitObject } from '../src/shared/split.js';
import { sha256Hex } from '../src/shared/split.js';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const run = (args: string[], env: NodeJS.ProcessEnv) =>
  new Promise<{ stdout: string; stderr: string; code: number }>((resolve) => {
    execFile(
      'npx',
      ['tsx', 'src/cli/index.ts', ...args],
      { cwd: PROJECT_ROOT, env: { ...process.env, ...env } },
      (error, stdout, stderr) => {
        const code = error && typeof (error as NodeJS.ErrnoException).code === 'number'
          ? ((error as unknown as { code: number }).code)
          : error
            ? 1
            : 0;
        resolve({ stdout, stderr, code });
      },
    );
  });

let server: DevServer;
let workdir: string;
const BRIDGE_ENV = () => ({
  BRIDGE_URL: `http://127.0.0.1:${server.port}`,
  BRIDGE_TOKEN: server.token,
});

beforeAll(async () => {
  server = await startDevServer();
  workdir = mkdtempSync(path.join(tmpdir(), 'agent-bridge-e2e-'));
});

afterAll(async () => {
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

async function pushFile(name: string, content: string, extraArgs: string[] = []) {
  const file = path.join(workdir, name);
  writeFileSync(file, content);
  return { file, result: await run(['push', file, ...extraArgs], BRIDGE_ENV()) };
}

function parseHandoff(stdout: string): { url: string; api: string; password: string } {
  const url = /URL:\s+(\S+)/.exec(stdout)?.[1];
  const api = /API:\s+(\S+)/.exec(stdout)?.[1];
  const password = /Password:\s+(\S+)/.exec(stdout)?.[1];
  if (!url || !api || !password) throw new Error('cannot parse CLI output:\n' + stdout);
  return { url, api, password };
}

describe('end-to-end: CLI -> worker -> retrieval -> decryption', () => {
  it('pushes, publicly serves ciphertext, and decrypts with only the password', async () => {
    const content = [
      '# HANDOFF',
      '',
      '## 当前进度',
      '- Bridge V1 已实现：客户端 AES-256-GCM 加密，服务器零明文',
      '## 待办',
      '- 让 ChatGPT 取回并继续设计',
    ].join('\n');
    const { result } = await pushFile('HANDOFF.md', content, ['--ttl', '300']);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('已回读解密验证');

    const { url, api, password } = parseHandoff(result.stdout);
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/h\/[0-9A-Z]{26}$/);

    // an anonymous client (e.g. a reasoning agent) can fetch and decrypt
    const res = await fetch(api);
    expect(res.status).toBe(200);
    expect(res.headers.get('Cache-Control')).toBe('no-store');
    const envelope = (await res.json()) as Parameters<typeof decryptHandoff>[0];
    expect(await decryptHandoff(envelope, password)).toBe(content);

    // wrong password must fail
    await expect(decryptHandoff(envelope, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA')).rejects.toThrow();

    // the human-facing viewer page is served
    const page = await fetch(url);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('Secure Agent Handoff');
  }, 90_000);

  it('aborts on detected credentials and pushes with --allow-secrets', async () => {
    const leaky = '配置如下：\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n';
    const aborted = await pushFile('LEAK.md', leaky);
    expect(aborted.result.code).toBe(2);
    expect(aborted.result.stdout).toContain('疑似凭据');
    expect(aborted.result.stderr).toContain('Context Firewall');
    // nothing was stored
    expect(aborted.result.stdout).not.toContain('URL:');

    const forced = await pushFile('LEAK2.md', leaky, ['--allow-secrets', 'e2e: 测试豁免通道，内容为虚构样例']);
    expect(forced.result.code).toBe(0);
    expect(forced.result.stdout).toContain('防火墙豁免');
  }, 90_000);

  it('rejects unauthenticated uploads and unknown ids over real HTTP', async () => {
    const base = `http://127.0.0.1:${server.port}`;
    const unauth = await fetch(base + '/v1/handoffs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(unauth.status).toBe(401);
    expect((await fetch(base + '/v1/handoffs/AAAAAAAAAAAAAAAAAAAAAAAAAA')).status).toBe(404);
  });

  it('lifecycle over real HTTP: claim, in-lease reads, burn (410), status', async () => {
    // dedicated short-lease server so the test can cross the deadline quickly
    const leaseServer = await startDevServer({ leaseSeconds: 2 });
    try {
      const base = `http://127.0.0.1:${leaseServer.port}`;
      const file = path.join(workdir, 'LIFE.md');
      writeFileSync(file, 'life cycle');
      const result = await run(['push', file, '--ttl', '300'], {
        BRIDGE_URL: base,
        BRIDGE_TOKEN: leaseServer.token,
      });
      expect(result.code).toBe(0);
      const { api } = parseHandoff(result.stdout);

      // sender token reads (CLI verify) must not have claimed it
      let st = await (await fetch(api + '/status')).json();
      expect(st.status).toBe('unclaimed');

      // recipient claims by reading
      expect((await fetch(api)).status).toBe(200);
      st = await (await fetch(api + '/status')).json();
      expect(st.status).toBe('claimed');
      expect(st.lease_remaining_seconds).toBeGreaterThan(0);

      // age the claim past the lease, then expect 410 burned
      const id = api.split('/').pop() as string;
      const stored = JSON.parse((await leaseServer.kv.get('h:' + id)) as string) as { claimed_at: string };
      stored.claimed_at = new Date(Date.now() - 31_000).toISOString();
      await leaseServer.kv.put('h:' + id, JSON.stringify(stored));
      const after = await fetch(api);
      expect(after.status).toBe(410);
      st = await (await fetch(api + '/status')).json();
      expect(st.status).toBe('burned');
    } finally {
      await leaseServer.close();
    }
  }, 90_000);

  it('honours short TTL expiry through the KV layer', async () => {
    const { result } = await pushFile('SHORT.md', 'short-lived', ['--ttl', '60']);
    expect(result.code).toBe(0);
    const { api } = parseHandoff(result.stdout);
    expect((await fetch(api)).status).toBe(200);
    // walk the clock past expiry inside the KV mock (same semantics as Cloudflare KV)
    const id = api.split('/').pop() as string;
    const stored = JSON.parse((await server.kv.get('h:' + id)) as string) as { expires_at: string };
    stored.expires_at = new Date(Date.now() - 1000).toISOString();
    await server.kv.put('h:' + id, JSON.stringify(stored));
    expect((await fetch(api)).status).toBe(404);
  }, 90_000);

  it('pushes multi-file Context Bundles: originals travel verbatim, blocked files dropped', async () => {
    const agentsMd = path.join(workdir, 'AGENTS.md');
    const modelsYaml = path.join(workdir, 'models.yaml');
    const notesTxt = path.join(workdir, 'notes.txt');
    const envFile = path.join(workdir, '.env');
    const pngFile = path.join(workdir, 'logo.png');
    writeFileSync(agentsMd, '# Agent 规则\n优先阅读本文件。\n');
    writeFileSync(modelsYaml, 'routing:\n  default: gpt-5-mini\n');
    writeFileSync(notesTxt, '普通文本文件\n');
    writeFileSync(envFile, 'API_KEY=secret-value-123\n');
    writeFileSync(pngFile, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));

    const result = await run(
      [
        'push',
        agentsMd,
        modelsYaml,
        notesTxt,
        envFile,
        pngFile,
        '--prompt',
        '当前模型路由设计是否过度设计？请阅读原始文件后判断。',
      ],
      BRIDGE_ENV(),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Context Bundle ready');
    expect(result.stdout).toContain('当前模型路由设计是否过度设计');
    // firewall drops the credential file and the binary, keeps the text files
    expect(result.stdout).toContain('✓ AGENTS.md');
    expect(result.stdout).toContain('✗ ' + envFile);
    expect(result.stdout).toContain('✗ ' + pngFile);
    expect(result.stdout).toContain('已剔除 2 个文件');

    const { api, password } = parseHandoff(result.stdout);
    const res = await fetch(api);
    expect(res.status).toBe(200);
    const record = (await res.json()) as {
      layout: string;
      id: string;
      salt: string;
      iterations: number;
      objects: Array<{ object_id: string; iv: string; ciphertext: string }>;
    };
    expect(record.layout).toBe('split');

    // manifest first, then files independently — the whole point of split transport
    const manifestObj = record.objects.find((o) => o.object_id === 'manifest')!;
    const manifestText = await decryptSplitObject(record, password, record.id, 'manifest', manifestObj.iv, manifestObj.ciphertext);
    const manifest = JSON.parse(manifestText) as {
      protocol: string;
      request: { prompt: string };
      files: Array<{ object_id: string; path: string; media_type: string; sha256: string }>;
    };
    expect(manifest.protocol).toBe('agent-context-bundle');
    expect(manifest.request.prompt).toContain('过度设计');
    expect(manifest.files).toHaveLength(3);
    expect(manifest.files.some((f) => f.path.includes('.env'))).toBe(false);

    const agents = manifest.files.find((f) => f.path.endsWith('AGENTS.md'))!;
    expect(agents.media_type).toBe('text/markdown');
    const agentsObj = record.objects.find((o) => o.object_id === agents.object_id)!;
    const agentsText = await decryptSplitObject(record, password, record.id, agents.object_id, agentsObj.iv, agentsObj.ciphertext);
    expect(agentsText).toContain('优先阅读本文件');
    expect(await sha256Hex(agentsText)).toBe(agents.sha256);
  }, 90_000);
});
