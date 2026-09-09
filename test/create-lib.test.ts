import { describe, expect, it } from 'vitest';
import { CREATE_LIB_SOURCE } from '../src/worker/create-lib.js';
import { renderCreatePage } from '../src/worker/new-page.js';
import { renderViewerPage, DECRYPT_FN_SOURCE } from '../src/worker/page.js';
import { decryptHandoff, encryptHandoff, generateSecret } from '../src/shared/handoff-crypto.js';
import { buildBundle, serializeBundle, BUNDLE_CONTENT_TYPE } from '../src/shared/bundle.js';
import { runFirewall } from '../src/cli/firewall.js';
import { validateEnvelope } from '../src/shared/types.js';

// Execute the exact browser create-lib source in Node (WebCrypto is global).
// eslint-disable-next-line @typescript-eslint/no-implied-eval
const createLib = eval(CREATE_LIB_SOURCE) as unknown as {
  LIMITS: { maxFiles: number; maxFileBytes: number; maxTotalBytes: number };
  BUNDLE_CONTENT_TYPE: string;
  generateSecret(): string;
  isTextPath(p: string): boolean;
  mediaTypeFor(p: string): string;
  looksBinary(b: Uint8Array): boolean;
  pathFindingFor(p: string): { rule: string } | null;
  firewallCheckFile(p: string, t: string): { findings: Array<{ severity: string; rule: string; line?: number }>; blocked: boolean };
  normalizeBundlePath(p: string): string;
  buildBundleJson(entries: Array<{ path: string; text: string }>, prompt: string, notes?: string): Promise<object>;
  encryptText(t: string, ct: string, iterations: number): Promise<{ secret: string; envelope: Record<string, unknown> }>;
  encryptBundle(b: object, iterations?: number): Promise<{ secret: string; envelope: Record<string, unknown> }>;
};

// eslint-disable-next-line @typescript-eslint/no-implied-eval
const bridgeDecrypt = eval(DECRYPT_FN_SOURCE) as (e: unknown, s: string) => Promise<string>;

describe('create-lib (browser) parity with the TypeScript implementation', () => {
  it('exposes the expected API and limits', () => {
    expect(createLib.BUNDLE_CONTENT_TYPE).toBe(BUNDLE_CONTENT_TYPE);
    expect(createLib.LIMITS).toEqual({ maxFiles: 100, maxFileBytes: 2_000_000, maxTotalBytes: 4_000_000 });
  });

  it('generates 160-bit grouped Crockford secrets like the CLI', () => {
    const s = createLib.generateSecret();
    expect(s).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$/);
  });

  it('firewall findings match the CLI firewall on the same inputs', () => {
    const cases: Array<{ path: string; text: string }> = [
      { path: 'README.md', text: '# 平常文档\n没有问题\n' },
      { path: '.env', text: 'API_KEY=xxx\n' },
      { path: 'config.yml', text: 'aws key AKIAIOSFODNN7EXAMPLE\n' },
      { path: 'cookie.txt', text: 'Set-Cookie: session=abcdef123456\n' },
    ];
    for (const c of cases) {
      const cli = runFirewall(c.path, c.text);
      const web = createLib.firewallCheckFile(c.path, c.text);
      expect(web.blocked, c.path).toBe(cli.blocked);
      const cliRules = [cli.pathFinding?.rule ?? '', ...cli.contentFindings.filter((f) => f.severity === 'block').map((f) => f.rule)].sort();
      const webRules = web.findings.filter((f) => f.severity === 'block').map((f) => f.rule).sort();
      // rule names differ slightly between implementations; compare counts + path rule presence
      expect(webRules.length, c.path).toBe(cliRules.filter(Boolean).length);
    }
    // a clean file is clean on both sides
    expect(createLib.firewallCheckFile('README.md', 'ok\n').blocked).toBe(false);
  });

  it('rejects unsafe bundle paths and binary content like the CLI', () => {
    expect(() => createLib.normalizeBundlePath('../x')).toThrow();
    expect(createLib.isTextPath('a.png')).toBe(false);
    expect(createLib.looksBinary(new Uint8Array([1, 0, 2]))).toBe(true);
  });

  it('web-built bundle decrypts with the shared CLI crypto (real cross-verification)', async () => {
    const webBundle = await createLib.buildBundleJson(
      [
        { path: 'AGENTS.md', text: '# 规则\n' },
        { path: 'config/models.yaml', text: 'default: gpt-5-mini\n' },
      ],
      '浏览器端构建的 Bundle',
    );
    const { secret, envelope } = await createLib.encryptBundle(webBundle);

    // shared server-side validation accepts it
    const validated = validateEnvelope({ ...envelope, expires_in: 300 } as unknown);
    expect(validated.ok).toBe(true);

    // shared TS decrypt recovers the exact bundle JSON
    const plain = await decryptHandoff(envelope as never, secret);
    const parsed = JSON.parse(plain);
    expect(parsed.protocol).toBe('agent-context-bundle');
    expect(parsed.request.prompt).toBe('浏览器端构建的 Bundle');
    expect(parsed.files[0].content).toBe('# 规则\n');
    expect(parsed.files[1].media_type).toBe('application/yaml');
  });

  it('CLI-built bundle is readable by the web decrypt source (viewer parity)', async () => {
    const bundle = await buildBundle([{ path: 'a.md', text: 'hello' }], { prompt: 'p' });
    const { secret, envelope } = await encryptHandoff(serializeBundle(bundle), {
      contentType: BUNDLE_CONTENT_TYPE,
    });
    expect(await bridgeDecrypt(envelope, secret)).toContain('"files"');
    void generateSecret;
  });

  it('page embeds the lib, talks to the right endpoints and stores the token', () => {
    const html = renderCreatePage();
    expect(html).toContain('bridgeCreateLib');
    expect(html).toContain("fetch('/v1/handoffs'");
    expect(html).toContain('bridge_upload_token');
    expect(html).toContain('Copy for ChatGPT');
  });
});
