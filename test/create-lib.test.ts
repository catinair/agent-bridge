import { describe, expect, it } from 'vitest';
import { CREATE_LIB_SOURCE } from '../src/worker/create-lib.js';
import { renderCreatePage } from '../src/worker/new-page.js';
import { renderViewerPage, DECRYPT_FN_SOURCE, BRIDGE_SPLIT_SOURCE } from '../src/worker/page.js';
import { decryptSplitObject } from '../src/shared/split.js';
import { runFirewall } from '../src/cli/firewall.js';
import { BUNDLE_CONTENT_TYPE } from '../src/shared/bundle.js';

// Execute the exact browser create-lib source in Node (WebCrypto is global).
const createLib = eval(CREATE_LIB_SOURCE) as unknown as {
  LIMITS: { maxFiles: number; maxFileBytes: number; maxTotalBytes: number };
  BUNDLE_CONTENT_TYPE: string;
  generateSecret(): string;
  isTextPath(p: string): boolean;
  looksBinary(b: Uint8Array): boolean;
  pathFindingFor(p: string): { rule: string } | null;
  firewallCheckFile(p: string, t: string): { findings: Array<{ severity: string; rule: string; line?: number }>; blocked: boolean };
  normalizeBundlePath(p: string): string;
  buildSplitHandoff(
    entries: Array<{ path: string; text: string }>,
    prompt: string,
    notes: string,
    origin: string,
  ): Promise<{
    secret: string;
    body: {
      layout: string;
      id: string;
      salt: string;
      iterations: number;
      content_type: string;
      objects: Array<{ object_id: string; iv: string; ciphertext: string }>;
    };
  }>;
};

// The viewer's split-object decryptor must handle lib-built records.
const bridgeDecryptObject = eval(BRIDGE_SPLIT_SOURCE) as (
  record: unknown,
  objectId: string,
  secret: string,
) => Promise<string>;

const ORIGIN = 'https://bridge.example.com';

async function makeBuilt() {
  return createLib.buildSplitHandoff(
    [
      { path: 'AGENTS.md', text: '# 规则\n' },
      { path: 'config/models.yaml', text: 'default: gpt-5-mini\n' },
    ],
    '浏览器端构建的 split Bundle',
    'config/models.yaml 是实际配置',
    ORIGIN,
  );
}

describe('create-lib (browser) parity with the TypeScript implementation', () => {
  it('exposes the expected API and limits', () => {
    expect(createLib.BUNDLE_CONTENT_TYPE).toBe(BUNDLE_CONTENT_TYPE);
    expect(createLib.LIMITS).toEqual({ maxFiles: 100, maxFileBytes: 2_000_000, maxTotalBytes: 4_000_000 });
  });

  it('generates 160-bit grouped Crockford secrets like the CLI', () => {
    expect(createLib.generateSecret()).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$/);
  });

  it('firewall findings match the CLI firewall on the same inputs', () => {
    const cases = [
      { path: 'README.md', text: '# 平常文档\n没有问题\n' },
      { path: '.env', text: 'API_KEY=xxx\n' },
      { path: 'config.yml', text: 'aws key AKIAIOSFODNN7EXAMPLE\n' },
      { path: 'cookie.txt', text: 'Set-Cookie: session=abcdef123456\n' },
    ];
    for (const c of cases) {
      const cli = runFirewall(c.path, c.text);
      const web = createLib.firewallCheckFile(c.path, c.text);
      expect(web.blocked, c.path).toBe(cli.blocked);
      const cliBlocks = [cli.pathFinding?.rule ?? '', ...cli.contentFindings.filter((f) => f.severity === 'block').map((f) => f.rule)].filter(Boolean);
      const webBlocks = web.findings.filter((f) => f.severity === 'block').map((f) => f.rule);
      expect(webBlocks.length, c.path).toBe(cliBlocks.length);
    }
    expect(createLib.firewallCheckFile('README.md', 'ok\n').blocked).toBe(false);
  });

  it('rejects unsafe bundle paths and binary content like the CLI', () => {
    expect(() => createLib.normalizeBundlePath('../x')).toThrow();
    expect(createLib.isTextPath('a.png')).toBe(false);
    expect(createLib.looksBinary(new Uint8Array([1, 0, 2]))).toBe(true);
  });
});

describe('create-lib split transport (cross-verified with shared crypto)', () => {
  it('builds a split body whose manifest carries discoverable hrefs', async () => {
    const built = await makeBuilt();
    expect(built.body.layout).toBe('split');
    expect(built.body.content_type).toBe(BUNDLE_CONTENT_TYPE);
    expect(built.body.objects.map((o) => o.object_id)).toEqual(['manifest', 'f1', 'f2']);

    const manifestObj = built.body.objects.find((o) => o.object_id === 'manifest')!;
    const manifestText = await decryptSplitObject(
      built.body, built.secret, built.body.id, 'manifest', manifestObj.iv, manifestObj.ciphertext,
    );
    const manifest = JSON.parse(manifestText) as {
      request: { prompt: string };
      notes?: string;
      files: Array<{ object_id: string; path: string; href: string; json_href: string }>;
    };
    expect(manifest.request.prompt).toBe('浏览器端构建的 split Bundle');
    expect(manifest.notes).toBe('config/models.yaml 是实际配置');
    expect(manifest.files[0]?.href).toBe(ORIGIN + '/v1/handoffs/' + built.body.id + '/files/f1.txt');
    expect(manifest.files[0]?.json_href).toBe(ORIGIN + '/v1/handoffs/' + built.body.id + '/files/f1');
  });

  it('shared crypto decrypts file objects, and the viewer decryptor agrees', async () => {
    const built = await makeBuilt();
    const plaintext = await bridgeDecryptObject(built.body, 'f1', built.secret);
    expect(plaintext).toBe('# 规则\n');
    await expect(bridgeDecryptObject(built.body, 'manifest', 'WRONG')).rejects.toThrow();
  });
});

describe('viewer page', () => {
  it('embeds both decryptors, discovery links and a strict CSP', () => {
    const html = renderViewerPage('ABC123TEST', 'https://bridge.example.com');
    expect(html).toContain('href="https://bridge.example.com/v1/handoffs/ABC123TEST.txt"');
    expect(html).toContain('text envelope');
    expect(html).toContain('bridgeDecrypt');
    expect(html).toContain('bridgeDecryptObject');
    expect(html).toContain('Content-Security-Policy');
    expect(html).toContain('noindex, nofollow');
  });

  it('split decryptor uses object-type domain separation in the AAD', () => {
    expect(BRIDGE_SPLIT_SOURCE).toContain("? 'manifest' : 'file/' + objectId");
    expect(BRIDGE_SPLIT_SOURCE).toContain("agent-handoff/v2/' + record.id + '/' + pathSeg");
  });

  it('page decrypt source roundtrips ciphertext produced by the shared encoder', async () => {
    const { encryptHandoff } = await import('../src/shared/handoff-crypto.js');
    const decrypt = eval(DECRYPT_FN_SOURCE) as (e: unknown, s: string) => Promise<string>;
    const { secret, envelope } = await encryptHandoff('# 交接文档\n');
    expect(await decrypt(envelope, secret)).toBe('# 交接文档\n');
  });
});
