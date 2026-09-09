import { describe, expect, it } from 'vitest';
import { checkContent, checkPath, runFirewall } from '../src/cli/firewall.js';
import { validateEnvelope } from '../src/shared/types.js';
import { encryptHandoff } from '../src/shared/handoff-crypto.js';

describe('context firewall: path policy (default deny)', () => {
  it.each([
    '.env',
    '.env.local',
    'config/.env.production',
    'id_rsa',
    'id_ed25519',
    'server.key',
    'cert.pem',
    'credentials.json',
    'secrets.yaml',
    'auth.json',
    'cookies.txt',
    '.npmrc',
    '.git/config',
    'node_modules/left-pad/index.js',
  ])('denies %s', (p) => {
    expect(checkPath(p)?.severity).toBe('block');
  });

  it.each(['HANDOFF.md', '.ai/HANDOFF.md', 'notes.md', 'src/worker/index.ts'])('allows %s', (p) => {
    expect(checkPath(p)).toBeNull();
  });
});

describe('context firewall: content scan', () => {
  it('blocks credential patterns with line numbers', () => {
    const findings = checkContent('正常行\naws key AKIAIOSFODNN7EXAMPLE here\n');
    const block = findings.find((f) => f.severity === 'block');
    expect(block?.line).toBe(2);
  });

  it('blocks cookie/session headers', () => {
    expect(checkContent('Set-Cookie: session=abcdef1234567890; HttpOnly').some((f) => f.severity === 'block')).toBe(true);
    expect(checkContent('session_token = "abcdef1234567890"').some((f) => f.severity === 'block')).toBe(true);
  });

  it('warns (not blocks) on high-entropy blobs', () => {
    const blob = 'Zm9vYmFy'.repeat(8); // 72 chars of base64-ish text, no pattern match
    const findings = checkContent(`blob: ${blob}`);
    expect(findings.every((f) => f.severity === 'warn')).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('runFirewall aggregates path + content into a single verdict', () => {
    const clean = runFirewall('HANDOFF.md', '# 平常的交接文档\n没有问题\n');
    expect(clean.blocked).toBe(false);

    const dirty = runFirewall('.env', 'DATABASE_URL=postgres://u:p@h/db\n');
    expect(dirty.blocked).toBe(true);
  });
});

describe('protocol self-description (V2 envelope)', () => {
  it('encrypt output carries machine-readable normalization hints', async () => {
    const { envelope } = await encryptHandoff('x');
    expect(envelope.protocol).toBe('agent-handoff');
    expect(envelope.encoding).toBe('utf-8');
    expect(envelope.secret_encoding).toBe('base32-crockford-grouped-4');
    expect(envelope.secret_normalization).toBe('strip-hyphens-whitespace-uppercase');
  });

  it('server validation passes the fields through and rejects bad values', async () => {
    const { envelope } = await encryptHandoff('x');
    const ok = validateEnvelope({ ...envelope, expires_in: 300 });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.envelope.protocol).toBe('agent-handoff');
      expect(ok.envelope.secret_normalization).toBe('strip-hyphens-whitespace-uppercase');
    }

    const bad = validateEnvelope({ ...envelope, protocol: 'something-else', expires_in: 300 });
    expect(bad.ok).toBe(false);

    // backward compatibility: V1 envelopes without the new fields still validate,
    // and defaults are filled in so every stored envelope is self-describing
    const legacy: Record<string, unknown> = { ...envelope };
    delete legacy.protocol;
    delete legacy.encoding;
    delete legacy.secret_encoding;
    delete legacy.secret_normalization;
    const legacyOk = validateEnvelope({ ...legacy, expires_in: 300 });
    expect(legacyOk.ok).toBe(true);
    if (legacyOk.ok) {
      expect(legacyOk.envelope.secret_normalization).toBe('strip-hyphens-whitespace-uppercase');
    }
  });
});
