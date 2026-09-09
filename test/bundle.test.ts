import { describe, expect, it } from 'vitest';
import {
  BUNDLE_CONTENT_TYPE,
  buildBundle,
  isTextPath,
  looksBinary,
  mediaTypeFor,
  normalizeBundlePath,
  serializeBundle,
} from '../src/shared/bundle.js';
import { decryptHandoff, encryptHandoff } from '../src/shared/handoff-crypto.js';
import { validateEnvelope } from '../src/shared/types.js';

describe('bundle construction', () => {
  it('builds a self-describing bundle with per-file metadata', async () => {
    const bundle = await buildBundle(
      [
        { path: 'AGENTS.md', text: '# rules\n' },
        { path: 'config/models.yaml', text: 'model: gpt-5\n' },
      ],
      { prompt: 'review 模型路由', generator: 'test' },
    );
    expect(bundle.protocol).toBe('agent-context-bundle');
    expect(bundle.version).toBe(1);
    expect(bundle.request.prompt).toBe('review 模型路由');
    expect(bundle.files).toHaveLength(2);
    expect(bundle.files[0]).toMatchObject({
      path: 'AGENTS.md',
      media_type: 'text/markdown',
      size: 8,
    });
    expect(bundle.files[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.files[1]?.media_type).toBe('application/yaml');
    expect(bundle.generated_at).toBeTruthy();
  });

  it('serializes to JSON that parses back identically', async () => {
    const bundle = await buildBundle([{ path: 'a.md', text: 'x' }], { prompt: 'p' });
    const parsed = JSON.parse(serializeBundle(bundle));
    expect(parsed.files[0].content).toBe('x');
    expect(parsed.request.prompt).toBe('p');
  });

  it('rejects unsafe paths', () => {
    expect(() => normalizeBundlePath('../etc/passwd')).toThrow();
    expect(() => normalizeBundlePath('/abs/path')).toThrow();
    expect(normalizeBundlePath('./docs/a.md')).toBe('docs/a.md');
  });

  it('classifies text vs binary content', () => {
    expect(looksBinary(new TextEncoder().encode('plain text'))).toBe(false);
    expect(looksBinary(new Uint8Array([0x23, 0x00, 0x41]))).toBe(true);
    expect(isTextPath('src/router.ts')).toBe(true);
    expect(isTextPath('Dockerfile')).toBe(true);
    expect(isTextPath('photo.png')).toBe(false);
    expect(mediaTypeFor('notes.txt')).toBe('text/plain');
  });
});

describe('bundle travels through the existing envelope pipeline', () => {
  it('encrypt/decrypt roundtrip preserves the bundle via BUNDLE_CONTENT_TYPE', async () => {
    const bundle = await buildBundle([{ path: 'docs/a.md', text: '# A' }], { prompt: 'p' });
    const { secret, envelope } = await encryptHandoff(serializeBundle(bundle), {
      contentType: BUNDLE_CONTENT_TYPE,
    });
    expect(envelope.content_type).toBe('application/vnd.agent-context-bundle+json');

    const validated = validateEnvelope({ ...envelope, expires_in: 300 });
    expect(validated.ok).toBe(true);

    const plain = await decryptHandoff(envelope, secret);
    const parsed = JSON.parse(plain);
    expect(parsed.protocol).toBe('agent-context-bundle');
    expect(parsed.files[0].content).toBe('# A');
  });
});
