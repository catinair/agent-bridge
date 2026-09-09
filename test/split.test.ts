import { describe, expect, it } from 'vitest';
import {
  buildSplitRecord,
  decryptSplitObject,
  fileObjectId,
  generateHandoffId,
  isValidHandoffId,
} from '../src/shared/split.js';
import { generateSecret } from '../src/shared/handoff-crypto.js';

async function makeRecord() {
  const secret = generateSecret();
  const handoffId = generateHandoffId();
  const manifest = {
    protocol: 'agent-context-bundle' as const,
    version: 1,
    request: { prompt: 'review this' },
    generated_at: new Date().toISOString(),
    generator: 'test',
    files: [
      { object_id: fileObjectId(0), path: 'AGENTS.md', media_type: 'text/markdown', size: 9, sha256: 'x'.repeat(64) },
      { object_id: fileObjectId(1), path: 'config/models.yaml', media_type: 'application/yaml', size: 22, sha256: 'y'.repeat(64) },
    ],
  };
  const record = await buildSplitRecord({
    handoffId,
    secret,
    iterations: 600_000,
    manifest,
    fileTexts: [
      { objectId: fileObjectId(0), text: '# 规则文件\n' },
      { objectId: fileObjectId(1), text: 'routing:\n  default: gpt-5-mini\n' },
    ],
    contentType: 'application/vnd.agent-context-bundle+json',
  });
  return { secret, handoffId, record, manifest };
}

describe('split transport', () => {
  it('builds a record with independent objects and decrypts each one', async () => {
    const { secret, handoffId, record, manifest } = await makeRecord();
    expect(record.layout).toBe('split');
    expect(record.id).toBe(handoffId);
    expect(isValidHandoffId(record.id)).toBe(true);
    expect(record.objects.map((o) => o.object_id)).toEqual(['manifest', 'f1', 'f2']);

    const manifestText = await decryptSplitObject(
      record, secret, handoffId, 'manifest',
      record.objects[0]!.iv, record.objects[0]!.ciphertext,
    );
    expect(JSON.parse(manifestText).files).toHaveLength(2);

    const f1 = await decryptSplitObject(
      record, secret, handoffId, 'f1',
      record.objects[1]!.iv, record.objects[1]!.ciphertext,
    );
    expect(f1).toBe('# 规则文件\n');
  });

  it('AAD binding rejects reordering / renaming of objects', async () => {
    const { secret, handoffId, record } = await makeRecord();
    const f1 = record.objects.find((o) => o.object_id === 'f1')!;
    const f2 = record.objects.find((o) => o.object_id === 'f2')!;
    // swap the two ciphertexts: decrypting under the swapped identity must fail
    await expect(
      decryptSplitObject(record, secret, handoffId, 'f1', f2.iv, f2.ciphertext),
    ).rejects.toThrow();
  });

  it('rejects a wrong secret', async () => {
    const { handoffId, record } = await makeRecord();
    const f1 = record.objects.find((o) => o.object_id === 'f1')!;
    await expect(
      decryptSplitObject(record, generateSecret(), handoffId, 'f1', f1.iv, f1.ciphertext),
    ).rejects.toThrow();
  });

  it('rejects splicing an object across handoffs (id is bound via AAD)', async () => {
    const first = await makeRecord();
    const second = await makeRecord();
    const f1 = first.record.objects.find((o) => o.object_id === 'f1')!;
    await expect(
      decryptSplitObject(second.record, first.secret, second.handoffId, 'f1', f1.iv, f1.ciphertext),
    ).rejects.toThrow();
  });
});
