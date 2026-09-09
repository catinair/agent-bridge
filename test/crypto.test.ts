import { describe, expect, it } from 'vitest';
import { base32CrockfordDecode, base64ToBytes } from '../src/shared/codec.js';
import {
  DecryptionError,
  DEFAULT_ITERATIONS,
  decryptHandoff,
  encryptHandoff,
  generateSecret,
  normalizeSecret,
} from '../src/shared/handoff-crypto.js';

describe('secret generation', () => {
  it('uses 160 bits of entropy in 8 groups of 4 base32 chars', () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){7}$/);
    expect(base32CrockfordDecode(secret)).toHaveLength(20);
  });

  it('never repeats', () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });

  it('normalizes dashes, case and strips whitespace', () => {
    expect(normalizeSecret('abcd-efgh ijkl mnop')).toBe('ABCDEFGHIJKLMNOP');
    // ambiguous letters are tolerated at decode time, not rewritten here
    expect(base32CrockfordDecode(normalizeSecret('jklm'))).toEqual(base32CrockfordDecode('JK1M'));
  });
});

describe('encrypt/decrypt roundtrip', () => {
  it('roundtrips a plaintext through envelope + secret', async () => {
    const plaintext = '# HANDOFF\n\n中文内容 + code `fences` 🎉\n';
    const { secret, envelope } = await encryptHandoff(plaintext);
    expect(envelope.algorithm).toBe('AES-256-GCM');
    expect(envelope.kdf).toBe('PBKDF2-SHA256');
    expect(envelope.iterations).toBe(DEFAULT_ITERATIONS);
    expect(base64ToBytes(envelope.iv)).toHaveLength(12);
    expect(base64ToBytes(envelope.salt)).toHaveLength(16);
    const decrypted = await decryptHandoff(envelope, secret);
    expect(decrypted).toBe(plaintext);
  });

  it('roundtrips with dashes/case mangled in the typed secret', async () => {
    const plaintext = 'some context';
    const { secret, envelope } = await encryptHandoff(plaintext);
    const mangled = secret.toLowerCase().replaceAll('-', ' ').split(' ').join('-');
    expect(await decryptHandoff(envelope, mangled)).toBe(plaintext);
  });

  it('rejects a wrong secret via GCM auth', async () => {
    const { envelope } = await encryptHandoff('top secret');
    await expect(decryptHandoff(envelope, generateSecret())).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejects tampered ciphertext', async () => {
    const { secret, envelope } = await encryptHandoff('top secret');
    const tampered = { ...envelope, ciphertext: envelope.ciphertext.slice(0, -4) + 'AAAA' };
    await expect(decryptHandoff(tampered, secret)).rejects.toBeInstanceOf(DecryptionError);
  });

  it('rejects unsupported envelope versions', async () => {
    const { envelope } = await encryptHandoff('x');
    await expect(
      decryptHandoff({ ...envelope, v: 99 } as never, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'),
    ).rejects.toBeInstanceOf(DecryptionError);
  });
});
