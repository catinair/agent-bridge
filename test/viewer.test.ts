import { describe, expect, it } from 'vitest';
import { DECRYPT_FN_SOURCE, renderViewerPage } from '../src/worker/page.js';
import { encryptHandoff } from '../src/shared/handoff-crypto.js';

// Execute the exact browser decrypt source in Node (WebCrypto is global).
// eslint-disable-next-line @typescript-eslint/no-implied-eval
const bridgeDecrypt = eval(DECRYPT_FN_SOURCE) as (
  envelope: unknown,
  secret: string,
) => Promise<string>;

describe('viewer page', () => {
  it('server-renders machine discovery links into the raw HTML', () => {
    const html = renderViewerPage('ABC123TEST', 'https://bridge.example.com');
    // body <a> is the most universally followed discovery signal
    expect(html).toContain('href="https://bridge.example.com/v1/handoffs/ABC123TEST">Agent-readable encrypted JSON</a>');
    // <link rel=alternate> with the protocol media type for better-behaved extractors
    expect(html).toContain('<link rel="alternate" type="application/vnd.agent-handoff+json" href="https://bridge.example.com/v1/handoffs/ABC123TEST">');
    expect(html).toContain('type="application/vnd.agent-handoff+json" href="https://bridge.example.com/v1/handoffs/ABC123TEST">Agent-readable');
    expect(html).toContain('bridgeDecrypt');
    expect(html).toContain('Content-Security-Policy');
    expect(html).toContain('noindex, nofollow');
  });

  it('rejects ids that would break out of the link attributes', () => {
    expect(() => renderViewerPage('"><script>')).toThrow();
  });

  it('page decrypt source roundtrips ciphertext produced by the shared encoder', async () => {
    const plaintext = '# 交接文档\n\n由浏览器端 JS 解密验证 ✅';
    const { secret, envelope } = await encryptHandoff(plaintext);
    expect(await bridgeDecrypt(envelope, secret)).toBe(plaintext);
  });

  it('page decrypt source rejects a wrong password', async () => {
    const { envelope } = await encryptHandoff('secret');
    await expect(bridgeDecrypt(envelope, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA')).rejects.toThrow(
      /wrong password/i,
    );
  });
});
