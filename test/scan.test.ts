import { describe, expect, it } from 'vitest';
import { scanForSecrets } from '../src/cli/scan.js';

describe('secret scanning', () => {
  it('flags common credential shapes with line numbers', () => {
    const text = [
      'normal line',
      'aws key AKIAIOSFODNN7EXAMPLE here',
      'token = "supersecretvalue123"',
      '-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');
    const findings = scanForSecrets(text);
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ line: 2, name: 'AWS Access Key ID' }),
        expect.objectContaining({ line: 3, name: expect.stringContaining('Credential assignment') }),
        expect.objectContaining({ line: 4, name: 'Private key block' }),
      ]),
    );
  });

  it('flags jwt / github / openai / slack / google / bearer shapes', () => {
    const text = [
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'ghp_abcdefghijklmnopqrstuvwxzy1234567890',
      'sk-proj-abcdefghijklmnop1234567890',
      'xoxb-1234567890-abcdefghij',
      'AIzaSyABCdefGHIjklMNOpqrsTUVwxyz1234567',
      'Authorization: Bearer abcdefghijklmnopqrst',
    ].join('\n');
    expect(scanForSecrets(text).length).toBeGreaterThanOrEqual(6);
  });

  it('does not flag ordinary handoff content', () => {
    const text = [
      '# HANDOFF',
      '',
      '## Architecture',
      '- uses Cloudflare Workers + KV, TTL = 300s',
      '- password never leaves the two endpoints',
      'const ttl = 300; // seconds',
      'contact: someone@example.com',
    ].join('\n');
    expect(scanForSecrets(text)).toEqual([]);
  });
});
