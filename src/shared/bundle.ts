/**
 * Context Bundle — the multi-file payload format.
 *
 * Design principle (from real-world usage): the local agent should do
 * Context Retrieval (pick relevant files), not Context Interpretation
 * (lossy summarization). Original files travel verbatim; a short request
 * explains what the receiving agent should figure out. The decrypted payload
 * is structured JSON so the receiver never needs a filesystem or a ZIP.
 *
 * Text files only in V1: md/txt/json/yaml/toml/code. Binary payloads are
 * rejected by the Context Firewall, not transcoded.
 */

export const BUNDLE_PROTOCOL = 'agent-context-bundle';
export const BUNDLE_VERSION = 1;
/** envelope content_type that marks a payload as a bundle */
export const BUNDLE_CONTENT_TYPE = 'application/vnd.agent-context-bundle+json';

export interface BundleFile {
  path: string;
  media_type: string;
  size: number;
  sha256: string;
  content: string;
}

export interface ContextBundle {
  protocol: typeof BUNDLE_PROTOCOL;
  version: typeof BUNDLE_VERSION;
  request: { prompt: string };
  notes?: string;
  generated_at: string;
  generator: string;
  files: BundleFile[];
}

export const BUNDLE_LIMITS = {
  maxFiles: 100,
  maxFileBytes: 2_000_000,
  maxTotalBytes: 4_000_000,
} as const;

const MEDIA_TYPES: Record<string, string> = {
  md: 'text/markdown',
  markdown: 'text/markdown',
  txt: 'text/plain',
  json: 'application/json',
  yaml: 'application/yaml',
  yml: 'application/yaml',
  toml: 'application/toml',
  sql: 'application/sql',
  html: 'text/html',
  htm: 'text/html',
  css: 'text/css',
  csv: 'text/csv',
  xml: 'application/xml',
  ts: 'text/x-typescript',
  tsx: 'text/x-typescript',
  mts: 'text/x-typescript',
  cts: 'text/x-typescript',
  js: 'text/x-javascript',
  mjs: 'text/x-javascript',
  cjs: 'text/x-javascript',
  jsx: 'text/x-javascript',
  py: 'text/x-python',
  rb: 'text/x-ruby',
  go: 'text/x-go',
  rs: 'text/x-rust',
  java: 'text/x-java',
  c: 'text/x-c',
  h: 'text/x-c',
  cc: 'text/x-c++',
  cpp: 'text/x-c++',
  sh: 'text/x-shellscript',
  swift: 'text/x-swift',
  kt: 'text/x-kotlin',
  php: 'text/x-php',
  ini: 'text/plain',
  cfg: 'text/plain',
  conf: 'text/plain',
  gitignore: 'text/plain',
  dockerfile: 'text/plain',
  lock: 'text/plain',
};

export function isTextPath(filePath: string): boolean {
  const base = filePath.toLowerCase().replace(/\\/g, '/').split('/').pop() ?? '';
  if (base === 'dockerfile' || base === 'license' || base === 'makefile' || base.startsWith('.gitignore')) {
    return true;
  }
  const ext = base.includes('.') ? (base.split('.').pop() ?? '') : '';
  return ext !== '' && ext in MEDIA_TYPES;
}

export function mediaTypeFor(filePath: string): string {
  const base = filePath.toLowerCase().replace(/\\/g, '/').split('/').pop() ?? '';
  if (base === 'dockerfile') return 'text/plain';
  const ext = base.includes('.') ? (base.split('.').pop() ?? '') : '';
  return MEDIA_TYPES[ext] ?? 'text/plain';
}

export function looksBinary(bytes: Uint8Array): boolean {
  // NUL byte is the cheapest reliable binary signal for text-ish formats
  return bytes.includes(0);
}

async function sha256HexBytes(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface BundleEntryInput {
  path: string;
  text: string;
}

/** Normalize the path stored in a bundle: forward slashes, no leading ./, no escapes. */
export function normalizeBundlePath(filePath: string): string {
  const p = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (p === '' || p.startsWith('/') || p.split('/').includes('..')) {
    throw new Error(`invalid bundle path: ${filePath}`);
  }
  return p;
}

export async function buildBundle(
  entries: BundleEntryInput[],
  opts: { prompt?: string; notes?: string; generator?: string } = {},
): Promise<ContextBundle> {
  const files: BundleFile[] = [];
  for (const entry of entries) {
    const path = normalizeBundlePath(entry.path);
    const bytes = new TextEncoder().encode(entry.text);
    files.push({
      path,
      media_type: mediaTypeFor(path),
      size: bytes.length,
      sha256: await sha256HexBytes(bytes),
      content: entry.text,
    });
  }
  return {
    protocol: BUNDLE_PROTOCOL,
    version: BUNDLE_VERSION,
    request: { prompt: opts.prompt ?? '' },
    notes: opts.notes,
    generated_at: new Date().toISOString(),
    generator: opts.generator ?? 'agent-bridge',
    files,
  };
}

export function serializeBundle(bundle: ContextBundle): string {
  return JSON.stringify(bundle, null, 2);
}

export function bundleTotalBytes(bundle: ContextBundle): number {
  return bundle.files.reduce((sum, f) => sum + f.size, 0);
}
