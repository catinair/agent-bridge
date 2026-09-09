/**
 * Browser-side "create" library for the /new page, shipped as an inline
 * <script> source string (same pattern as the viewer's DECRYPT_FN_SOURCE).
 *
 * It re-implements, in dependency-free ES5-ish JS, exactly what the CLI does:
 *   path/credential firewall → Context Bundle JSON → secret (160-bit,
 *   Crockford base32, grouped) → PBKDF2-SHA256 → AES-256-GCM → envelope.
 *
 * Keeping it as an exported string lets tests execute the exact same source
 * in Node and cross-verify against the shared TypeScript implementation
 * (encrypt with the page lib, decrypt with the CLI crypto, and vice versa).
 * Plain JS, single quotes, no template literals — embedded in a TS template.
 */
export const CREATE_LIB_SOURCE = `(function bridgeCreateLib() {
  'use strict';
  var B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  var BUNDLE_CONTENT_TYPE = 'application/vnd.agent-context-bundle+json';
  var DEFAULT_ITERATIONS = 600000;
  var LIMITS = { maxFiles: 100, maxFileBytes: 2000000, maxTotalBytes: 4000000 };

  function bytesToB64(bytes) {
    var bin = '';
    var CH = 0x8000;
    for (var i = 0; i < bytes.length; i += CH) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return btoa(bin);
  }

  function b32encode(bytes) {
    var bits = 0, value = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  function generateSecret() {
    var bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    var encoded = b32encode(bytes);
    return encoded.replace(/(.{4})/g, '$1-').replace(/-$/, '');
  }

  function normalizeSecretInput(s) {
    return s.replace(/[\\s-]/g, '').toUpperCase();
  }

  async function sha256Hex(bytes) {
    var d = await crypto.subtle.digest('SHA-256', bytes);
    return Array.prototype.map.call(new Uint8Array(d), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  var MEDIA = {
    md: 'text/markdown', markdown: 'text/markdown', txt: 'text/plain',
    json: 'application/json', yaml: 'application/yaml', yml: 'application/yaml',
    toml: 'application/toml', sql: 'application/sql', html: 'text/html',
    htm: 'text/html', css: 'text/css', csv: 'text/csv', xml: 'application/xml',
    ts: 'text/x-typescript', tsx: 'text/x-typescript', mts: 'text/x-typescript',
    js: 'text/x-javascript', mjs: 'text/x-javascript', jsx: 'text/x-javascript',
    py: 'text/x-python', rb: 'text/x-ruby', go: 'text/x-go', rs: 'text/x-rust',
    java: 'text/x-java', c: 'text/x-c', h: 'text/x-c', cc: 'text/x-c++',
    cpp: 'text/x-c++', sh: 'text/x-shellscript', swift: 'text/x-swift',
    kt: 'text/x-kotlin', php: 'text/x-php', ini: 'text/plain', cfg: 'text/plain',
    conf: 'text/plain'
  };

  function baseName(p) {
    var parts = p.replace(/\\\\/g, '/').split('/');
    return parts[parts.length - 1].toLowerCase();
  }
  function isTextPath(p) {
    var b = baseName(p);
    if (b === 'dockerfile' || b === 'license' || b === 'makefile' || b.indexOf('.gitignore') === 0) return true;
    var dot = b.lastIndexOf('.');
    if (dot < 0) return false;
    return MEDIA.hasOwnProperty(b.slice(dot + 1));
  }
  function mediaTypeFor(p) {
    if (baseName(p) === 'dockerfile') return 'text/plain';
    var b = baseName(p);
    var dot = b.lastIndexOf('.');
    if (dot < 0) return 'text/plain';
    return MEDIA[b.slice(dot + 1)] || 'text/plain';
  }
  function looksBinary(bytes) {
    for (var i = 0; i < bytes.length; i++) { if (bytes[i] === 0) return true; }
    return false;
  }

  var PATH_DENY_BASENAMES = ['.env', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
    'credential', 'credentials', 'secret', 'secrets', 'cookie', 'cookies',
    'auth', 'passwd', '.npmrc', '.netrc', '.htpasswd'];
  var PATH_DENY_EXTENSIONS = ['.pem', '.key', '.p12', '.pfx', '.p7b', '.keystore', '.kdbx', '.jks'];
  var PATH_DENY_SEGMENTS = ['.git', '.ssh', 'node_modules'];

  function pathFindingFor(p) {
    var lower = p.toLowerCase().replace(/\\\\/g, '/');
    var parts = lower.split('/');
    var base = parts[parts.length - 1];
    for (var i = 0; i < PATH_DENY_SEGMENTS.length; i++) {
      if (parts.indexOf(PATH_DENY_SEGMENTS[i]) >= 0) return { rule: 'path in ' + PATH_DENY_SEGMENTS[i] + '/' };
    }
    for (var j = 0; j < PATH_DENY_EXTENSIONS.length; j++) {
      if (base.slice(-PATH_DENY_EXTENSIONS[j].length) === PATH_DENY_EXTENSIONS[j]) {
        return { rule: 'key-material extension ' + PATH_DENY_EXTENSIONS[j] };
      }
    }
    for (var k = 0; k < PATH_DENY_BASENAMES.length; k++) {
      if (base === PATH_DENY_BASENAMES[k] || base.indexOf(PATH_DENY_BASENAMES[k]) === 0) {
        return { rule: 'credential filename ' + PATH_DENY_BASENAMES[k] + '*' };
      }
    }
    return null;
  }

  var SECRET_PATTERNS = [
    { name: 'AWS Access Key ID', re: /\\bAKIA[0-9A-Z]{16}\\b/ },
    { name: 'Private key block', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
    { name: 'Certificate/key material block', re: /-----BEGIN (?:CERTIFICATE|ENCRYPTED PRIVATE KEY|OPENSSH PRIVATE KEY)-----/ },
    { name: 'GitHub token', re: /\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\\b/ },
    { name: 'GitHub fine-grained PAT', re: /\\bgithub_pat_[A-Za-z0-9_]{20,}\\b/ },
    { name: 'OpenAI-style API key', re: /\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\\b/ },
    { name: 'Anthropic API key', re: /\\bsk-ant-[A-Za-z0-9_-]{20,}\\b/ },
    { name: 'Slack token', re: /\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b/ },
    { name: 'Google API key', re: /\\bAIza[0-9A-Za-z_-]{35}\\b/ },
    { name: 'JWT', re: /\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b/ },
    { name: 'Bearer/Authorization value', re: /\\b(?:Bearer|Basic)\\s+[A-Za-z0-9._~+\\/=\\-]{15,}\\b/ },
    { name: 'Credential assignment', re: /\\b(?:api[_-]?key|secret|passwd|password|token|credential)\\b\\s*[:=]\\s*["'][^"'\\s]{8,}["']/i },
    { name: 'Connection string with credentials', re: /\\b(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis):\\/\\/[^\\s:@/]+:[^\\s@/]+@[^\\s]+/i },
    { name: 'Cookie / session header', re: /(?:^|\\b)(?:set-cookie|cookie)\\s*:\\s*\\S+/i },
    { name: 'Session token assignment', re: /\\bsession[_-]?(?:id|token|key)\\b\\s*[:=]\\s*["'][^"'\\s]{8,}["']/i }
  ];

  var HIGH_ENTROPY_RUN = /[A-Za-z0-9+/_=-]{40,}/;

  function firewallCheckFile(path, text) {
    var findings = [];
    var pf = pathFindingFor(path);
    if (pf) findings.push({ severity: 'block', layer: 'path', rule: pf.rule });
    var lines = text.split(/\\r?\\n/);
    for (var i = 0; i < lines.length; i++) {
      for (var j = 0; j < SECRET_PATTERNS.length; j++) {
        if (SECRET_PATTERNS[j].re.test(lines[i])) {
          findings.push({ severity: 'block', layer: 'content', rule: SECRET_PATTERNS[j].name, line: i + 1 });
        }
      }
      if (HIGH_ENTROPY_RUN.test(lines[i])) {
        findings.push({ severity: 'warn', layer: 'anomaly', rule: 'high-entropy blob', line: i + 1 });
      }
    }
    return { findings: findings, blocked: findings.some(function (f) { return f.severity === 'block'; }) };
  }

  function normalizeBundlePath(p) {
    var out = p.replace(/\\\\/g, '/').replace(/^\\.\\//, '');
    if (out === '' || out.charAt(0) === '/' || out.split('/').indexOf('..') >= 0) {
      throw new Error('invalid bundle path');
    }
    return out;
  }

  async function buildBundleJson(entries, prompt, notes) {
    var files = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var bytes = new TextEncoder().encode(e.text);
      files.push({
        path: normalizeBundlePath(e.path),
        media_type: mediaTypeFor(e.path),
        size: bytes.length,
        sha256: await sha256Hex(bytes),
        content: e.text
      });
    }
    var bundle = {
      protocol: 'agent-context-bundle',
      version: 1,
      request: { prompt: prompt || '' },
      generated_at: new Date().toISOString(),
      generator: 'agent-bridge-web',
      files: files
    };
    if (notes) bundle.notes = notes;
    return bundle;
  }

  async function deriveKeyRaw(secretInput, salt, iterations) {
    var km = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(normalizeSecretInput(secretInput)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  }

  async function encryptText(plaintext, contentType, iterations) {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var secret = generateSecret();
    var key = await deriveKeyRaw(secret, salt, iterations);
    var ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(plaintext));
    return {
      secret: secret,
      envelope: {
        protocol: 'agent-handoff',
        v: 1,
        algorithm: 'AES-256-GCM',
        kdf: 'PBKDF2-SHA256',
        iterations: iterations,
        salt: bytesToB64(salt),
        iv: bytesToB64(iv),
        ciphertext: bytesToB64(new Uint8Array(ct)),
        content_type: contentType,
        encoding: 'utf-8',
        secret_encoding: 'base32-crockford-grouped-4',
        secret_normalization: 'strip-hyphens-whitespace-uppercase'
      }
    };
  }

  async function encryptBundle(bundle, iterations) {
    return encryptText(JSON.stringify(bundle, null, 2), BUNDLE_CONTENT_TYPE, iterations || DEFAULT_ITERATIONS);
  }

  return {
    LIMITS: LIMITS,
    BUNDLE_CONTENT_TYPE: BUNDLE_CONTENT_TYPE,
    bytesToB64: bytesToB64,
    sha256Hex: sha256Hex,
    generateSecret: generateSecret,
    normalizeSecretInput: normalizeSecretInput,
    isTextPath: isTextPath,
    mediaTypeFor: mediaTypeFor,
    looksBinary: looksBinary,
    pathFindingFor: pathFindingFor,
    firewallCheckFile: firewallCheckFile,
    normalizeBundlePath: normalizeBundlePath,
    buildBundleJson: buildBundleJson,
    encryptText: encryptText,
    encryptBundle: encryptBundle
  };
})()`;
