export interface ScanFinding {
  line: number;
  name: string;
}

/**
 * Heuristic credential detection run over handoff content before encryption.
 * Findings abort the push (unless explicitly overridden) so that generated
 * context documents never ship live credentials.
 */
export const SECRET_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Private key block', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { name: 'Certificate/key material block', re: /-----BEGIN (?:CERTIFICATE|ENCRYPTED PRIVATE KEY|OPENSSH PRIVATE KEY)-----/ },
  {
    name: 'Cookie / session header',
    re: /(?:^|\b)(?:set-cookie|cookie)\s*:\s*\S+/i,
  },
  {
    name: 'Session token assignment',
    re: /\bsession[_-]?(?:id|token|key)\b\s*[:=]\s*["'][^"'\s]{8,}["']/i,
  },
  { name: 'GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/ },
  { name: 'GitHub fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { name: 'OpenAI-style API key (sk-…)', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'Bearer/Authorization value', re: /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{15,}\b/ },
  {
    name: 'Credential assignment (api_key/secret/password/token = …)',
    re: /\b(?:api[_-]?key|secret|passwd|password|token|credential)\b\s*[:=]\s*["'][^"'\s]{8,}["']/i,
  },
  {
    name: 'Connection string with credentials',
    re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s:@/]+:[^\s@/]+@[^\s]+/i,
  },
];

export function scanForSecrets(text: string): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((line, idx) => {
    for (const p of SECRET_PATTERNS) {
      if (p.re.test(line)) {
        findings.push({ line: idx + 1, name: p.name });
      }
    }
  });
  return findings;
}
