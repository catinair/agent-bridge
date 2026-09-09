/**
 * Context Firewall — the pre-upload policy layer for handoff content.
 *
 * The strongest cryptosystem cannot help if the plaintext should never have
 * been shipped. This runs BEFORE encryption and has three layers:
 *
 *   1. path policy   — default-deny for credential-bearing file names
 *   2. content scan  — credential patterns (regex library in scan.ts)
 *   3. anomaly heuristics — high-entropy blobs, oversized documents (warn)
 *
 * Severity model:
 *   - "block" findings abort the push. Overridable only with an explicit,
 *     recorded human reason (`--allow-secrets "<reason>"`), never silently.
 *   - "warn" findings are printed but do not block.
 */
import { basename } from 'node:path';
import { SECRET_PATTERNS, type ScanFinding } from './scan.js';

export type Severity = 'block' | 'warn';

export interface FirewallFinding {
  severity: Severity;
  layer: 'path' | 'content' | 'anomaly';
  rule: string;
  line?: number;
  detail: string;
}

/** Basenames denied when the file name equals or starts with one of these. */
const PATH_DENY_BASENAMES = [
  '.env',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'credential',
  'credentials',
  'secret',
  'secrets',
  'cookie',
  'cookies',
  'auth',
  'passwd',
  '.npmrc',
  '.netrc',
  '.htpasswd',
];

/** Extensions that are key material or credential stores, no exceptions. */
const PATH_DENY_EXTENSIONS = ['.pem', '.key', '.p12', '.pfx', '.p7b', '.keystore', '.kdbx', '.jks'];

/** Directory components that are never meaningful to hand off. */
const PATH_DENY_SEGMENTS = ['.git', '.ssh', 'node_modules'];

export function checkPath(filePath: string): FirewallFinding | null {
  const p = filePath.toLowerCase().replace(/\\/g, '/');
  const base = basename(p);

  for (const seg of PATH_DENY_SEGMENTS) {
    if (p.split('/').includes(seg)) {
      return {
        severity: 'block',
        layer: 'path',
        rule: `path in ${seg}/`,
        detail: `"${filePath}" 位于默认拒绝目录 ${seg}/`,
      };
    }
  }
  for (const ext of PATH_DENY_EXTENSIONS) {
    if (base.endsWith(ext)) {
      return {
        severity: 'block',
        layer: 'path',
        rule: `key-material extension ${ext}`,
        detail: `"${filePath}" 是密钥材料文件`,
      };
    }
  }
  for (const name of PATH_DENY_BASENAMES) {
    if (base === name || base.startsWith(name)) {
      return {
        severity: 'block',
        layer: 'path',
        rule: `credential filename ${name}*`,
        detail: `"${filePath}" 命中凭据文件命名策略`,
      };
    }
  }
  return null;
}

const HIGH_ENTROPY_RUN = /[A-Za-z0-9+/_=-]{40,}/;

export function checkContent(text: string): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, idx) => {
    for (const p of SECRET_PATTERNS) {
      if (p.re.test(line)) {
        findings.push({
          severity: 'block',
          layer: 'content',
          rule: p.name,
          line: idx + 1,
          detail: `疑似凭据（第 ${idx + 1} 行）：${p.name}`,
        });
      }
    }
    if (HIGH_ENTROPY_RUN.test(line)) {
      findings.push({
        severity: 'warn',
        layer: 'anomaly',
        rule: 'high-entropy blob',
        line: idx + 1,
        detail: `第 ${idx + 1} 行包含长高熵字符串，可能是未识别的密钥（仅警告）`,
      });
    }
  });

  return findings;
}

export interface FirewallReport {
  pathFinding: FirewallFinding | null;
  contentFindings: FirewallFinding[];
  /** true when there is at least one "block" finding */
  blocked: boolean;
  bytes: number;
  oversizedWarn: boolean;
}

const SIZE_WARN_BYTES = 512 * 1024;

export function runFirewall(filePath: string, content: string): FirewallReport {
  const pathFinding = checkPath(filePath);
  const contentFindings = checkContent(content);
  const bytes = Buffer.byteLength(content, 'utf8');
  return {
    pathFinding,
    contentFindings,
    blocked: pathFinding !== null || contentFindings.some((f) => f.severity === 'block'),
    bytes,
    oversizedWarn: bytes > SIZE_WARN_BYTES,
  };
}

export function printReport(report: FirewallReport): void {
  const total = (report.pathFinding ? 1 : 0) + report.contentFindings.length;
  if (total === 0 && !report.oversizedWarn) {
    console.log('🛡 Context Firewall：通过（路径、内容、熵异常均无发现）');
    return;
  }

  console.log('🛡 Context Firewall：');
  if (report.pathFinding) {
    console.log(`   🚫 [路径] ${report.pathFinding.detail}（规则：${report.pathFinding.rule}）`);
  }
  for (const f of report.contentFindings.slice(0, 20)) {
    console.log(`   ${f.severity === 'block' ? '🚫' : '⚠️ '} [${f.layer}] ${f.detail}`);
  }
  if (report.contentFindings.length > 20) {
    console.log(`   … 其余 ${report.contentFindings.length - 20} 条发现已省略`);
  }
  if (report.oversizedWarn) {
    console.log(`   ⚠️  [anomaly] 文件 ${report.bytes} 字节，超出常规交接体积（仅警告）`);
  }
}

export type { ScanFinding };
