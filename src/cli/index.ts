import fs from 'node:fs';
import path from 'node:path';
import {
  BUNDLE_CONTENT_TYPE,
  BUNDLE_LIMITS,
  isTextPath,
  looksBinary,
  mediaTypeFor,
  normalizeBundlePath,
  type BundleEntryInput,
} from '../shared/bundle.js';
import { decryptHandoff, DEFAULT_ITERATIONS, encryptHandoff, generateSecret } from '../shared/handoff-crypto.js';
import {
  buildSplitRecord,
  decryptSplitObject,
  fileHrefs,
  fileObjectId,
  generateHandoffId,
  sha256Hex,
  type SplitManifest,
  type SplitManifestFile,
} from '../shared/split.js';
import { LIMITS } from '../shared/types.js';
import { fetchEnvelope, pushEnvelope } from './api.js';
import { copyToClipboard } from './clipboard.js';
import { configPath, loadBridgeConfig, saveBridgeConfig } from './config.js';
import { printReport, runFirewall } from './firewall.js';

const VERSION = '0.1.0';
const DEFAULT_HANDOFF_CANDIDATES = [
  '.ai/HANDOFF.md',
  '.ai/handoff.md',
  'HANDOFF.md',
  'handoff.md',
];

const CONTENT_TYPES: Record<string, string> = {
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.txt': 'text/plain',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.html': 'text/html',
  '.yaml': 'text/yaml',
  '.yml': 'text/yaml',
};

function usage(): never {
  console.log(`agent-bridge CLI v${VERSION} — 零知识临时交接通道

用法：
  bridge push  <file...> [--prompt "<请求>"] [--notes "<说明>"] [--ttl <秒>] [--copy] [--allow-secrets "<理由>"]
      单个 markdown 文件且不带 --prompt：HANDOFF 模式（简单状态同步）。
      多个文件、或带 --prompt：Context Bundle 模式——原始文件原样传输，
      远端 Agent 自己阅读建立理解。文本文件之外会被自动剔除（无豁免）。

      示例：
        bridge push HANDOFF.md
        bridge push AGENTS.md README.md docs/architecture.md --prompt "review 当前架构"

  bridge check <file...>
      只运行 Context Firewall 并输出报告，不上传（退出码 0/2）。

  bridge config --url <https://...> --token <UPLOAD_TOKEN>
      保存 Bridge 地址与上传令牌（写入 ${configPath()}，权限 0600）。
      也可用环境变量 BRIDGE_URL / BRIDGE_TOKEN 临时覆盖。

  bridge help | --help | -h
  bridge --version
`);
  process.exit(0);
}

function fail(message: string, code = 1): never {
  console.error(`错误：${message}`);
  process.exit(code);
}

function parseFlags(args: string[]): { positional: string[]; flags: Map<string, string | boolean> } {
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    if (a === '--copy') {
      flags.set(a, true);
    } else if (a === '--ttl' || a === '--iterations' || a === '--allow-secrets' || a === '--prompt' || a === '--notes') {
      const v = args[++i];
      if (v === undefined) fail(`${a} 需要一个参数`);
      flags.set(a, v);
    } else if (a.startsWith('--')) {
      fail(`未知参数：${a}`);
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function contentTypeFor(file: string): string {
  return CONTENT_TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
}

function resolveInputFiles(positional: string[]): string[] {
  if (positional.length > 0) {
    const unique = [...new Set(positional)];
    for (const f of unique) {
      if (!fs.existsSync(f)) fail(`文件不存在：${f}`);
      if (!fs.statSync(f).isFile()) fail(`不是普通文件：${f}`);
    }
    return unique;
  }
  for (const candidate of DEFAULT_HANDOFF_CANDIDATES) {
    if (fs.existsSync(candidate)) return [candidate];
  }
  fail('未指定文件，且当前目录找不到 .ai/HANDOFF.md 或 HANDOFF.md');
}

/** Path stored inside the bundle: repo-relative when given, basename for absolute inputs. */
function bundlePathFor(file: string): string {
  if (path.isAbsolute(file)) return path.basename(file);
  return normalizeBundlePath(file);
}

async function push(args: string[]): Promise<void> {
  const { positional, flags } = parseFlags(args);
  const files = resolveInputFiles(positional);
  const prompt = flags.has('--prompt') ? String(flags.get('--prompt')).trim() : '';
  const notes = flags.has('--notes') ? String(flags.get('--notes')).trim() : '';
  const isBundle = files.length > 1 || prompt !== '' || notes !== '';
  if (isBundle) {
    return bundlePush(files, { prompt, notes, flags });
  }

  // ---- legacy single-document handoff mode (unchanged semantics) ----
  const file = files[0] as string;
  const plaintext = fs.readFileSync(file, 'utf8');

  const byteLength = Buffer.byteLength(plaintext, 'utf8');
  if (byteLength > LIMITS.maxPlaintextBytes) {
    fail(`文件过大：${byteLength} 字节（上限 ${LIMITS.maxPlaintextBytes}）`);
  }

  const allowReason = flags.has('--allow-secrets') ? String(flags.get('--allow-secrets')).trim() : '';
  const report = runFirewall(file, plaintext);
  printReport(report);

  if (report.blocked) {
    if (!allowReason) {
      console.error(
        '\n🛑 Context Firewall 命中 block 级发现，已中止上传。\n' +
          '   确认必须传输时，携带人类确认过的理由强制推送：\n' +
          '   bridge push <file> --allow-secrets "<为什么必须发>"\n' +
          '   （理由会显示在推送结果中；Agent 不得自行编造理由绕过）',
      );
      process.exit(2);
    }
    if (allowReason.length < 4) {
      fail('豁免理由太短，请写明实际原因（至少 4 个字符）');
    }
  } else if (allowReason) {
    console.log('ℹ️ 未命中 block 级发现，--allow-secrets 豁免未被使用。');
  }

  const cfg = loadBridgeConfig();
  if (!cfg.baseUrl || !cfg.uploadToken) {
    fail(
      `缺少 Bridge 配置。请先执行：\n` +
        `  bridge config --url https://<worker-domain> --token <UPLOAD_TOKEN>\n` +
        `或设置环境变量 BRIDGE_URL / BRIDGE_TOKEN。`,
    );
  }

  const ttl = flags.has('--ttl') ? parseInt(String(flags.get('--ttl')), 10) : LIMITS.defaultTtlSeconds;
  if (!Number.isInteger(ttl) || ttl < LIMITS.minTtlSeconds || ttl > LIMITS.maxTtlSeconds) {
    fail(`--ttl 必须是 ${LIMITS.minTtlSeconds}~${LIMITS.maxTtlSeconds} 之间的整数秒`);
  }

  const iterations = flags.has('--iterations')
    ? parseInt(String(flags.get('--iterations')), 10)
    : DEFAULT_ITERATIONS;
  if (!Number.isInteger(iterations)) fail('--iterations 必须是整数');

  process.stdout.write('🔐 本地加密中（PBKDF2 派生密钥，约 1 秒）…\n');
  const { secret, envelope } = await encryptHandoff(plaintext, {
    contentType: contentTypeFor(file),
    iterations,
  });

  const created = await pushEnvelope(cfg.baseUrl, cfg.uploadToken, {
    ...envelope,
    expires_in: ttl,
  });

  // Post-upload verification: fetch the public ciphertext back and decrypt it
  // locally to prove the whole chain works before the user shares anything.
  let verified = false;
  try {
    const back = await fetchEnvelope(cfg.baseUrl, created.id);
    if (back.status === 200 && back.envelope) {
      const roundtrip = await decryptHandoff(back.envelope, secret);
      verified = roundtrip === plaintext;
    }
  } catch {
    verified = false;
  }
  if (!verified) {
    fail('上传后回读验证失败——请勿分享此链接，请重试或检查服务端。');
  }

  const expiresLocal = new Date(created.expires_at).toLocaleString('zh-CN', { hour12: false });
  const snippet = [
    '继续这个项目：',
    created.url,
    `密码：${secret}`,
    `（${Math.round(ttl / 60)} 分钟内有效）`,
  ].join('\n');

  console.log(`
Handoff ready ✅  （已回读解密验证）${report.blocked ? '\n\n⚠️⚠️  本次推送携带防火墙豁免，理由：' + allowReason + ' —— 请人工确认内容确实应当传输' : ''}

URL:      ${created.url}
API:      ${created.api_url}
Password: ${secret}
Expires:  ${created.expires_at}（本地 ${expiresLocal}）

复制给 ChatGPT：
----------------------------------------
${snippet}
----------------------------------------`);

  if (flags.has('--copy')) {
    if (copyToClipboard(snippet)) {
      console.log('📋 交接信息已复制到剪贴板。');
    } else {
      console.error('⚠️ 剪贴板工具不可用，请手动复制上面四行。');
    }
  }
}

interface BundlePushOptions {
  prompt: string;
  notes: string;
  flags: Map<string, string | boolean>;
}

function humanSize(bytes: number): string {
  return bytes >= 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
}

/**
 * Multi-file Context Bundle mode. Original files travel verbatim; the local
 * agent's job is retrieval (which files) + a short request, never
 * interpretation. Firewall-blocked files are dropped unconditionally — the
 * Bridge decides what must never travel, and bundle mode has no override.
 */
async function bundlePush(fileList: string[], opts: BundlePushOptions): Promise<void> {
  const { flags } = opts;
  if (fileList.length > BUNDLE_LIMITS.maxFiles) {
    fail(`文件数超过上限（${BUNDLE_LIMITS.maxFiles}）`);
  }
  if (flags.has('--allow-secrets')) {
    console.log('ℹ️ Bundle 模式下防火墙拒绝的文件会被直接剔除（无豁免通道），--allow-secrets 未被使用。');
  }

  const entries: BundleEntryInput[] = [];
  const dropped: string[] = [];
  let totalBytes = 0;

  for (const file of fileList) {
    const bytes = fs.readFileSync(file);
    if (bytes.length > BUNDLE_LIMITS.maxFileBytes) {
      console.log(`✗ ${file}：${humanSize(bytes.length)} 超过单文件上限 ${humanSize(BUNDLE_LIMITS.maxFileBytes)}，已剔除`);
      dropped.push(file);
      continue;
    }
    if (looksBinary(bytes)) {
      console.log(`✗ ${file}：二进制文件（Bundle V1 仅支持纯文本），已剔除`);
      dropped.push(file);
      continue;
    }
    if (!isTextPath(file)) {
      console.log(`✗ ${file}：非文本扩展名（Bundle V1 仅支持纯文本），已剔除`);
      dropped.push(file);
      continue;
    }
    const text = bytes.toString('utf8');
    const bPath = bundlePathFor(file);
    const report = runFirewall(file, text);
    if (report.blocked) {
      console.log(`✗ ${file}：被 Context Firewall 拒绝，已剔除`);
      for (const f of report.contentFindings.filter((x) => x.severity === 'block').slice(0, 5)) {
        console.log(`    第 ${f.line} 行：${f.rule}`);
      }
      if (report.pathFinding) console.log(`    ${report.pathFinding.rule}`);
      dropped.push(file);
      continue;
    }
    const warns = report.contentFindings.filter((x) => x.severity === 'warn');
    console.log(`✓ ${bPath}（${humanSize(bytes.length)}）${warns.length > 0 ? ` ⚠️ ${warns.length} 条告警` : ''}`);
    entries.push({ path: bPath, text });
    totalBytes += bytes.length;
  }

  if (entries.length === 0) fail('所有文件都被剔除，没有可推送的内容');
  if (totalBytes > LIMITS.maxBundleBytes) {
    fail(`Bundle 总大小 ${totalBytes} 字节超过上限 ${LIMITS.maxBundleBytes}`);
  }
  if (dropped.length > 0) {
    console.log(`🛡 已剔除 ${dropped.length} 个文件：${dropped.join('、')}`);
  }

  const cfg = loadBridgeConfig();
  if (!cfg.baseUrl || !cfg.uploadToken) {
    fail(
      `缺少 Bridge 配置。请先执行：\n` +
        `  bridge config --url https://<worker-domain> --token <UPLOAD_TOKEN>\n` +
        `或设置环境变量 BRIDGE_URL / BRIDGE_TOKEN。`,
    );
  }

  const ttl = flags.has('--ttl') ? parseInt(String(flags.get('--ttl')), 10) : LIMITS.defaultTtlSeconds;
  if (!Number.isInteger(ttl) || ttl < LIMITS.minTtlSeconds || ttl > LIMITS.maxTtlSeconds) {
    fail(`--ttl 必须是 ${LIMITS.minTtlSeconds}~${LIMITS.maxTtlSeconds} 之间的整数秒`);
  }
  const iterations = flags.has('--iterations')
    ? parseInt(String(flags.get('--iterations')), 10)
    : DEFAULT_ITERATIONS;
  if (!Number.isInteger(iterations)) fail('--iterations 必须是整数');

  // split transport: manifest + one encrypted object per file
  const handoffId = generateHandoffId();
  const secret = generateSecret();
  const manifestFiles: SplitManifestFile[] = [];
  const fileTexts: Array<{ objectId: string; text: string }> = [];
  const origin = cfg.baseUrl.replace(/\/+$/, '');
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i] as BundleEntryInput;
    manifestFiles.push({
      object_id: fileObjectId(i),
      path: e.path,
      media_type: mediaTypeFor(e.path),
      size: new TextEncoder().encode(e.text).length,
      sha256: await sha256Hex(e.text),
      ...fileHrefs(origin, handoffId, fileObjectId(i)),
    });
    fileTexts.push({ objectId: fileObjectId(i), text: e.text });
  }
  const manifest: SplitManifest = {
    protocol: 'agent-context-bundle',
    version: 1,
    request: { prompt: opts.prompt },
    generated_at: new Date().toISOString(),
    generator: `agent-bridge-cli/${VERSION}`,
    files: manifestFiles,
  };
  if (opts.notes) manifest.notes = opts.notes;

  const record = await buildSplitRecord({
    handoffId,
    secret,
    iterations,
    manifest,
    fileTexts,
    contentType: BUNDLE_CONTENT_TYPE,
  });

  process.stdout.write(`🔐 加密 Bundle（${manifestFiles.length} 个文件独立加密，共 ${humanSize(totalBytes)}）…\n`);
  const created = await pushEnvelope(cfg.baseUrl, cfg.uploadToken, {
    ...record,
    expires_in: ttl,
  } as unknown as Parameters<typeof pushEnvelope>[2]);

  let verified = false;
  try {
    const back = await fetchEnvelope(cfg.baseUrl, created.id);
    if (back.status === 200 && back.envelope) {
      const remote = back.envelope as unknown as {
        id: string;
        salt: string;
        iterations: number;
        objects: Array<{ object_id: string; iv: string; ciphertext: string }>;
      };
      const manifestObj = remote.objects.find((o) => o.object_id === 'manifest');
      if (!manifestObj) throw new Error('manifest object missing');
      const manifestText = await decryptSplitObject(remote, secret, remote.id, 'manifest', manifestObj.iv, manifestObj.ciphertext);
      const parsedManifest = JSON.parse(manifestText) as SplitManifest;
      verified =
        parsedManifest.files.length === manifestFiles.length &&
        manifestFiles.every((mf) => {
          const got = parsedManifest.files.find((f) => f.object_id === mf.object_id);
          return got && got.path === mf.path && got.sha256 === mf.sha256;
        });
      if (verified) {
        for (const mf of manifestFiles) {
          const obj = remote.objects.find((o) => o.object_id === mf.object_id);
          if (!obj) { verified = false; break; }
          const text = await decryptSplitObject(remote, secret, remote.id, mf.object_id, obj.iv, obj.ciphertext);
          if (await sha256Hex(text) !== mf.sha256) { verified = false; break; }
        }
      }
    }
  } catch {
    verified = false;
  }
  if (!verified) {
    fail('上传后回读验证失败——请勿分享此链接，请重试或检查服务端。');
  }

  const expiresLocal = new Date(created.expires_at).toLocaleString('zh-CN', { hour12: false });
  const snippet = [
    '继续这个项目：',
    created.url,
    `密码：${secret}`,
    `（${Math.round(ttl / 60)} 分钟内有效）`,
  ].join('\n');

  console.log(`
Context Bundle ready ✅（${manifestFiles.length} 个文件独立加密，共 ${humanSize(totalBytes)}，已回读逐文件校验）
Request: ${opts.prompt || '（未提供——建议附一句你想让对方解决什么）'}
URL:      ${created.url}
API:      ${created.api_url}
Password: ${secret}
Expires:  ${created.expires_at}（本地 ${expiresLocal}）

复制给 ChatGPT：
----------------------------------------
${snippet}
----------------------------------------`);

  if (flags.has('--copy')) {
    if (copyToClipboard(snippet)) {
      console.log('📋 交接信息已复制到剪贴板。');
    } else {
      console.error('⚠️ 剪贴板工具不可用，请手动复制上面四行。');
    }
  }
}

function configCmd(args: string[]): void {
  let url: string | undefined;
  let token: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--url') url = args[++i];
    else if (a === '--token') token = args[++i];
    else fail(`未知参数：${a}`);
  }
  if (!url || !token) fail('用法：bridge config --url <https://...> --token <UPLOAD_TOKEN>');
  if (!/^https:\/\//.test(url as string)) fail('URL 必须是 https://');
  const where = saveBridgeConfig({ baseUrl: url as string, uploadToken: token as string });
  console.log(`✅ 已保存到 ${where}（权限 0600）`);
}

function checkCmd(args: string[]): void {
  const { positional } = parseFlags(args);
  const files = resolveInputFiles(positional);
  let blocked = false;
  for (const file of files) {
    const plaintext = fs.readFileSync(file, 'utf8');
    const report = runFirewall(file, plaintext);
    printReport(report);
    if (report.blocked) blocked = true;
  }
  process.exit(blocked ? 2 : 0);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') usage();
  if (cmd === '--version' || cmd === '-v') {
    console.log(VERSION);
    return;
  }
  if (cmd === 'push') return push(rest);
  if (cmd === 'check') return checkCmd(rest);
  if (cmd === 'config') return configCmd(rest);
  fail(`未知命令：${cmd}（试试 bridge help）`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
