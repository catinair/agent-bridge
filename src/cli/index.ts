import fs from 'node:fs';
import path from 'node:path';
import { decryptHandoff, DEFAULT_ITERATIONS, encryptHandoff } from '../shared/handoff-crypto.js';
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
  bridge push  [file] [--ttl <秒>] [--iterations <次>] [--copy] [--allow-secrets "<理由>"]
      加密并上传交接文档，输出 URL + 临时密码（默认 TTL 300 秒）。
      不指定文件时依次查找 .ai/HANDOFF.md、HANDOFF.md。
      上传前强制经过 Context Firewall（路径策略 / 凭据扫描 / 熵异常）。
      命中 block 级发现时必须提供豁免理由，理由会显示在推送结果里。
      --iterations 覆盖 PBKDF2 迭代次数（默认 600000，范围 100000~2000000）。

  bridge check [file]
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
    } else if (a === '--ttl' || a === '--iterations' || a === '--allow-secrets') {
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

function resolveInputFile(positional: string[]): string {
  if (positional.length > 1) fail('一次只能推送一个文件');
  if (positional.length === 1) {
    const f = positional[0] as string;
    if (!fs.existsSync(f)) fail(`文件不存在：${f}`);
    return f;
  }
  for (const candidate of DEFAULT_HANDOFF_CANDIDATES) {
    if (fs.existsSync(candidate)) return candidate;
  }
  fail('未指定文件，且当前目录找不到 .ai/HANDOFF.md 或 HANDOFF.md');
}

async function push(args: string[]): Promise<void> {
  const { positional, flags } = parseFlags(args);
  const file = resolveInputFile(positional);
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
  const file = resolveInputFile(positional);
  const plaintext = fs.readFileSync(file, 'utf8');
  const report = runFirewall(file, plaintext);
  printReport(report);
  process.exit(report.blocked ? 2 : 0);
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
