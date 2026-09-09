#!/usr/bin/env node
/**
 * One-shot setup + deploy for the Agent Handoff Bridge:
 *   1. checks `wrangler` authentication (auto-runs `wrangler login` if needed)
 *   2. creates the KV namespace and writes its id into wrangler.toml
 *   3. deploys the Worker (workers.dev)
 *   4. generates the upload token, stores it as a Worker secret
 *   5. writes the CLI config so `bridge push` works immediately
 *
 * Every step is idempotent — re-running after a failure skips what's done.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const TOML = path.join(ROOT, 'wrangler.toml');
const PLACEHOLDER = 'KV_NAMESPACE_ID_PLACEHOLDER';

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: ROOT, encoding: 'utf8', ...opts });
}

/** Runs a setup step; on failure prints the command output cleanly (no stack trace) and exits. */
function runStep(msg, cmd, args, opts = {}) {
  step(msg);
  try {
    return run(cmd, args, opts);
  } catch (err) {
    const out = String(err.stdout ?? '');
    const errOut = String(err.stderr ?? '');
    if (out.trim()) console.error(out.trim());
    if (errOut.trim()) console.error(errOut.trim());
    console.error(`\n✘ 步骤失败：${cmd} ${args.join(' ')}`);
    console.error('排查后重新运行 `npm run setup` 即可，已完成的步骤会自动跳过。');
    process.exit(1);
  }
}

function isLoggedIn() {
  let out = '';
  try {
    out = run('npx', ['wrangler', 'whoami'], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    out = String(err.stdout ?? '') + String(err.stderr ?? '');
  }
  // wrangler whoami 未认证时退出码也是 0，必须检查输出内容
  return !/not authenticated/i.test(out);
}

function readAccountId() {
  try {
    const out = run('npx', ['wrangler', 'whoami'], { stdio: ['ignore', 'pipe', 'pipe'] });
    return /\b([0-9a-f]{32})\b/.exec(out)?.[1] ?? null;
  } catch {
    return null;
  }
}

function readOAuthToken() {
  const candidates = [
    path.join(os.homedir(), 'Library', 'Preferences', '.wrangler', 'config', 'default.toml'),
    path.join(os.homedir(), '.wrangler', 'config', 'default.toml'),
    path.join(os.homedir(), '.config', '.wrangler', 'config', 'default.toml'),
  ];
  for (const p of candidates) {
    try {
      const m = /oauth_token\s*=\s*"([^"]+)"/.exec(readFileSync(p, 'utf8'));
      if (m) return m[1];
    } catch {
      // try next location
    }
  }
  return null;
}

async function fetchWorkersSubdomain(accountId, token) {
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    const json = await res.json();
    if (json?.success && json?.result?.subdomain) return json.result.subdomain;
  } catch {
    // fall through
  }
  return null;
}

async function askWorkerUrlFallback() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(
    '\n请把上面部署输出里的 workers.dev URL 粘贴进来（形如 https://agent-bridge.xxx.workers.dev）：',
  );
  rl.close();
  const url = /https:\/\/[^\s]+\.workers\.dev/.exec(answer)?.[0];
  if (!url) {
    console.error('URL 格式不正确。重新运行 `npm run setup` 再试一次。');
    process.exit(1);
  }
  return url;
}

function step(msg) {
  console.log(`\n==> ${msg}`);
}

step('检查 Cloudflare 登录状态');
if (!isLoggedIn()) {
  console.log(
    '尚未登录 Cloudflare —— 正在发起浏览器授权（wrangler login）…\n' +
      '请在弹出的浏览器页面中点击 Allow；若浏览器没有自动打开，手动打开终端里显示的链接。\n',
  );
  try {
    execFileSync('npx', ['wrangler', 'login'], { cwd: ROOT, stdio: 'inherit' });
  } catch {
    console.error(
      '\n登录未完成。请单独运行 `npx wrangler login` 完成授权（命令后面不要带 # 注释，zsh 会当成参数），\n然后再运行 `npm run setup`。',
    );
    process.exit(1);
  }
  if (!isLoggedIn()) {
    console.error('\n登录仍未生效，请重新运行 `npx wrangler login`。');
    process.exit(1);
  }
}
console.log(
  run('npx', ['wrangler', 'whoami'], { stdio: ['ignore', 'pipe', 'inherit'] })
    .trim()
    .split('\n')
    .slice(-6)
    .join('\n'),
);

step('创建 KV namespace（如尚未创建）');
// fresh clone: wrangler.toml is gitignored — create it from the committed example
if (!existsSync(TOML)) {
  writeFileSync(TOML, readFileSync(path.join(ROOT, 'wrangler.toml.example'), 'utf8'));
}
let toml = readFileSync(TOML, 'utf8');
if (toml.includes(PLACEHOLDER)) {
  const out = runStep('创建 namespace HANDOFFS', 'npx', ['wrangler', 'kv', 'namespace', 'create', 'HANDOFFS']);
  const id = /id\s*=\s*"([0-9a-f]+)"/.exec(out)?.[1];
  if (!id) {
    console.error(out);
    console.error('\n无法从 wrangler 输出中解析 namespace id，请手动把 id 填入 wrangler.toml 后重新运行 npm run setup。');
    process.exit(1);
  }
  toml = toml.replace(PLACEHOLDER, id);
  writeFileSync(TOML, toml);
  console.log(`KV namespace 已创建并写入 wrangler.toml: ${id}`);
} else {
  console.log('wrangler.toml 已配置 namespace，跳过。');
}

step('部署 Worker');
let deployedUrl = null;
let deployErrorText = '';
try {
  const deployOut = run('npx', ['wrangler', 'deploy'], { stdio: ['ignore', 'pipe', 'inherit'] });
  deployedUrl = /https:\/\/[^\s]+\.workers\.dev/.exec(deployOut)?.[0] ?? null;
  console.log(deployOut.trim().split('\n').slice(-8).join('\n'));
} catch (err) {
  deployErrorText = String(err.stdout ?? '') + String(err.stderr ?? '');
  const trimmed = deployErrorText.trim();
  if (trimmed) console.error(trimmed);
}

if (!deployedUrl && /register a workers\.dev subdomain/i.test(deployErrorText)) {
  console.log(
    '\n你的 Cloudflare 账号还没有注册 workers.dev 子域名（新账号的一次性设置）。\n' +
      '接下来 wrangler 会在终端里问你两个问题：\n' +
      '  1) Would you like to register a workers.dev subdomain now?  → 输入 y 回车\n' +
      '  2) 子域名名称 → 只能小写字母/数字/连字符，例如 mao-workers\n' +
      '回答后会自动继续完成部署。\n',
  );
  const status = spawnSync('npx', ['wrangler', 'deploy'], { cwd: ROOT, stdio: 'inherit' }).status;
  if (status !== 0) {
    console.error('\n部署没有成功。处理后重新运行 `npm run setup`（已完成步骤会自动跳过）。');
    process.exit(1);
  }
}

if (!deployedUrl) {
  // 交互式部署的输出无法捕获，改从 Cloudflare API 查询子域名来构造 URL
  const accountId = readAccountId();
  const oauthToken = readOAuthToken();
  const subdomain = accountId && oauthToken ? await fetchWorkersSubdomain(accountId, oauthToken) : null;
  if (subdomain) {
    deployedUrl = `https://agent-bridge.${subdomain}.workers.dev`;
    console.log(`\n部署完成：${deployedUrl}`);
  } else {
    deployedUrl = await askWorkerUrlFallback();
  }
}

const token = randomBytes(32).toString('base64url');
runStep(
  '生成并写入上传令牌（BRIDGE_UPLOAD_TOKEN）',
  'bash',
  ['-c', 'printf %s "$TOKEN" | npx wrangler secret put BRIDGE_UPLOAD_TOKEN'],
  {
    env: { ...process.env, TOKEN: token },
    stdio: ['ignore', 'pipe', 'inherit'],
  },
);
console.log('Worker secret 已写入。');

step('写入本地 CLI 配置');
const configPath = path.join(os.homedir(), '.config', 'agent-bridge', 'config.json');
mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
writeFileSync(configPath, JSON.stringify({ baseUrl: deployedUrl, uploadToken: token }, null, 2) + '\n');
chmodSync(configPath, 0o600);
console.log(`${configPath} (0600)`);

console.log(`
✅ 部署完成

Bridge URL:   ${deployedUrl}
上传令牌:     已保存到 ${configPath}（Worker 侧存于 secret，请勿外传）
健康检查:     curl ${deployedUrl}/health

试一下（在本仓库放一个 .ai/HANDOFF.md 或指定文件）：
  npm run build
  node bin/bridge.js push <文件> --copy

把输出的 URL + 密码四行复制给 ChatGPT 即可（5 分钟内有效）。
`);
