import { spawnSync } from 'node:child_process';
import type {
  CreateHandoffRequest,
  CreateHandoffResponse,
  HandoffEnvelope,
} from '../shared/types.js';
import { loadBridgeConfig } from './config.js';

function root(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

let proxyReadyFor: string | null = null;

/**
 * Route requests through a proxy where the direct route may be blocked
 * (e.g. *.workers.dev on some networks). Precedence: HTTPS_PROXY/ALL_PROXY
 * env > `proxy` field in the config file > macOS system proxy (scutil).
 * Local addresses never go through a proxy.
 */
async function configureProxy(baseUrl: string): Promise<void> {
  const host = new URL(baseUrl).hostname;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.local')) {
    return;
  }
  if (proxyReadyFor === baseUrl) return;
  proxyReadyFor = baseUrl;

  const envProxy =
    process.env.HTTPS_PROXY ??
    process.env.https_proxy ??
    process.env.ALL_PROXY ??
    process.env.all_proxy;
  const configProxy = loadBridgeConfig().proxy;
  const systemProxy = detectMacSystemProxy();
  const proxy = envProxy || configProxy || systemProxy;
  if (!proxy) return;

  try {
    const { ProxyAgent, setGlobalDispatcher } = await import('undici');
    setGlobalDispatcher(new ProxyAgent(proxy));
    process.stderr.write(`️🛰 走代理 ${proxy}（直连 ${host} 不可达或按配置）\n`);
  } catch {
    process.stderr.write('⚠️ 检测到代理配置但 undici 不可用，将尝试直连。\n');
  }
}

function detectMacSystemProxy(): string | null {
  if (process.platform !== 'darwin') return null;
  try {
    const out = spawnSync('scutil', ['--proxy'], { encoding: 'utf8' }).stdout ?? '';
    const enabled = /HTTPSEnable\s*:\s*1/.test(out);
    const host = /HTTPSProxy\s*:\s*(\S+)/.exec(out)?.[1];
    const port = /HTTPSPort\s*:\s*(\d+)/.exec(out)?.[1];
    if (enabled && host && port) return `http://${host}:${port}`;
  } catch {
    // best effort only
  }
  return null;
}

export async function pushEnvelope(
  baseUrl: string,
  uploadToken: string,
  body: CreateHandoffRequest,
): Promise<CreateHandoffResponse> {
  await configureProxy(baseUrl);
  const res = await fetch(root(baseUrl) + '/v1/handoffs', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + uploadToken,
    },
    body: JSON.stringify(body),
  });
  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      typeof data === 'object' && data !== null && 'message' in data
        ? String((data as { message: unknown }).message)
        : res.statusText;
    throw new Error(`上传失败：HTTP ${res.status} ${msg}`);
  }
  return data as CreateHandoffResponse;
}

export interface FetchResult {
  status: number;
  envelope?: HandoffEnvelope;
  message?: string;
}

export async function fetchEnvelope(baseUrl: string, id: string, uploadToken?: string): Promise<FetchResult> {
  await configureProxy(baseUrl);
  const headers: Record<string, string> = {};
  if (uploadToken) headers.Authorization = 'Bearer ' + uploadToken;
  const res = await fetch(root(baseUrl) + '/v1/handoffs/' + encodeURIComponent(id), { headers });
  const data: unknown = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      typeof data === 'object' && data !== null && 'message' in data
        ? String((data as { message: unknown }).message)
        : res.statusText;
    return { status: res.status, message: msg };
  }
  return { status: res.status, envelope: data as HandoffEnvelope };
}
