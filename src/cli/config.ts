import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface BridgeConfig {
  baseUrl?: string;
  uploadToken?: string;
  /** optional proxy URL, e.g. http://127.0.0.1:7897 */
  proxy?: string;
}

const CONFIG_DIR = path.join(os.homedir(), '.config', 'agent-bridge');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

/**
 * Precedence: environment variables override the config file, so agents can
 * run against a different bridge without touching user config.
 */
export function loadBridgeConfig(): BridgeConfig {
  let file: BridgeConfig = {};
  try {
    file = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) as BridgeConfig;
  } catch {
    // no config file yet
  }
  return {
    baseUrl: process.env.BRIDGE_URL ?? file.baseUrl,
    uploadToken: process.env.BRIDGE_TOKEN ?? file.uploadToken,
    proxy: process.env.BRIDGE_PROXY ?? file.proxy,
  };
}

export function saveBridgeConfig(cfg: { baseUrl: string; uploadToken: string }): string {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  return CONFIG_PATH;
}

export function configPath(): string {
  return CONFIG_PATH;
}
