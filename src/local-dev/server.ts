/**
 * Runs the exact Worker code on node:http with an in-memory KV, so the whole
 * CLI -> upload -> fetch -> decrypt chain is testable/deployable offline.
 * Production runs the same fetch() handler on Cloudflare Workers.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import worker from '../worker/index.js';
import type { Env } from '../worker/env.js';
import { InMemoryKV } from './kv.js';

export interface DevServer {
  port: number;
  token: string;
  kv: InMemoryKV;
  close(): Promise<void>;
}

export async function startDevServer(opts: { token?: string } = {}): Promise<DevServer> {
  const token = opts.token ?? crypto.randomUUID().replace(/-/g, '');
  const kv = new InMemoryKV();
  const env: Env = { HANDOFFS: kv, BRIDGE_UPLOAD_TOKEN: token };

  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'internal', message: String(err) }));
    });
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const body = Buffer.concat(chunks);
    const port = (server.address() as AddressInfo).port;
    const webRequest = new Request(`http://127.0.0.1:${port}${req.url ?? '/'}`, {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
    });
    const webResponse = await worker.fetch(webRequest, env);
    const headers: Record<string, string> = {};
    webResponse.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const payload = Buffer.from(await webResponse.arrayBuffer());
    res.writeHead(webResponse.status, headers);
    res.end(req.method === 'HEAD' ? undefined : payload);
  }

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;

  return {
    port,
    token,
    kv,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
