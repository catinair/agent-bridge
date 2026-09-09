import { startDevServer } from '../src/local-dev/server.js';

const server = await startDevServer(
  process.env.BRIDGE_UPLOAD_TOKEN ? { token: process.env.BRIDGE_UPLOAD_TOKEN } : {},
);

console.log(`Local Agent Bridge dev server (in-memory KV, 与生产同一份 Worker 代码)

  URL:   http://127.0.0.1:${server.port}
  Token: ${server.token}

CLI 使用：
  BRIDGE_URL=http://127.0.0.1:${server.port} BRIDGE_TOKEN=${server.token} \\
    npm run bridge -- push <file> --copy
`);
