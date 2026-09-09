# Agent Handoff Bridge（中文文档）

[English](./README.md)

> 一个 **5 分钟自毁、客户端加密、服务器零明文、URL 与密钥分离** 的 Agent Context Drop。
> 用于把本地仓库的 AI 交接上下文（HANDOFF.md）安全地临时递给 ChatGPT 或其他推理 Agent。

推荐用 `npm link` 全局安装 CLI，任何目录直接运行 `bridge push ...`；全局配置在
`~/.config/agent-bridge/config.json`（URL + 上传令牌，0600）。

```
本地 Agent 写 HANDOFF.md
        │
        ▼
bridge push          ←── 本地生成 160-bit 密码，AES-256-GCM 加密
        │
        │  HTTPS（Bearer 上传令牌）
        ▼
Cloudflare Worker ──── Cloudflare KV（只存密文，TTL 300s 自动销毁）
        │
        │  URL + 密码（两段分离，由你手动粘给对方）
        ▼
ChatGPT / 浏览器      ←── 拉取密文，本地解密（WebCrypto）
```

## 安全模型

| 威胁场景 | 结果 |
| --- | --- |
| KV 数据库泄露 | 只有密文 + 高熵 ID，无法解密 |
| 只有 URL 泄露 | 只有密文 |
| 只有密码泄露 | 找不到对应文档 |
| URL + 密码同时泄露 | 仅 5 分钟窗口内可读 |
| 服务器管理员 | 全程看不到明文和密码 |
| URL 扫描枚举 | 130-bit 随机 ID + 读取限流 |

落实的关键需求：

- **Burn after reading 生命周期**：未领取时 5 分钟 fallback TTL；首次读取即 claim，
  进入 3 分钟读取窗口（READ_LEASE_SECONDS 可配，默认 180s；可重复读取），窗口结束整体销毁（410 Gone + tombstone）
- **客户端加密**：AES-256-GCM（认证加密），密钥 = PBKDF2-SHA256(secret, salt, 600k 迭代)
- **客户端加密**：AES-256-GCM（认证加密），密钥 = PBKDF2-SHA256(secret, salt, 600k 迭代)
- 密码 160 bit CSPRNG，Crockford Base32 展示为 `XXXX-XXXX-…`；**从不出现在 URL / 服务器 / 日志**
- ID 130 bit 随机，不可枚举
- 上传需长期 `BRIDGE_UPLOAD_TOKEN`（Bearer），与一次性密码分离；Worker 未配置该 secret 时上传**默认拒绝**
- 所有响应 `Cache-Control: no-store`、`X-Robots-Tag: noindex, nofollow`、`Referrer-Policy: no-referrer`
- 每分钟每 IP 读取限流（默认 60，KV 近似计数）+ 上传限流
- **Context Firewall**：上传前强制路径策略 / 凭据扫描 / 熵异常检测（见下）
- 说明："阅后即焚"指 Bridge 中的临时密文在领取后销毁；内容一旦交付给目标 AI，
  其后续处理与保留遵循对应 AI 服务自身的数据政策
- 明文上限 2 MB；服务器校验信封格式、迭代次数、TTL 范围
- 服务器不记录任何请求体；`[observability] enabled = false`

与 ChatGPT 原方案的唯一偏差：KDF 用 **PBKDF2-SHA256（600k 迭代）** 而非 Argon2id——Argon2id 在 Node 与浏览器 WebCrypto 中均无原生支持，而浏览器端零依赖解密是本设计（`/h/:id` 查看页）的硬需求。PBKDF2 600k 是 OWASP 当前推荐强度。

## V2：Context Firewall（上传前的内容防线）

加密做得再好，也不能安全地运输不该运输的东西。`bridge push` / `bridge check` 强制经过三层防线：

| 层 | 内容 | 级别 |
| --- | --- | --- |
| 路径策略 | 默认拒绝：`.env*`、`id_rsa*`、`*.pem`、`*.key`、`credentials*`、`secrets*`、`cookies*`、`auth*`、`.git/`、`.ssh/`、`node_modules/`、`.npmrc` 等 | 🚫 block |
| 凭据扫描 | AWS/GitHub/OpenAI/Anthropic/Slack/Google key、私钥块、JWT、Cookie 头、session token、数据库连接串、`password=` 赋值等 | 🚫 block |
| 异常启发 | 长高熵字符串（可能是漏网密钥）、超大文件（>512KB） | ⚠️ warn |

block 级发现会中止上传；**豁免必须携带人类确认过的理由**（`--allow-secrets "<为什么必须发>"`），
理由会原样显示在推送结果里——Agent 不得自行编造理由绕过。

`bridge check <file>` 只跑防火墙出报告、不上传，适合 Agent 在组装交接文档时自检。

## V2：协议自描述

信封现在自带机器可读的协议说明（第一次接入的 Agent 不再需要文档外的暗知识）：

```json
{
  "protocol": "agent-handoff",
  "v": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "encoding": "utf-8",
  "secret_encoding": "base32-crockford-grouped-4",
  "secret_normalization": "strip-hyphens-whitespace-uppercase",
  "...": "salt/iv/ciphertext/content_type/created_at/expires_at"
}
```

`secret_normalization` 是实测教训：推理 Agent 第一次解密失败，正是因为把展示用的
`XXXX-XXXX-…` 原样喂给了 KDF。旧信封（无这些字段）依然兼容，服务端会补上默认值。

发现机制标准化：`/h/:id` 页面用 `application/vnd.agent-handoff+json` 标注机器端点
（`<link rel="alternate">` + 正文 `<a>`）。任何 Agent 看到该媒体类型即按本协议读取。
**API 响应的 Content-Type 保持 `application/json`**（实测兼容，改动无收益）。

## 明确不做（V2 决议）

- **one-time read（读一次即毁）**：Agent/Web retrieval 会重试同一 URL，严格 one-shot 会把
  可靠性搞差；5 分钟 TTL 已足够
- 账号、项目管理、历史记录、永久存储、向量库、双向同步、WebSocket、OAuth、Argon2 WASM、dashboard

## 目录结构

```
agent-bridge/
├── src/
│   ├── shared/            # 线格式 + 加解密核心（CLI / Worker / 浏览器三方共用）
│   │   ├── codec.ts       #   base64 / Crockford Base32 / 常量时间比较
│   │   ├── types.ts       #   HandoffEnvelope + 服务端校验 + 上限
│   │   └── handoff-crypto.ts
│   ├── worker/            # Cloudflare Worker（无任何 npm 运行时依赖）
│   │   ├── index.ts       #   POST/GET/DELETE /v1/handoffs、/h/:id、限流、安全头
│   │   ├── auth.ts        #   Bearer 令牌校验（hash 后常量时间比较）
│   │   └── page.ts        #   /h/:id 浏览器解密查看页（内联 CSP）
│   ├── cli/               # bridge 命令行
│   │   ├── index.ts       #   push / config
│   │   ├── scan.ts        #   密钥扫描
│   │   ├── api.ts / config.ts / clipboard.ts
│   └── local-dev/         # 把同一份 Worker 代码跑在 node:http + 内存 KV（本地联调用）
├── scripts/
│   ├── setup-deploy.mjs   # 一键：建 KV → 部署 → 写 secret → 配置 CLI
│   └── dev-server.ts      # 本地开发服务器
├── test/                  # 54 个测试：单元 + Worker 行为 + 浏览器解密源码 + 本地端到端
└── wrangler.toml
```

## 部署（一次性）

```bash
npm run setup
```

就这一条命令。未登录 Cloudflare 时它会自动发起 `wrangler login`（浏览器弹出后点 Allow），
然后自动：建 KV namespace → 部署 Worker → 生成上传令牌写入 secret → 配置 CLI。
任何一步失败都可以直接重跑，已完成的步骤会自动跳过。

> 注意：命令后面不要带 `# 注释` 再粘贴——zsh 交互模式不把 `#` 当注释，会当成参数报错。

`npm run setup` 会把 Bridge URL 和上传令牌写进 `~/.config/agent-bridge/config.json`（0600），
令牌同时存为 Worker secret `BRIDGE_UPLOAD_TOKEN`。**令牌只在这两处，泄露任一即轮换。**

先验证链路（ChatGPT 方案里强调的 Day 0 流程）：

```bash
curl https://<worker>.workers.dev/health
echo "# smoke test" > /tmp/HANDOFF.md
npm run bridge -- push /tmp/HANDOFF.md
```

按输出提示把「URL + 密码」粘给 ChatGPT，让它实际取回并解密一次；确认当前 Chat 环境
能完成这条链路后，再考虑绑定自定义域名。

### 网络注意事项（重要）

`*.workers.dev` 在部分地区网络会被阻断（DNS 正常、TCP 直连超时）。已实测：

- **ChatGPT / 海外出口访问 Bridge：不受影响**（阻断只发生在本地网络出口）
- **本机 `bridge push`：CLI 会自动按以下优先级走代理**——
  1. 环境变量 `HTTPS_PROXY` / `ALL_PROXY`
  2. 配置文件里的 `proxy` 字段
  3. macOS 系统代理（`scutil --proxy`，Clash/Surge 等开启系统代理即自动生效）

  本地地址（localhost/127.0.0.1）永远不走代理，本地开发不受影响。
- 长期方案：在 Cloudflare 绑定自定义域名（自定义域名不在被阻断名单内），改一下
  `~/.config/agent-bridge/config.json` 的 `baseUrl` 即可，其余无感。

## 日常使用

```bash
bridge push                    # 推送 .ai/HANDOFF.md 或 HANDOFF.md（任意目录可用）
bridge push path/to/file.md    # 推送指定文件
bridge push --ttl 120 --copy   # 自定义 TTL + 把交接四行写进剪贴板
bridge push --iterations 300000  # 覆盖 PBKDF2 迭代次数（默认 600000）
bridge push AGENTS.md README.md docs/architecture.md \
  --prompt "review 当前架构"      # 多文件 → Context Bundle 模式
bridge check path/to/file.md   # 只跑 Context Firewall 出报告，不上传
bridge config --url https://... --token ...   # 重新配置（或用 BRIDGE_URL/BRIDGE_TOKEN 环境变量）
```

`push` 的完整动作：读文件 → 防火墙 → 生成 160-bit 密码 → 加密 → 上传 →
**立即公网回读并本地解密验证** → 打印四行交接文本。

### Context Bundle（多文件模式）

传多个文件或带 `--prompt` 即进入 Bundle 模式：**原始文件原样传输**，本地 Agent 只做
"选文件 + 写一句请求"，不做有损总结；解密后是结构化 JSON（`files[].path/media_type/
size/sha256/content`），远端 Agent 直接阅读原文。二进制或被防火墙拒绝的文件会被
**无条件剔除（Bundle 模式无豁免）**；单文件且无 `--prompt` 时保持原 HANDOFF 模式。

给本地 Agent 的固定工作流（可写进 AGENTS.md）：

```text
1. 分析 repo，生成 .ai/HANDOFF.md（目标 / 现状 / 待办 / 关键文件 / 约束）
2. 运行 bridge push --copy
3. 把剪贴板四行交给用户粘给 ChatGPT
```

## 对端（ChatGPT / 任意 Agent）取回协议

两段信息分离交付：`URL`（人看的页面）与 `密码`。机器取回用 API 端点：

```http
GET /v1/handoffs/{id}
```

Bundle 使用 **split transport**：manifest 与每个文件作为独立对象加密
（同一 handoff secret、每对象随机 IV、AAD 绑定 `agent-handoff/v2/<id>/<objectId>`
防止中转方调换/拼接对象）。Agent 先读 manifest（request + 文件清单 + 每文件
object_id），再按需取用并独立解密：

```text
GET /v1/handoffs/<id>                     # 完整记录（全部对象）
GET /v1/handoffs/<id>/manifest.txt        # manifest 信封（text/plain）
GET /v1/handoffs/<id>/files/<obj>.txt     # 文件对象信封（text/plain）
```

id 由客户端生成（仍然 130-bit 不可枚举），以便在上传前绑定 AAD。
manifest 的每个文件条目带有可发现的绝对链接（`href` 指向 text 信封、`json_href`
指向 JSON 对象端点），manifest.txt 响应末尾还会附加服务器渲染的全量对象链接清单。
单文件 HANDOFF 保持原始单信封格式。若抓取层吞掉 JSON body，可用纯文本
fallback：`GET /v1/handoffs/{id}.txt`（`text/plain`，同样的字段以 key: value
平铺），链接同样标注在 /h/:id 页面上：

```json
{
  "v": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt": "…", "iv": "…", "ciphertext": "…",
  "content_type": "text/markdown",
  "created_at": "…", "expires_at": "…"
}
```

解密（任何支持 WebCrypto 的环境，约 10 行）：

```js
const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret.replace(/-/g, '').toUpperCase()), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: b64d(env.salt), iterations: env.iterations, hash: 'SHA-256' },
  km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
const plain = new TextDecoder().decode(
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(env.iv) }, key, b64d(env.ciphertext)));
```

密码输错时 GCM 认证失败，不会得到任何明文。人类浏览器直接打开 URL，在页面输入密码即可（页面内联 JS 本地解密，无任何外部资源）。

## Web UI

同一个 Worker 直接提供轻量界面，无需第二个应用：

| 路由 | 用途 |
| --- | --- |
| `/` | 落地页：这是什么 + 入口 |
| `/new` | 浏览器创建交接：拖入文件、写 prompt、逐文件防火墙状态、本地 WebCrypto 加密、上传密文 |
| `/h/:id` | 人类查看页：输入密码本地解密（支持 Bundle 结构化渲染） |
| `/v1/…` | Agent API |

CLI 做的所有事（防火墙、Bundle 组装、PBKDF2 + AES-GCM）都在浏览器里完成。
页面需要上传令牌（可选记住在本机 localStorage）——自托管中转要求发送方认证，没有账号体系；
接收方永远不需要令牌。

## 本地开发与测试

```bash
npm run dev        # 同一份 Worker 代码跑在 127.0.0.1:<随机端口>（内存 KV）
npm test           # 54 个测试：加解密/防火墙/Worker 行为/浏览器解密源码/CLI→服务器端到端
npm run typecheck
```

## V1 明确不做（防止范围膨胀）

账号体系、协作、永久存储、项目管理、聊天记录、向量库、双向同步、复杂权限、
ChatGPT→本地方向（几 KB 的 Execution Brief 复制粘贴成本更低）。
