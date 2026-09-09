# UI Walkthrough — agent-bridge web UI

配套截图：`01-landing.png` ~ `05-viewer-decrypted.png`（随本 Bundle 以图片形式单独提供）。

## 屏幕清单

### 01 — Landing（`/`）
- 主标语：**Give AI agents context, not access.**
- 特性标签：Client-side encrypted · Burn after reading · Self-hosted · Zero-knowledge
- 说明段：拖几个文件、写一句话、粘贴生成的链接+密码；服务器只存密文、5 分钟硬删除
- 按钮：`Create a secure handoff →`（去 /new）、`Status`（/health）
- 底部：接收方指引（拿到链接的人在 `/h/<id>` 输入密码，密码永远不到服务器）

### 02 — Create（`/new`，空表单）
- 拖拽区：支持拖入或多选，提示仅文本类型（.md .txt .json .yaml .ts .py …）
- 三个输入区：Prompt（想让 AI 做什么）、Notes（可选，材料关系说明）、上传令牌（记住勾选框 → localStorage）
- 按钮：创建安全交接 / 重置

### 03 — Create（已填状态）
- 每个文件一行状态：`✓ 路径（大小）`，被防火墙拒绝的显示 `✗ + 原因`，可疑高熵内容显示告警条数
- 读取文件期间创建按钮禁用（防竞态）

### 04 — Result（创建成功）
- 倒计时（服务器端 X:XX 后自动销毁）
- URL / 密码分开两栏，各自一键复制
- Bundle 摘要（文件数、总大小、Prompt）
- 四行交接文本 + `Copy for ChatGPT` 一键复制

### 05 — Viewer（`/h/:id` 解密后）
- 输入密码 → 本地 WebCrypto 解密（split Bundle：先解 manifest，展示 🎯 请求块）
- 文件列表逐个折叠展示，展开时按需解密，可单独复制
- 页面同时服务端渲染 Agent 入口链接（manifest / f1 / f2 …），人类与 Agent 共用同一 URL

## 交互原则
- 人类与 Agent 共用同一个 URL：页面既是人的解密器，也是 Agent 的 discovery 入口
- 令牌只保存在创建者本机（localStorage，可取消勾选不记住）；接收方永远不需要令牌
- 全部加密在客户端完成；页面无任何外部资源，CSP 锁死
