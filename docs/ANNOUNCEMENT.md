# Launch announcements

## English (X / Reddit / Hacker News style)

**agent-bridge — Give AI context, not access.**

I kept pasting half my repo into ChatGPT: architecture docs, configs, PRDs —
along with paths, secrets-adjacent context, and everything the model didn't
need. So I built a small self-hosted tool to do it properly.

`bridge push AGENTS.md docs/architecture.md config/models.yaml --prompt "review the routing design"`

- files are screened (Context Firewall) and encrypted **in your browser/CLI**
- your own Cloudflare Worker stores ciphertext only
- the recipient follows links from a single URL: manifest → original files
- after a 180-second read window the whole bundle **burns** (410 Gone)

Split transport: the manifest and every file are independently encrypted
objects with AAD binding — agents read what they need, not one giant blob.
Validated end-to-end with real ChatGPT retrieval.

MIT, self-hosted on the free Cloudflare plan. Repo:
https://github.com/catinair/agent-bridge

## 中文（即刻 / V2EX / 小红书风格）

做了一个小工具：**Agent Handoff Bridge**。

痛点：想让 ChatGPT 帮忙评审方案，就得把架构文档、配置、PRD 一坨坨贴进对话——
贴多了乱，贴敏感了慌。

它做的事很简单：

1. 选几个文件（CLI 或网页拖拽）
2. 浏览器/CLI 本地加密（服务器只见密文）
3. 生成一个链接 + 一次性密码，粘给 ChatGPT
4. 对方按需读取原始文件，**5 分钟未领取自动过期，领取后 3 分钟读取窗口，到期整体销毁**

不是网盘、不是知识库、不做账号体系——就是个阅后即焚的上下文中转，
部署在你自己的 Cloudflare Workers 上（免费套餐就够）。

已用真实 ChatGPT 完成多轮黑盒消费验证。MIT 开源：
https://github.com/catinair/agent-bridge
