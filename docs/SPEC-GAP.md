# Spec Gap Analysis — V3 / Open-source V1 Release Spec

对照 ChatGPT 合并版规格（V3 / Open-source V1 Release Spec）的逐项盘点。
状态：✅ 已实现 · 🔧 本轮补齐 · 📝 记录为偏差（有意不照抄） · ⏳ P1/P2 后续。

| Spec 条目 | 状态 | 说明 |
| --- | --- | --- |
| 1 定位 / 2 核心原则 | 🔧 | 定位改为 "Give AI context, not access." + burn-after-reading 主承诺 |
| 3 安全边界（burn 只作用于 bridge） | 🔧 | README/viewer/创建页均已加 quiet 说明 |
| 4 Context Bundle（Request + 原始文件 + Notes） | ✅ | split manifest 承载 |
| 5 Retrieval not Summarization | ✅ | 传输原文；本地 Agent 只做检索与轻量 notes |
| 6 逻辑 schema（manifest 只放元数据） | ✅ | files[] 为元数据；正文在独立对象 |
| 7 仅文本类型 | ✅ | 防火墙剔除二进制/非文本扩展名 |
| 8–9 Split transport | ✅ | manifest + 逐文件独立加密对象 |
| 10 AES-256-GCM + PBKDF2 600k（不引入 Argon2） | ✅ | 与规格一致 |
| 11 Secret 160-bit / 分组展示 / 归一化字段 | ✅ | `secret_normalization` 比规格示例更精确（含空白与大写归一），等效 |
| 12 AAD domain separation | 🔧 | `/manifest` 与 `/file/<objectId>` 分域 |
| 13 HTML discovery links（human URL 起） | ✅ | JSON/text 信封 + 每对象 `<a>` 服务端渲染 |
| 14 JSON + text fallback | ✅ | 记录级、manifest、逐对象均有 |
| 15 ciphertext 分块（500–800 字符） | ✅ | 600 字符有序 chunks |
| 16–17 Context Firewall（fail closed） | ✅ | 路径默认拒绝 + 凭据扫描 + 熵/体积启发 |
| 18 `--allow-secrets` 显式豁免（不得自动触发） | ✅ | 必须携带人类理由并回显；Bundle 模式无豁免（直接剔除） |
| 19 上传令牌与 handoff secret 分离 | ✅ | 一直如此 |
| 20 令牌记住默认 OFF + Bridge settings 折叠 + 帮助文案 | 🔧 | 本轮修复 |
| 21–25 Claim / read lease / bundle-level burn / UI 状态 | 🔧 | 本轮实现：首次匿名读取 claim（60s lease，可配）→ 到期 burn；410 + tombstone；`/status` 端点；结果页/查看页显示生命周期 |
| 26–27 Cloudflare 架构保持；免费额度发布前核对 | 🔧 | 架构保持；README 未写死额度数字，发布前按官方文档核对（待办） |
| 28–30 CLI 多文件 + 状态输出 | 🔧 | 多文件已实现；输出补 Status 行；`bridge handoff` 以 Agent 工作流（skill）形式落地而非 CLI 子命令（📝 偏差：检索是 Agent 职责） |
| 31–35 落地页（徽章/三步/footer 降级） | 🔧 | 本轮修复 |
| 36–40 /new 信息架构（令牌收进 Bridge settings、移除文件、总计） | 🔧 | 本轮修复 |
| 41 结果页 "undefined B" bug | 🔧 | human() 防御式格式化，已修 |
| 42 结果页生命周期状态 | 🔧 | 轮询 /status 显示 Unclaimed/Claimed/Burned |
| 43 Copy for ChatGPT 一键 | ✅ | 已有 |
| 44–45 查看页懒解密 | ✅ | 已有 |
| 46 查看页 footer 说明 | 🔧 | quiet 文案已加 |
| 47 UI 语言统一英文 | 🔧 | /new 与 /h 已英文化；README 英主 + 中文版 |
| 48–50 开源叙事与 self-hosted 边界 | 🔧 | README 定位更新；无公共托管计划已写明 |
| 51 不做清单 | ✅ | 全部未做（保持不做） |
| 52 P0 清单 | 🔧 | 除"免费额度核对"外全部完成 |
| 53 P1 打磨 | ⏳ | 部分已顺带完成（移除文件、总计、防火墙反馈、footer）；其余 P1 后续 |
| 54 不要为这些延迟发布 | ✅ | 认同 |
| 55 发布定义 | ⏳ | 待真实 repo 全流程演练 |

## 已知偏差（有意为之）

1. **KDF**：PBKDF2-SHA256（600k）而非 Argon2id——浏览器/Node 零依赖兼容所需，规格允许。
2. **notes 结构**：V1 为自由文本字符串，未做 `file_relationships[]` 结构化（规格为建议结构；协议版本化后可演进）。
3. **`secret_normalization` 取值**：`strip-hyphens-whitespace-uppercase`（比规格示例更精确）。
4. **`bridge handoff` 子命令**：以 Agent 工作流（skill 文档）形式存在，CLI 不内置自动检索。
5. **read lease**：默认 **180 秒（3 分钟）**，经 `READ_LEASE_SECONDS` 可配（30–3600），
   不做滑动延长——保证确定的 burn 期限。60s 版本经真实 ChatGPT 多文件消费实测过短。

## P1 遗留（不阻塞开源）

- 文件类型预览、错误态打磨、移动端/键盘可访问性、ARIA 细化
- macOS Keychain 存上传令牌
- 自定义域名绑定指引
