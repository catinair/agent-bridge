# agent-bridge

> Self-destructing, end-to-end-encrypted context handoffs between your local
> coding agents and reasoning agents (ChatGPT, Claude, Gemini, …).
>
> [中文文档](./README.zh-CN.md)

`agent-bridge` is a self-hosted relay for AI-agent handoffs. Your local agent
packs project context into a markdown file, the CLI encrypts it client-side,
and the ciphertext sits on **your own** Cloudflare Worker for **5 minutes**.
You paste a link plus a one-time password into the chat, and the reasoning
agent fetches and decrypts the document by itself — no plugins, no logins, no
copy-pasting half your repository.

```
local agent writes HANDOFF.md
        │
        ▼
bridge push           ←── 160-bit secret generated locally, AES-256-GCM
        │
        │  HTTPS (Bearer upload token)
        ▼
Cloudflare Worker ──── Cloudflare KV (ciphertext only, TTL 300s hard delete)
        │
        │  URL + password (two separate halves, delivered by you)
        ▼
ChatGPT / browser     ←── fetches ciphertext, decrypts locally (WebCrypto)
```

The core loop is validated end-to-end against real ChatGPT web retrieval: the
agent opens the human URL, discovers the machine endpoint from a
server-rendered `<a>` link, fetches the JSON envelope, and decrypts it with
the password from your message — zero extra copying on your side.

## Why not just paste the file?

You can, until the context is bigger than a chat message, contains things you
don't want in a third-party transcript, or needs to happen ten times a day.
`agent-bridge` turns the handoff into a one-liner for the agent and a ⌘V for
you:

- **Zero-knowledge server** — the Worker only ever sees ciphertext; the
  password never leaves your machine and the recipient's head
- **5-minute TTL** — KV hard-deletes the payload; expired links return 404
- **URL/secret separation** — neither half is useful alone
- **Context Firewall** — uploads are screened for credentials *before* they
  are encrypted (a strong cipher safely shipping a leaked key is still a leak)
- **Self-describing protocol** — the envelope tells any agent how to normalize
  the password and which KDF/algorithm to use; no out-of-band folklore

## Security model

| Threat | Defense |
| --- | --- |
| Guessing handoff IDs | 130-bit random IDs, non-enumerable |
| URL leaks alone | Payload stays ciphertext |
| KV / Cloudflare data breach | Ciphertext only |
| Brute-forcing the secret | 160-bit CSPRNG + PBKDF2-SHA256 (600k iterations) |
| Replaying URL + secret | 5-minute TTL bounds the window |
| Tampered ciphertext | AES-GCM authentication |
| Strangers using your bridge as a file drop | Long-term Bearer upload token |
| Agent accidentally shipping `.env` / keys | Context Firewall (default-deny paths + credential scan) |
| Password leaking to server or logs | It never leaves the two endpoints |

Other guarantees: `Cache-Control: no-store`, `X-Robots-Tag: noindex,
nofollow`, `Referrer-Policy: no-referrer` on every response; per-IP read rate
limiting; 2 MB payload cap; the server logs nothing about request bodies.

Design decisions worth knowing:

- **PBKDF2-SHA256 (600k) instead of Argon2id** — Argon2id has no native
  support in Node or browser WebCrypto, and the zero-dependency browser
  viewer needs the same KDF the CLI uses. 600k PBKDF2 meets the current
  OWASP recommendation for this construction.
- **No burn-after-read** — web-retrieval agents legitimately retry the same
  URL; one-shot semantics would trade reliability for a marginal gain the
  5-minute TTL already provides.
- **No accounts, no history, no dashboard** — it is a relay, not a platform.

## Quickstart (your own Cloudflare account; the free plan is enough)

```bash
git clone <this repo> && cd agent-bridge
npm install
npm run setup        # wrangler login → KV namespace → deploy → token → CLI config
npm link             # make `bridge` available in every shell
```

`npm run setup` is idempotent: it logs you in if needed (browser OAuth),
creates the KV namespace, deploys the Worker to
`https://<worker>.<your-subdomain>.workers.dev`, generates the upload token,
stores it as a Worker secret, and writes the CLI config. Note: don't append
`# comments` when pasting commands — interactive zsh treats `#` as an
argument, not a comment.

Smoke-test the chain:

```bash
curl https://<your-worker>.workers.dev/health     # → {"ok":true}
echo "# smoke test" > /tmp/HANDOFF.md
bridge push /tmp/HANDOFF.md --copy
```

Paste the four clipboard lines into any reasoning agent within 5 minutes and
watch it fetch and decrypt the document. That's the whole product.

## CLI usage

```bash
bridge push                       # push .ai/HANDOFF.md or HANDOFF.md
bridge push path/to/file.md       # explicit file
bridge push --ttl 120 --copy      # custom TTL + clipboard-ready handoff text
bridge push --iterations 300000   # override PBKDF2 iterations (default 600k)
bridge check path/to/file.md      # run the Context Firewall only, no upload
bridge config --url https://… --token …   # reconfigure
```

### Context Bundles (multi-file)

Pass several files — or add `--prompt` — and push switches to **bundle
mode**: original files travel verbatim (no lossy summarization by the local
agent), with a short request explaining what the receiving agent should
figure out:

```bash
bridge push AGENTS.md README.md docs/architecture.md \
  --prompt "Review the current architecture" \
  --notes "architecture.md is the core doc; models.yaml is the live config"
```

The decrypted payload is structured JSON (`files[].path/media_type/size/
sha256/content`) — the receiver reads it directly, no ZIP, no filesystem.
Text files only in V1; anything binary or firewall-blocked is **dropped
unconditionally** (bundle mode has no override — the Bridge decides what must
never travel). Single-file pushes without `--prompt` keep the original
HANDOFF-document behavior.

`push` reads the file → runs the Context Firewall → generates a 160-bit
secret → encrypts → uploads → **fetches the public ciphertext back and
decrypts it locally** to prove the chain works → prints the four-line handoff
text (and copies it with `--copy`).

## For receiving agents (the protocol)

Input: a human URL (`/h/<id>`) plus a password. The page server-renders a
discovery link to the machine endpoint, annotated with the protocol media
type:

```html
<link rel="alternate" type="application/vnd.agent-handoff+json"
      href="https://…/v1/handoffs/<id>">
<a rel="alternate" type="application/vnd.agent-handoff+json"
   href="https://…/v1/handoffs/<id>">Agent-readable encrypted JSON</a>
```

`GET /v1/handoffs/<id>` returns the envelope as JSON. If a retrieval layer
swallows raw JSON bodies, the same envelope is also available as flat
`key: value` text at `GET /v1/handoffs/<id>.txt` (`text/plain`) — linked from
the `/h/<id>` page as `text envelope`. For bundles
(`content_type: application/vnd.agent-context-bundle+json`) the decrypted
plaintext is itself JSON: `{ protocol: "agent-context-bundle", version: 1,
request: { prompt }, files: [{ path, media_type, size, sha256, content }] }` —
read the originals directly from `files[].content`.

```json
{
  "protocol": "agent-handoff",
  "v": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "salt": "…", "iv": "…", "ciphertext": "…",
  "content_type": "text/markdown",
  "encoding": "utf-8",
  "secret_encoding": "base32-crockford-grouped-4",
  "secret_normalization": "strip-hyphens-whitespace-uppercase",
  "created_at": "…", "expires_at": "…"
}
```

Decryption (any WebCrypto environment): normalize the secret per
`secret_normalization` (strip hyphens/whitespace, uppercase), derive the key
with PBKDF2-SHA256 (`salt`, `iterations`), then decrypt `ciphertext` with
AES-256-GCM (`iv`). A wrong password fails GCM authentication — there is no
oracle. The API responds with `Content-Type: application/json`; 404 covers
both "unknown" and "expired".

Humans get the same page: type the password, the inline JavaScript (no
external resources, CSP-locked) decrypts locally.

## Context Firewall

Encryption cannot help if the plaintext should never travel. `push` and
`check` enforce:

| Layer | Content | Severity |
| --- | --- | --- |
| Path policy | default-deny: `.env*`, `id_rsa*`, `*.pem`, `*.key`, `credentials*`, `secrets*`, `cookies*`, `auth*`, `.git/`, `.ssh/`, `node_modules/`, `.npmrc`, … | block |
| Credential scan | AWS/GitHub/OpenAI/Anthropic/Slack/Google keys, private-key blocks, JWTs, cookie/session headers, DB connection strings, `password = "…"` | block |
| Anomalies | long high-entropy strings, oversized documents (>512 KB) | warn |

A `block` finding aborts the upload. Overriding requires an explicit recorded
human reason — `bridge push <file> --allow-secrets "<why>"` — which is echoed
in the push output. Agents should never invent a reason on their own;
`bridge check` runs the same firewall without uploading.

## Configuration

`~/.config/agent-bridge/config.json` (0600):

```json
{ "baseUrl": "https://…", "uploadToken": "…", "proxy": null }
```

Environment overrides: `BRIDGE_URL`, `BRIDGE_TOKEN`, `BRIDGE_PROXY`.
On networks where `*.workers.dev` is unreachable (DNS resolves but TCP is
blocked), the CLI automatically uses `HTTPS_PROXY`/`ALL_PROXY`, the
configured `proxy`, or the macOS system proxy. localhost is never proxied.
The receiving agent fetches from its own network and is unaffected by local
blocks; a custom domain on your Cloudflare account removes the local block
entirely.

## Web UI

The same Worker serves a minimal UI — no second app, no server:

| Route | Purpose |
| --- | --- |
| `/` | Landing: what this is, links to create / open |
| `/new` | **Create a handoff in the browser**: drag & drop files, write the prompt, see per-file firewall verdicts, encrypt locally (WebCrypto), upload ciphertext |
| `/h/:id` | Human reader: password → local decryption, bundle-aware rendering |
| `/v1/…` | Agent API |

Everything the CLI does happens in the browser too — firewall screening, bundle
assembly, PBKDF2 + AES-GCM. The page holds your upload token (optionally
remembered in localStorage, device-only) because a self-hosted relay requires
the sender to authenticate; there is no account. People who just *receive* a
handoff never need the token.

## Development

```bash
npm run dev        # same Worker code on 127.0.0.1 with an in-memory KV
npm test           # unit + worker behavior + browser-decrypt-source + CLI e2e
npm run typecheck
npm run deploy     # wrangler deploy (needs local wrangler.toml — created by setup)
```

```
src/
├── shared/       # wire format + crypto core (CLI / Worker / browser share it)
├── worker/       # Cloudflare Worker: API, rate limiting, viewer page (zero deps)
├── cli/          # bridge push / check / config, firewall, clipboard
└── local-dev/    # node:http harness + in-memory KV (runs the real Worker code)
```

## Scope

Deliberately **not** built: accounts, projects, handoff history, permanent
storage, vector databases, bidirectional sync, WebSockets, OAuth, dashboards,
burn-after-read. It is a relay, not a platform — see `CHANGELOG.md` for the
reasoning behind each cut.

## License

MIT — see [LICENSE](./LICENSE).
