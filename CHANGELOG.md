# Changelog

## 1.2.2 — 2026-09-09

- Text envelope: ciphertext is emitted as an ordered `ciphertext_chunks` list
  (~600 chars each, concatenate + base64-decode) because web-retrieval layers
  truncate very long single lines. JSON endpoint unchanged

## 1.2.1 — 2026-09-09

- Text-envelope fallback: `GET /v1/handoffs/<id>.txt` serves the same
  ciphertext envelope as flat `key: value` text (`text/plain`), for retrieval
  environments that swallow raw JSON bodies; discovered via an additional
  `text envelope` link on `/h/<id>`. Security model unchanged
- HEAD requests are now handled as GET (body stripped by the runtime)

## 1.2.0 — 2026-09-09

- **Web UI on the same Worker** — no second app:
  - `/` landing ("Give AI agents context, not access.")
  - `/new` browser-based bundle creator: drag & drop, per-file firewall
    verdicts, prompt + notes, WebCrypto encryption, upload-token handling with
    optional localStorage remember, result view with Copy for ChatGPT
  - browser create-lib cross-verified against the shared TypeScript crypto and
    firewall in tests (encrypt with the page, decrypt with the CLI)
- Fixed: viewer/create pages now also clear the FileList snapshot bug where
  only the first selected file was processed

## 1.1.0 — 2026-09-09

- **Context Bundles**: multi-file pushes where original files travel verbatim
  plus a short `--prompt` / `--notes`; decrypted payload is structured JSON
  (`application/vnd.agent-context-bundle+json`), no ZIP, no filesystem needed
  on the receiving side. Text files only in V1
- Bundle-aware Context Firewall: every file is checked (path policy +
  credential scan + binary/extension detection); blocked files are dropped
  **unconditionally** — bundle mode has no override
- Viewer page renders bundles structurally: request block + per-file
  collapsible sections with individual copy buttons
- Server limits raised for bundles (4 MB plaintext, 4.4 MB ciphertext cap);
  single-document mode unchanged (2 MB)
- CLI: `--prompt` / `--notes` flags; `check` accepts multiple files;
  `--iterations` is now actually wired to the KDF (was parsed and ignored)

## 1.0.0 — 2026-09-09

First public release.

- End-to-end encrypted handoffs: client-side AES-256-GCM, PBKDF2-SHA256
  (600k iterations, configurable), 160-bit Crockford-Base32 secrets
- Cloudflare Workers + KV relay: ciphertext only, TTL hard delete (default
  300s, 60–3600s), 130-bit non-enumerable IDs, per-IP rate limiting,
  Bearer-token upload auth, hardened response headers
- Machine discovery: `/h/:id` viewer page server-renders `<link rel=alternate>`
  and `<a>` links to the JSON envelope endpoint, annotated
  `application/vnd.agent-handoff+json`; validated against real ChatGPT web
  retrieval
- Self-describing envelope: `protocol`, `encoding`, `secret_encoding`,
  `secret_normalization` fields (backward compatible)
- CLI: `bridge push` (with post-upload public roundtrip verification),
  `bridge check`, `bridge config`; clipboard integration; automatic proxy
  fallback (env → config → macOS system proxy)
- Context Firewall: default-deny path policy, credential scanning, entropy /
  size anomaly warnings; overrides require a recorded human reason
- 54 tests: unit, worker behavior (mocked KV), browser decrypt source
  executed against shared-encoder ciphertext, and a full CLI → HTTP →
  decrypt end-to-end suite
