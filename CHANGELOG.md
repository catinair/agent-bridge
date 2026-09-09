# Changelog

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
