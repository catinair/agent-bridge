# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security reports. Use GitHub's
private security advisory for this repository, or contact the maintainer
directly (see the repository profile). You can expect a best-effort response
within a few days; this is a personal project maintained without SLAs.

## Scope

In scope:

- The Worker (`src/worker/`): authentication of uploads, access control,
  information leakage via responses or headers, the viewer page's handling of
  secrets
- The crypto core (`src/shared/handoff-crypto.ts`): envelope handling, key
  derivation, secret generation and normalization
- The CLI (`src/cli/`): anything that could cause credentials or plaintext to
  leak (logs, config file permissions, clipboard behavior)

Out of scope:

- Cloudflare's platform itself (report to
  [Cloudflare Security](https://developers.cloudflare.com/foundational-security-disclosure/))
- The user's own device compromise, or a recipient intentionally leaking a
  decrypted handoff they were trusted with
- The fact that a handoff *exists* (metadata: URL requests are visible to
  Cloudflare as any HTTP traffic would be; the CLI and server never log
  bodies, but transport-level metadata is inherent to HTTPS)

## Honest boundaries

This tool protects context documents in transit with a 5-minute window. It
cannot protect you from: pushing a secret that the Context Firewall fails to
recognize (heuristic detection is best-effort — override requires a recorded
human reason for exactly this reason), a compromised local machine, or a
recipient you pasted the URL + password into keeping a copy. The server is
zero-knowledge by design and stores no plaintext and no passwords — verify
it: `src/worker/` is small, dependency-free, and meant to be read.

## Deployment hygiene

Run your own Worker (`npm run setup`). Do not send handoffs to a Worker you
did not deploy — the whole trust model assumes you control the relay.
