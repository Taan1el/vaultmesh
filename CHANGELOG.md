# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-09-15

### Added
- Express API for a local secrets vault: 3-of-5 Shamir threshold unseal, AES-256-GCM envelope encryption (a single-use data-encryption key per secret, wrapped by a rotatable key-encryption key), KEK rotation with re-wrap of existing secrets, dynamic leases with a renewal cap, and a SHA-256 hash-chained audit log.
- Node's native SQLite (`node:sqlite`, WAL mode) as storage, seeded with a small set of sample secrets on first start.
- React 19 dashboard: a custodian unseal flow with sample shares, a secret inventory with a decrypt-and-inspect drawer, key version history, dynamic lease countdowns with renew and revoke, and an audit ledger with chain verification.
- In-browser demo mode for GitHub Pages: the same shared validation, Shamir, lease, audit and seed modules run against the Web Crypto API and localStorage instead of the API, with a "Reset demo data" control.
- Docker image (multi-stage build, runs as a non-root user, health check) and a Compose file for local use.
- CI workflow (lint, test, build, Docker build on Node 22 and 24) and a GitHub Pages deployment workflow.

### Fixed
- A forged, truncated or re-cased custodian share was counted as progress, and once reconstruction failed every later share failed too until the reset endpoint was called. Shares are now validated and tracked by index, KEKs are verified before the vault unseals, and a failed attempt clears progress so custodians can submit three fresh shares.
- The server rebuilt the root key from the stored demo shares on every start, so restarting silently unsealed a sealed vault. Seal state is now stored and respected at startup.
- `maxTtlSeconds` was stored but never checked, an expired lease could still be renewed before the reaper ran, and a dynamic secret had no way to get a new lease once the first one ended. Renewals are now capped, expired leases are rejected, and reading a dynamic secret issues a fresh lease when none is active.
- The API had no authentication but sent `Access-Control-Allow-Origin: *` and listened on every interface, so any site or device on the network could read decrypted secrets or seal the vault. CORS is removed, API POSTs must be JSON, responses are not cacheable, and the server binds to `127.0.0.1` unless `HOST` is set.
- Error responses could leak internal detail (SQL and crypto library messages, HTML stack trace pages for malformed JSON); errors now carry their own HTTP status, unknown API routes return JSON 404s, and unexpected failures return a generic 500.
- The compiled server was emitted to `dist/server/src` because the build includes the shared folder, so `npm start` and the Docker image pointed at a file that never existed.
- The container ran an entry point the build never produced and stored the database outside the mounted volume.
- `npm run dev` joined the server and client commands with `&`, which runs them one after the other on Windows instead of together, so the dashboard never started.
- Sample seed data used live-style payment and cloud credential formats that secret scanners flag; they are now obvious placeholders.
- "Load sample" always loaded the first custodian share instead of the next unused one, so the vault could not be fully unsealed from the dashboard; lease state also went stale until a manual refresh, and sealed-only actions stayed clickable only to fail.
- Several counts in the dashboard (secrets, key versions, audit entries, remaining shares) were always shown as plural, so a count of one read as "1 entries" or "1 versions".
