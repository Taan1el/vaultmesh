# VaultMesh

VaultMesh is a local secrets management console for experimenting with envelope encryption, key rotation, threshold unseal flows, dynamic leases, and tamper-evident audit logs.

The product ships as a TypeScript Node API with a Vite React dashboard. It stores encrypted secret envelopes in SQLite, keeps key material in memory only while unsealed, and exposes operational controls for rotating key-encryption keys and re-wrapping stored data-encryption keys.

## What It Does

- Initializes a vault with 3-of-5 Shamir custodian shares.
- Encrypts each secret with a single-use AES-256-GCM data-encryption key.
- Wraps each data-encryption key with the active key-encryption key.
- Seals the vault by purging in-memory root and key-encryption keys.
- Unseals the vault after three unique custodian shares are submitted.
- Rotates key-encryption keys and re-wraps existing secret envelopes without decrypting stored payloads.
- Issues, renews, revokes, and expires dynamic leases.
- Chains audit entries with SHA-256 hashes and verifies ledger integrity.

## Tech Stack

- React 19, TypeScript, Vite
- Node.js, Express, TypeScript
- SQLite WAL mode through `node:sqlite`
- Vitest and Supertest
- Docker and GitHub Actions workflow files

## Run Locally

Requirements:

- Node.js 24 or newer
- npm

Install dependencies:

```bash
npm install
```

Run the API and dashboard in separate terminals:

```bash
npm run dev --workspace=server
npm run dev --workspace=client
```

The API listens on `http://localhost:4005` by default. The Vite dashboard runs on `http://localhost:3005` and proxies `/api` calls to the API.

Build and test:

```bash
npm test
npm run build
```

## Docker

Build and run the production server:

```bash
docker compose up --build
```

The container serves the API and built client from `http://localhost:4005`.

## API Overview

- `GET /api/vault/status`
- `POST /api/vault/seal`
- `POST /api/vault/unseal`
- `POST /api/vault/keks/rotate`
- `POST /api/vault/keks/rewrap`
- `GET /api/secrets`
- `POST /api/secrets`
- `GET /api/secrets/:path`
- `GET /api/leases`
- `POST /api/leases/:id/renew`
- `POST /api/leases/:id/revoke`
- `GET /api/audit/verify`

## Design Trade-offs

- Demo custodian shares are stored so the local workflow remains reproducible. A production system would distribute shares out of band and never expose them through an API.
- The current persistence layer is SQLite for a portable local setup. The schema is relational and can be moved to PostgreSQL with explicit migrations.
- Authentication and authorization are intentionally outside the current scope. API callers are represented by headers and defaults so the cryptographic workflows remain easy to inspect.
- The dynamic credential values are simulated. Lease lifecycle behavior is implemented, but no external cloud provider credentials are minted.

## Next Improvements

- Add role-based access controls around secret reads and key operations.
- Add migration tooling for database schema changes.
- Add Playwright coverage for seal, unseal, and lease workflows.
- Add screenshot generation for release documentation.
