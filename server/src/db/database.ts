import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

export class VaultDatabase {
  private db: DatabaseSync;

  constructor(dbPath?: string) {
    const resolvedPath = dbPath || path.resolve(process.cwd(), 'data', 'vaultmesh.db');
    const dir = path.dirname(resolvedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(resolvedPath);
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS kek_store (
        version INTEGER PRIMARY KEY,
        encrypted_kek TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        path TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        kek_version INTEGER NOT NULL,
        encrypted_dek TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        is_dynamic INTEGER NOT NULL DEFAULT 0,
        ttl_seconds INTEGER NOT NULL DEFAULT 0,
        max_ttl_seconds INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS leases (
        id TEXT PRIMARY KEY,
        secret_id TEXT NOT NULL,
        secret_path TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ttl_seconds INTEGER NOT NULL,
        renew_count INTEGER NOT NULL DEFAULT 0,
        max_renewals INTEGER NOT NULL DEFAULT 5,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        revoked_at TEXT,
        FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        secret_path TEXT,
        actor TEXT NOT NULL,
        ip TEXT NOT NULL,
        status TEXT NOT NULL,
        details TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_secrets_path ON secrets(path);
      CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    `);
  }

  getDb(): DatabaseSync {
    return this.db;
  }

  close(): void {
    this.db.close();
  }
}