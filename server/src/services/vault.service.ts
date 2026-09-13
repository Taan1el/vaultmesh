import crypto from 'node:crypto';
import { VaultDatabase } from '../db/database.js';
import { EnvelopeEncryption, EnvelopeEncryptedPackage } from '../crypto/envelope.js';
import { ShamirSecretSharing } from '../crypto/shamir.js';
import {
  VaultState,
  VaultStatus,
  UnsealProgress,
  StoredSecret,
  SecretLease,
  DecryptedSecret,
  CreateSecretDto,
  KekVersionInfo,
  AuditEntry,
  AuditAction,
  AuditVerificationResult,
} from '../../../shared/types.js';
import { badRequest, conflict, notFound, vaultSealed, VaultError } from '../../../shared/errors.js';
import { parseCreateSecretInput, parseRenewIncrement, parseSecretPath } from '../../../shared/validation.js';
import { formatShare, type SharePoint } from '../../../shared/shamir.js';
import { assertLeaseRevocable, LEASE_MAX_RENEWALS, planLeaseRenewal } from '../../../shared/leases.js';
import { auditChainInputs, checkAuditChain, GENESIS_HASH } from '../../../shared/audit.js';

const UNSEAL_THRESHOLD = 3;
const TOTAL_SHARES = 5;
const ROOT_KEY_BYTES = 32;

export class VaultService {
  private db: VaultDatabase;
  private status: VaultStatus = 'SEALED';
  private rootMasterKey: Buffer | null = null;
  private inMemoryKeks: Map<number, Buffer> = new Map();
  // Submitted custodian shares for the current unseal attempt, keyed by share index.
  private submittedShares: Map<number, string> = new Map();
  private masterShares: string[] = [];
  private reaperTimer: NodeJS.Timeout | null = null;

  constructor(db: VaultDatabase) {
    this.db = db;
    this.bootstrapVault();
    this.startLeaseReaper();
  }

  private bootstrapVault(): void {
    const rawDb = this.db.getDb();
    const initRow = rawDb.prepare('SELECT value FROM vault_metadata WHERE key = ?').get('is_initialized') as { value: string } | undefined;

    if (!initRow) {
      // Initialize fresh vault
      const rootKey = crypto.randomBytes(ROOT_KEY_BYTES);
      this.rootMasterKey = rootKey;
      this.masterShares = ShamirSecretSharing.split(rootKey, TOTAL_SHARES, UNSEAL_THRESHOLD);

      const kekV1 = EnvelopeEncryption.generateKek();
      this.inMemoryKeks.set(1, kekV1);

      // Encrypt KEK V1 with Root Master Key
      const encryptedKek = EnvelopeEncryption.wrapKey(kekV1, rootKey);

      rawDb.exec('BEGIN IMMEDIATE;');
      try {
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('is_initialized', 'true');
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('threshold', '3');
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('total_shares', '5');
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('active_kek_version', '1');
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('status', 'UNSEALED');
        rawDb.prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?)').run('demo_shares', JSON.stringify(this.masterShares));

        rawDb.prepare('INSERT INTO kek_store (version, encrypted_kek, created_at, is_active) VALUES (?, ?, ?, ?)')
          .run(1, encryptedKek, new Date().toISOString(), 1);

        rawDb.exec('COMMIT;');
      } catch (err) {
        rawDb.exec('ROLLBACK;');
        throw err;
      }

      this.status = 'UNSEALED';

      // Record Genesis Audit
      this.recordAudit({
        action: 'VAULT_INIT',
        actor: 'system/bootstrap',
        ip: '127.0.0.1',
        status: 'SUCCESS',
        details: 'Vault initialized with 3-of-5 Shamir threshold and KEK v1',
      });

      // Seed default production-grade secrets
      this.seedInitialSecrets();
    } else {
      const sharesRow = rawDb.prepare('SELECT value FROM vault_metadata WHERE key = ?').get('demo_shares') as { value: string } | undefined;
      if (sharesRow) {
        this.masterShares = JSON.parse(sharesRow.value);
      }

      // A vault that was sealed before shutdown stays sealed after a restart.
      const statusRow = rawDb.prepare('SELECT value FROM vault_metadata WHERE key = ?').get('status') as { value: string } | undefined;
      if (statusRow?.value !== 'SEALED' && this.masterShares.length >= UNSEAL_THRESHOLD) {
        this.rootMasterKey = ShamirSecretSharing.combine(this.masterShares.slice(0, UNSEAL_THRESHOLD));
        this.inMemoryKeks = this.unwrapKeks(this.rootMasterKey);
        this.status = 'UNSEALED';
      }
    }
  }

  private seedInitialSecrets(): void {
    this.createSecret({
      path: 'secret/production/database',
      name: 'Production PostgreSQL Primary',
      description: 'Primary connection credentials with auto-replicated replica read strings',
      plaintext: JSON.stringify({
        host: 'db-cluster-primary.internal.cloud',
        port: 5432,
        database: 'orders_production',
        username: 'pg_app_svc',
        password: 'P@ssw0rd_SuperSecure_9921',
        pool_size: 25,
      }),
      isDynamic: false,
    }, 'system/seeder', '127.0.0.1');

    this.createSecret({
      path: 'secret/payments/stripe',
      name: 'Stripe API Gateway Keys',
      description: 'Production webhook signing secret and private restricted key',
      plaintext: JSON.stringify({
        publishable_key: 'pk_live_51M0abcdef1234567890',
        secret_key: 'rk_live_99abc99xyz001122334455',
        webhook_secret: 'whsec_99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4',
      }),
      isDynamic: false,
    }, 'system/seeder', '127.0.0.1');

    this.createSecret({
      path: 'secret/cloud/aws_sts_token',
      name: 'Ephemeral AWS STS Credential',
      description: 'Dynamic temporary STS token with automatic 30s TTL lease revocation',
      plaintext: JSON.stringify({
        access_key_id: 'ASIAZ9876543210ABCDEF',
        secret_access_key: 'k8J9xL2pQ5mN8vT1wR4yU7iO0sA3dF6gH9jK2lZ',
        session_token: 'FQoGZXIvYXdzEJr//////////wEaDEB...EXAMPLE_TOKEN',
      }),
      isDynamic: true,
      ttlSeconds: 30,
      maxTtlSeconds: 120,
    }, 'system/seeder', '127.0.0.1');
  }

  /**
   * Decrypts every stored KEK with a candidate root key. AES-GCM authentication
   * fails for a wrong key, so this also proves that reconstructed shares are valid.
   */
  private unwrapKeks(rootKey: Buffer): Map<number, Buffer> {
    const rawDb = this.db.getDb();
    const rows = rawDb.prepare('SELECT version, encrypted_kek FROM kek_store').all() as { version: number; encrypted_kek: string }[];
    const keks = new Map<number, Buffer>();
    try {
      for (const r of rows) {
        keks.set(r.version, EnvelopeEncryption.unwrapKey(r.encrypted_kek, rootKey));
      }
    } catch (err) {
      for (const kek of keks.values()) kek.fill(0);
      throw err;
    }
    return keks;
  }

  private setMetadata(key: string, value: string): void {
    this.db
      .getDb()
      .prepare('INSERT INTO vault_metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, value);
  }

  getState(): VaultState {
    const rawDb = this.db.getDb();
    const activeKekRow = rawDb.prepare('SELECT value FROM vault_metadata WHERE key = ?').get('active_kek_version') as { value: string } | undefined;
    const countRow = rawDb.prepare('SELECT COUNT(*) as count FROM secrets').get() as { count: number };
    const leaseRow = rawDb.prepare("SELECT COUNT(*) as count FROM leases WHERE status = 'ACTIVE'").get() as { count: number };

    return {
      status: this.status,
      threshold: UNSEAL_THRESHOLD,
      totalShares: TOTAL_SHARES,
      sharesSubmitted: this.submittedShares.size,
      submittedShareIndexes: this.submittedShareIndexes(),
      activeKekVersion: activeKekRow ? parseInt(activeKekRow.value, 10) : 1,
      totalSecrets: countRow.count,
      activeLeases: leaseRow.count,
      isInitialized: true,
    };
  }

  getDemoShares(): string[] {
    return this.masterShares;
  }

  seal(actor = 'operator', ip = '127.0.0.1'): VaultState {
    if (this.status === 'SEALED') {
      return this.getState();
    }
    if (this.rootMasterKey) {
      this.rootMasterKey.fill(0);
      this.rootMasterKey = null;
    }
    for (const [, kek] of this.inMemoryKeks) {
      kek.fill(0);
    }
    this.inMemoryKeks.clear();
    this.submittedShares.clear();
    this.status = 'SEALED';
    this.setMetadata('status', 'SEALED');

    this.recordAudit({
      action: 'VAULT_SEAL',
      actor,
      ip,
      status: 'SUCCESS',
      details: 'Vault was manually sealed. All master keys purged from RAM.',
    });

    return this.getState();
  }

  submitUnsealShare(shareStr: string, actor = 'custodian', ip = '127.0.0.1'): UnsealProgress {
    let point: SharePoint;
    try {
      point = ShamirSecretSharing.parseShare(shareStr, ROOT_KEY_BYTES);
    } catch (err) {
      throw badRequest(err instanceof Error ? err.message : 'Invalid share');
    }

    if (this.status === 'UNSEALED') {
      return this.unsealProgress();
    }

    if (this.submittedShares.has(point.x)) {
      throw conflict(`Share ${point.x} was already submitted. Use a different custodian share.`);
    }
    this.submittedShares.set(point.x, formatShare(point));

    if (this.submittedShares.size < UNSEAL_THRESHOLD) {
      return this.unsealProgress();
    }

    // Every attempt that reaches the threshold ends here, so a bad share never
    // leaves the vault stuck with an unusable set of submitted shares.
    const shares = Array.from(this.submittedShares.values());
    this.submittedShares.clear();
    let candidate: Buffer | null = null;
    try {
      candidate = ShamirSecretSharing.combine(shares);
      this.inMemoryKeks = this.unwrapKeks(candidate);
      this.rootMasterKey = candidate;
      this.status = 'UNSEALED';
      this.setMetadata('status', 'UNSEALED');
    } catch {
      candidate?.fill(0);
      this.recordAudit({
        action: 'VAULT_UNSEAL',
        actor,
        ip,
        status: 'FAILED',
        details: 'Unseal failed: the submitted shares did not reconstruct the root key',
      });
      throw badRequest('The submitted shares do not reconstruct the root key. Progress was reset, so submit three valid shares again.');
    }

    this.recordAudit({
      action: 'VAULT_UNSEAL',
      actor,
      ip,
      status: 'SUCCESS',
      details: `Vault unsealed with ${UNSEAL_THRESHOLD} custodian shares`,
    });

    return this.unsealProgress();
  }

  private unsealProgress(): UnsealProgress {
    const unsealed = this.status === 'UNSEALED';
    const sharesSubmitted = unsealed ? UNSEAL_THRESHOLD : this.submittedShares.size;
    return {
      status: this.status,
      sharesSubmitted,
      submittedShareIndexes: this.submittedShareIndexes(),
      threshold: UNSEAL_THRESHOLD,
      sharesRemaining: UNSEAL_THRESHOLD - sharesSubmitted,
      unsealed,
    };
  }

  private submittedShareIndexes(): number[] {
    return Array.from(this.submittedShares.keys()).sort((a, b) => a - b);
  }

  resetUnseal(): void {
    this.submittedShares.clear();
  }

  private assertUnsealed(): void {
    if (this.status !== 'UNSEALED' || !this.rootMasterKey) {
      throw vaultSealed();
    }
  }

  rotateKek(actor = 'security-admin', ip = '127.0.0.1'): KekVersionInfo {
    this.assertUnsealed();
    const rawDb = this.db.getDb();

    const maxRow = rawDb.prepare('SELECT MAX(version) as max_v FROM kek_store').get() as { max_v: number };
    const nextVersion = (maxRow.max_v || 1) + 1;

    const newKek = EnvelopeEncryption.generateKek();
    const encryptedKek = EnvelopeEncryption.wrapKey(newKek, this.rootMasterKey!);

    rawDb.exec('BEGIN IMMEDIATE;');
    try {
      rawDb.prepare('UPDATE kek_store SET is_active = 0 WHERE is_active = 1').run();
      rawDb.prepare('INSERT INTO kek_store (version, encrypted_kek, created_at, is_active) VALUES (?, ?, ?, ?)')
        .run(nextVersion, encryptedKek, new Date().toISOString(), 1);
      rawDb.prepare('UPDATE vault_metadata SET value = ? WHERE key = ?').run(String(nextVersion), 'active_kek_version');
      rawDb.exec('COMMIT;');
    } catch (err) {
      rawDb.exec('ROLLBACK;');
      throw err;
    }

    this.inMemoryKeks.set(nextVersion, newKek);

    this.recordAudit({
      action: 'KEK_ROTATE',
      actor,
      ip,
      status: 'SUCCESS',
      details: `Active KEK rotated to version ${nextVersion}`,
    });

    return {
      version: nextVersion,
      createdAt: new Date().toISOString(),
      secretsCount: 0,
      isActive: true,
    };
  }

  rewrapSecrets(actor = 'security-admin', ip = '127.0.0.1'): { rewrappedCount: number; activeVersion: number } {
    this.assertUnsealed();
    const rawDb = this.db.getDb();
    const activeState = this.getState();
    const activeVersion = activeState.activeKekVersion;
    const activeKek = this.inMemoryKeks.get(activeVersion);

    if (!activeKek) throw new VaultError(500, `Active KEK v${activeVersion} is not loaded`);

    const outdated = rawDb.prepare('SELECT id, path, kek_version, encrypted_dek FROM secrets WHERE kek_version < ?')
      .all(activeVersion) as { id: string; path: string; kek_version: number; encrypted_dek: string }[];

    let rewrappedCount = 0;
    rawDb.exec('BEGIN IMMEDIATE;');
    try {
      const updateStmt = rawDb.prepare('UPDATE secrets SET kek_version = ?, encrypted_dek = ?, updated_at = ? WHERE id = ?');
      for (const item of outdated) {
        const oldKek = this.inMemoryKeks.get(item.kek_version);
        if (!oldKek) throw new VaultError(500, `KEK v${item.kek_version} is not loaded`);

        const newEncryptedDek = EnvelopeEncryption.rewrapDek(item.encrypted_dek, oldKek, activeKek);
        updateStmt.run(activeVersion, newEncryptedDek, new Date().toISOString(), item.id);
        rewrappedCount++;

        this.recordAudit({
          action: 'SECRET_REWRAP',
          secretPath: item.path,
          actor,
          ip,
          status: 'SUCCESS',
          details: `Re-wrapped DEK from KEK v${item.kek_version} to KEK v${activeVersion} with zero plaintext exposure`,
        });
      }
      rawDb.exec('COMMIT;');
    } catch (err) {
      rawDb.exec('ROLLBACK;');
      throw err;
    }

    return { rewrappedCount, activeVersion };
  }

  listKekVersions(): KekVersionInfo[] {
    const rawDb = this.db.getDb();
    const versions = rawDb.prepare(`
      SELECT 
        k.version, 
        k.created_at as createdAt, 
        k.is_active as isActive,
        COUNT(s.id) as secretsCount
      FROM kek_store k
      LEFT JOIN secrets s ON s.kek_version = k.version
      GROUP BY k.version, k.created_at, k.is_active
      ORDER BY k.version DESC
    `).all() as any[];

    return versions.map((v) => ({
      version: v.version,
      createdAt: v.createdAt,
      secretsCount: v.secretsCount || 0,
      isActive: Boolean(v.isActive),
    }));
  }

  createSecret(dto: CreateSecretDto, actor = 'developer', ip = '127.0.0.1'): StoredSecret {
    const input = parseCreateSecretInput(dto);
    this.assertUnsealed();
    const rawDb = this.db.getDb();
    const activeState = this.getState();
    const activeVersion = activeState.activeKekVersion;
    const activeKek = this.inMemoryKeks.get(activeVersion);

    if (!activeKek) throw new VaultError(500, `Active KEK v${activeVersion} is not loaded`);

    const normalizedPath = input.path;
    const pkg: EnvelopeEncryptedPackage = EnvelopeEncryption.encrypt(input.plaintext, activeKek, activeVersion);

    const id = `sec_${crypto.randomBytes(8).toString('hex')}`;
    const now = new Date().toISOString();
    const { isDynamic, ttlSeconds, maxTtlSeconds } = input;
    let lease: SecretLease | undefined;

    rawDb.exec('BEGIN IMMEDIATE;');
    try {
      rawDb.prepare(`
        INSERT INTO secrets (
          id, path, name, description, kek_version, encrypted_dek, iv, auth_tag, ciphertext, version, is_dynamic, ttl_seconds, max_ttl_seconds, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        normalizedPath,
        input.name,
        input.description,
        pkg.kekVersion,
        pkg.encryptedDek,
        pkg.iv,
        pkg.authTag,
        pkg.ciphertext,
        1,
        isDynamic ? 1 : 0,
        ttlSeconds,
        maxTtlSeconds,
        now,
        now
      );

      if (isDynamic) {
        lease = this.insertLease(id, normalizedPath, ttlSeconds);
      }

      rawDb.exec('COMMIT;');
    } catch (err) {
      rawDb.exec('ROLLBACK;');
      if (err instanceof Error && err.message.includes('UNIQUE constraint failed')) {
        throw conflict(`Secret at path "${normalizedPath}" already exists`);
      }
      throw err;
    }

    this.recordAudit({
      action: 'SECRET_CREATE',
      secretPath: normalizedPath,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Created secret under KEK v${pkg.kekVersion} (Dynamic: ${isDynamic})`,
    });
    if (lease) this.auditLeaseIssued(lease, actor, ip);

    return {
      id,
      path: normalizedPath,
      name: input.name,
      description: input.description,
      kekVersion: pkg.kekVersion,
      encryptedDek: pkg.encryptedDek,
      iv: pkg.iv,
      authTag: pkg.authTag,
      ciphertext: pkg.ciphertext,
      version: 1,
      isDynamic,
      ttlSeconds,
      maxTtlSeconds,
      createdAt: now,
      updatedAt: now,
    };
  }

  readSecret(pathOrId: string, actor = 'developer', ip = '127.0.0.1'): DecryptedSecret {
    const cleanQuery = parseSecretPath(pathOrId);
    this.assertUnsealed();
    const rawDb = this.db.getDb();

    const row = rawDb.prepare(`
      SELECT * FROM secrets WHERE path = ? OR id = ?
    `).get(cleanQuery, cleanQuery) as any;

    if (!row) {
      this.recordAudit({
        action: 'SECRET_READ',
        secretPath: cleanQuery,
        actor,
        ip,
        status: 'DENIED',
        details: `Secret not found at path: ${cleanQuery}`,
      });
      throw notFound(`Secret not found at path "${cleanQuery}"`);
    }

    const kek = this.inMemoryKeks.get(row.kek_version);
    if (!kek) {
      throw new VaultError(500, `KEK v${row.kek_version} is not loaded`);
    }

    const pkg: EnvelopeEncryptedPackage = {
      kekVersion: row.kek_version,
      encryptedDek: row.encrypted_dek,
      iv: row.iv,
      authTag: row.auth_tag,
      ciphertext: row.ciphertext,
    };

    const plaintext = EnvelopeEncryption.decrypt(pkg, kek);
    let parsedData: Record<string, any> | undefined;
    try {
      parsedData = JSON.parse(plaintext);
    } catch {
      // plain text string
    }

    // Reading a dynamic secret returns its current lease. When the last lease
    // expired or was revoked, the read issues a new one.
    let lease: SecretLease | undefined;
    let issuedLease = false;
    if (Boolean(row.is_dynamic)) {
      const activeLease = rawDb.prepare(`
        SELECT * FROM leases WHERE secret_id = ? AND status = 'ACTIVE' AND expires_at > ? ORDER BY expires_at DESC LIMIT 1
      `).get(row.id, new Date().toISOString()) as any;

      if (activeLease) {
        lease = this.toLease(activeLease);
      } else {
        lease = this.insertLease(row.id, row.path, row.ttl_seconds);
        issuedLease = true;
      }
    }

    this.recordAudit({
      action: 'SECRET_READ',
      secretPath: row.path,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Read and decrypted secret with KEK v${row.kek_version}`,
    });
    if (lease && issuedLease) this.auditLeaseIssued(lease, actor, ip);

    return {
      id: row.id,
      path: row.path,
      name: row.name,
      description: row.description || '',
      kekVersion: row.kek_version,
      plaintext,
      parsedData,
      version: row.version,
      isDynamic: Boolean(row.is_dynamic),
      lease,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  listSecrets(): StoredSecret[] {
    const rawDb = this.db.getDb();
    const rows = rawDb.prepare('SELECT * FROM secrets ORDER BY path ASC').all() as any[];
    return rows.map((r) => ({
      id: r.id,
      path: r.path,
      name: r.name,
      description: r.description || '',
      kekVersion: r.kek_version,
      encryptedDek: r.encrypted_dek,
      iv: r.iv,
      authTag: r.auth_tag,
      ciphertext: r.ciphertext,
      version: r.version,
      isDynamic: Boolean(r.is_dynamic),
      ttlSeconds: r.ttl_seconds,
      maxTtlSeconds: r.max_ttl_seconds,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }));
  }

  deleteSecret(pathOrId: string, actor = 'developer', ip = '127.0.0.1'): { path: string } {
    const cleanQuery = parseSecretPath(pathOrId);
    this.assertUnsealed();
    const rawDb = this.db.getDb();

    const row = rawDb.prepare('SELECT id, path FROM secrets WHERE path = ? OR id = ?').get(cleanQuery, cleanQuery) as any;
    if (!row) throw notFound(`Secret not found at path "${cleanQuery}"`);

    rawDb.exec('BEGIN IMMEDIATE;');
    try {
      rawDb.prepare('DELETE FROM leases WHERE secret_id = ?').run(row.id);
      rawDb.prepare('DELETE FROM secrets WHERE id = ?').run(row.id);
      rawDb.exec('COMMIT;');
    } catch (err) {
      rawDb.exec('ROLLBACK;');
      throw err;
    }

    this.recordAudit({
      action: 'SECRET_DELETE',
      secretPath: row.path,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Secret at path "${row.path}" was permanently deleted`,
    });

    return { path: row.path };
  }

  renewLease(leaseId: string, incrementSeconds?: unknown, actor = 'client-app', ip = '127.0.0.1'): SecretLease {
    const increment = parseRenewIncrement(incrementSeconds);
    this.assertUnsealed();
    const rawDb = this.db.getDb();
    const row = rawDb.prepare(`
      SELECT l.*, s.max_ttl_seconds FROM leases l LEFT JOIN secrets s ON s.id = l.secret_id WHERE l.id = ?
    `).get(leaseId) as any;

    if (!row) throw notFound(`Lease "${leaseId}" not found`);
    const lease = this.toLease(row);
    const renewal = planLeaseRenewal(lease, row.max_ttl_seconds ?? 0, increment, Date.now());

    rawDb.prepare(`
      UPDATE leases SET expires_at = ?, renew_count = ? WHERE id = ?
    `).run(renewal.expiresAt, renewal.renewCount, leaseId);

    this.recordAudit({
      action: 'LEASE_RENEW',
      secretPath: lease.secretPath,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Lease "${leaseId}" renewed (${renewal.renewCount}/${lease.maxRenewals}) until ${renewal.expiresAt}`,
    });

    return { ...lease, expiresAt: renewal.expiresAt, renewCount: renewal.renewCount };
  }

  revokeLease(leaseId: string, actor = 'client-app', ip = '127.0.0.1'): SecretLease {
    this.assertUnsealed();
    const rawDb = this.db.getDb();
    const row = rawDb.prepare('SELECT * FROM leases WHERE id = ?').get(leaseId) as any;

    if (!row) throw notFound(`Lease "${leaseId}" not found`);
    const lease = this.toLease(row);
    assertLeaseRevocable(lease);
    const now = new Date().toISOString();

    rawDb.prepare(`
      UPDATE leases SET status = 'REVOKED', revoked_at = ? WHERE id = ?
    `).run(now, leaseId);

    this.recordAudit({
      action: 'LEASE_REVOKE',
      secretPath: lease.secretPath,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Lease "${leaseId}" revoked by ${actor}`,
    });

    return { ...lease, status: 'REVOKED', revokedAt: now };
  }

  listLeases(): SecretLease[] {
    const rawDb = this.db.getDb();
    const rows = rawDb.prepare('SELECT * FROM leases ORDER BY issued_at DESC LIMIT 50').all() as any[];
    return rows.map((r) => this.toLease(r));
  }

  private toLease(row: any): SecretLease {
    return {
      id: row.id,
      secretId: row.secret_id,
      secretPath: row.secret_path,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      ttlSeconds: row.ttl_seconds,
      renewCount: row.renew_count,
      maxRenewals: row.max_renewals,
      status: row.status,
      ...(row.revoked_at ? { revokedAt: row.revoked_at } : {}),
    };
  }

  private insertLease(secretId: string, secretPath: string, ttlSeconds: number): SecretLease {
    const issued = Date.now();
    const lease: SecretLease = {
      id: `lease_${crypto.randomBytes(10).toString('hex')}`,
      secretId,
      secretPath,
      issuedAt: new Date(issued).toISOString(),
      expiresAt: new Date(issued + ttlSeconds * 1000).toISOString(),
      ttlSeconds,
      renewCount: 0,
      maxRenewals: LEASE_MAX_RENEWALS,
      status: 'ACTIVE',
    };
    this.db.getDb().prepare(`
      INSERT INTO leases (id, secret_id, secret_path, issued_at, expires_at, ttl_seconds, renew_count, max_renewals, status)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, 'ACTIVE')
    `).run(lease.id, secretId, secretPath, lease.issuedAt, lease.expiresAt, ttlSeconds, LEASE_MAX_RENEWALS);
    return lease;
  }

  private auditLeaseIssued(lease: SecretLease, actor: string, ip: string): void {
    this.recordAudit({
      action: 'LEASE_ISSUE',
      secretPath: lease.secretPath,
      actor,
      ip,
      status: 'SUCCESS',
      details: `Lease "${lease.id}" issued for ${lease.ttlSeconds} seconds`,
    });
  }

  private startLeaseReaper(): void {
    if (this.reaperTimer) clearInterval(this.reaperTimer);
    this.reaperTimer = setInterval(() => {
      this.sweepExpiredLeases();
    }, 2000);
  }

  sweepExpiredLeases(): number {
    const rawDb = this.db.getDb();
    const nowIso = new Date().toISOString();

    const expiredRows = rawDb.prepare(`
      SELECT id, secret_path FROM leases WHERE status = 'ACTIVE' AND expires_at <= ?
    `).all(nowIso) as { id: string; secret_path: string }[];

    if (expiredRows.length === 0) return 0;

    rawDb.exec('BEGIN IMMEDIATE;');
    try {
      const updateStmt = rawDb.prepare("UPDATE leases SET status = 'EXPIRED' WHERE id = ?");
      for (const row of expiredRows) {
        updateStmt.run(row.id);
        this.recordAudit({
          action: 'LEASE_EXPIRE',
          secretPath: row.secret_path,
          actor: 'system/lease-reaper',
          ip: '127.0.0.1',
          status: 'SUCCESS',
          details: `Lease "${row.id}" TTL expired and was auto-revoked`,
        });
      }
      rawDb.exec('COMMIT;');
    } catch (err) {
      rawDb.exec('ROLLBACK;');
      console.error('Failed to sweep expired leases:', err);
    }

    return expiredRows.length;
  }

  private recordAudit(params: {
    action: AuditAction;
    actor: string;
    ip: string;
    status: 'SUCCESS' | 'DENIED' | 'FAILED';
    details: string;
    secretPath?: string;
  }): AuditEntry {
    const rawDb = this.db.getDb();
    const lastRow = rawDb.prepare('SELECT entry_hash FROM audit_log ORDER BY rowid DESC LIMIT 1').get() as { entry_hash: string } | undefined;
    const previousHash = lastRow?.entry_hash || GENESIS_HASH;

    const id = `aud_${crypto.randomBytes(8).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const payload = {
      id,
      timestamp,
      action: params.action,
      secretPath: params.secretPath || null,
      actor: params.actor,
      ip: params.ip,
      status: params.status,
      details: params.details,
    };

    const entryHash = EnvelopeEncryption.computeAuditHash(previousHash, { ...payload, secretPath: params.secretPath });

    rawDb.prepare(`
      INSERT INTO audit_log (id, timestamp, action, secret_path, actor, ip, status, details, previous_hash, entry_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      timestamp,
      params.action,
      params.secretPath || null,
      params.actor,
      params.ip,
      params.status,
      params.details,
      previousHash,
      entryHash
    );

    return {
      ...payload,
      secretPath: params.secretPath,
      previousHash,
      entryHash,
    };
  }

  getAuditLog(limit = 100): AuditEntry[] {
    const rawDb = this.db.getDb();
    const rows = rawDb.prepare('SELECT * FROM audit_log ORDER BY rowid DESC LIMIT ?').all(limit) as any[];
    return rows.map((r) => this.toAuditEntry(r));
  }

  verifyAuditLedger(): AuditVerificationResult {
    const rawDb = this.db.getDb();
    const rows = rawDb.prepare('SELECT * FROM audit_log ORDER BY rowid ASC').all() as any[];
    const entries = rows.map((r) => this.toAuditEntry(r));
    const hashes = auditChainInputs(entries).map((input) => crypto.createHash('sha256').update(input).digest('hex'));
    return checkAuditChain(entries, hashes, new Date().toISOString());
  }

  private toAuditEntry(row: any): AuditEntry {
    return {
      id: row.id,
      timestamp: row.timestamp,
      action: row.action,
      ...(row.secret_path ? { secretPath: row.secret_path } : {}),
      actor: row.actor,
      ip: row.ip,
      status: row.status,
      details: row.details,
      previousHash: row.previous_hash,
      entryHash: row.entry_hash,
    };
  }

  destroy(): void {
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }
  }
}