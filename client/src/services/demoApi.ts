// In-browser implementation of the vault API for the static GitHub Pages build.
// It follows the server's rules by reusing the shared modules (validation,
// Shamir shares, lease limits, audit chain, sample data) and encrypts with the
// Web Crypto API. Vault data is persisted in localStorage; keys live only in memory.
import type {
  AuditAction,
  AuditEntry,
  CreateSecretDto,
  DecryptedSecret,
  KekVersionInfo,
  SecretLease,
  StoredSecret,
  UnsealProgress,
  VaultState,
  VaultStatus,
} from '../../../shared/types';
import { badRequest, conflict, notFound, vaultSealed, VaultError } from '../../../shared/errors';
import {
  parseAuditLimit,
  parseCreateSecretInput,
  parseRenewIncrement,
  parseSecretPath,
} from '../../../shared/validation';
import { combineShares, formatShare, parseShare, splitSecret } from '../../../shared/shamir';
import { assertLeaseRevocable, LEASE_MAX_RENEWALS, planLeaseRenewal } from '../../../shared/leases';
import { auditChainInputs, auditHashInput, checkAuditChain, GENESIS_HASH } from '../../../shared/audit';
import { bytesToHex } from '../../../shared/encoding';
import { SAMPLE_SECRETS } from '../../../shared/seed';
import type { VaultApi } from './api';
import {
  KEY_BYTES,
  decryptEnvelope,
  encryptEnvelope,
  randomBytes,
  rewrapDek,
  sha256Hex,
  unwrapKey,
  wrapKey,
} from './demoCrypto';

export const DEMO_STORAGE_KEY = 'vaultmesh-demo:v1';

const UNSEAL_THRESHOLD = 3;
const TOTAL_SHARES = 5;
const MAX_LEASES_LISTED = 50;
const DEFAULT_AUDIT_LIMIT = 8;
const BROWSER_IP = 'browser';

interface StoredKek {
  version: number;
  encryptedKek: string;
  createdAt: string;
  isActive: boolean;
}

/** The persisted part of the vault, equivalent to the server's SQLite tables. */
interface PersistedVault {
  version: 1;
  status: VaultStatus;
  demoShares: string[];
  activeKekVersion: number;
  keks: StoredKek[];
  secrets: StoredSecret[];
  leases: SecretLease[];
  audit: AuditEntry[];
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface DemoApi extends VaultApi {
  /** Deletes all demo data. The next call creates a fresh sample vault. */
  reset(): Promise<void>;
}

export function memoryStorage(): StorageLike {
  const items = new Map<string, string>();
  return {
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => void items.set(key, value),
    removeItem: (key) => void items.delete(key),
  };
}

function browserStorage(): StorageLike {
  try {
    const storage = globalThis.localStorage;
    const probe = `${DEMO_STORAGE_KEY}:probe`;
    storage.setItem(probe, '1');
    storage.removeItem(probe);
    return storage;
  } catch {
    // Private mode or blocked storage: keep the demo working for this page view.
    return memoryStorage();
  }
}

function isPersistedVault(value: unknown): value is PersistedVault {
  const v = value as PersistedVault;
  return (
    !!v &&
    v.version === 1 &&
    (v.status === 'SEALED' || v.status === 'UNSEALED') &&
    Array.isArray(v.demoShares) &&
    Array.isArray(v.keks) &&
    Array.isArray(v.secrets) &&
    Array.isArray(v.leases) &&
    Array.isArray(v.audit)
  );
}

const randomId = (prefix: string, bytes: number) => `${prefix}_${bytesToHex(randomBytes(bytes))}`;
const nowIso = () => new Date().toISOString();

export function createDemoApi(storageFactory: () => StorageLike = browserStorage): DemoApi {
  let storage: StorageLike | null = null;
  let vault: PersistedVault | null = null;
  let rootKey: Uint8Array | null = null;
  let keks = new Map<number, Uint8Array>();
  const submittedShares = new Map<number, string>();
  let queue: Promise<unknown> = Promise.resolve();

  const getStorage = () => (storage ??= storageFactory());

  function clearKeys() {
    rootKey?.fill(0);
    rootKey = null;
    for (const kek of keks.values()) kek.fill(0);
    keks = new Map();
  }

  function save(v: PersistedVault) {
    try {
      getStorage().setItem(DEMO_STORAGE_KEY, JSON.stringify(v));
    } catch {
      // Storage full or blocked: continue in memory for this page view.
      storage = memoryStorage();
      storage.setItem(DEMO_STORAGE_KEY, JSON.stringify(v));
    }
  }

  function readStored(): PersistedVault | null {
    try {
      const raw = getStorage().getItem(DEMO_STORAGE_KEY);
      if (!raw) return null;
      const parsed: unknown = JSON.parse(raw);
      return isPersistedVault(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  async function unwrapKeks(v: PersistedVault, key: Uint8Array): Promise<Map<number, Uint8Array>> {
    const result = new Map<number, Uint8Array>();
    try {
      for (const stored of v.keks) {
        result.set(stored.version, await unwrapKey(stored.encryptedKek, key));
      }
    } catch (error) {
      for (const kek of result.values()) kek.fill(0);
      throw error;
    }
    return result;
  }

  async function recordAudit(
    v: PersistedVault,
    entry: { action: AuditAction; actor: string; status?: AuditEntry['status']; details: string; secretPath?: string }
  ) {
    const previousHash = v.audit.length ? v.audit[v.audit.length - 1].entryHash : GENESIS_HASH;
    const fields = {
      id: randomId('aud', 8),
      timestamp: nowIso(),
      action: entry.action,
      ...(entry.secretPath ? { secretPath: entry.secretPath } : {}),
      actor: entry.actor,
      ip: BROWSER_IP,
      status: entry.status ?? 'SUCCESS',
      details: entry.details,
    };
    const entryHash = await sha256Hex(auditHashInput(previousHash, fields));
    v.audit.push({ ...fields, previousHash, entryHash });
  }

  function newLease(secret: StoredSecret): SecretLease {
    const issued = Date.now();
    return {
      id: randomId('lease', 10),
      secretId: secret.id,
      secretPath: secret.path,
      issuedAt: new Date(issued).toISOString(),
      expiresAt: new Date(issued + secret.ttlSeconds * 1000).toISOString(),
      ttlSeconds: secret.ttlSeconds,
      renewCount: 0,
      maxRenewals: LEASE_MAX_RENEWALS,
      status: 'ACTIVE',
    };
  }

  async function auditLeaseIssued(v: PersistedVault, lease: SecretLease, actor: string) {
    await recordAudit(v, {
      action: 'LEASE_ISSUE',
      actor,
      secretPath: lease.secretPath,
      details: `Lease "${lease.id}" issued for ${lease.ttlSeconds} seconds`,
    });
  }

  function requireKeys(v: PersistedVault): Uint8Array {
    if (v.status !== 'UNSEALED' || !rootKey) throw vaultSealed();
    const kek = keks.get(v.activeKekVersion);
    if (!kek) throw new VaultError(500, `Active KEK v${v.activeKekVersion} is not loaded`);
    return kek;
  }

  async function createSecretIn(v: PersistedVault, dto: CreateSecretDto, actor: string): Promise<StoredSecret> {
    const input = parseCreateSecretInput(dto);
    const kek = requireKeys(v);
    if (v.secrets.some((s) => s.path === input.path)) {
      throw conflict(`Secret at path "${input.path}" already exists`);
    }

    const sealedPayload = await encryptEnvelope(input.plaintext, kek, v.activeKekVersion);
    const now = nowIso();
    const secret: StoredSecret = {
      id: randomId('sec', 8),
      path: input.path,
      name: input.name,
      description: input.description,
      ...sealedPayload,
      version: 1,
      isDynamic: input.isDynamic,
      ttlSeconds: input.ttlSeconds,
      maxTtlSeconds: input.maxTtlSeconds,
      createdAt: now,
      updatedAt: now,
    };
    v.secrets.push(secret);
    const lease = secret.isDynamic ? newLease(secret) : undefined;
    if (lease) v.leases.push(lease);

    await recordAudit(v, {
      action: 'SECRET_CREATE',
      actor,
      secretPath: secret.path,
      details: `Created secret under KEK v${secret.kekVersion} (Dynamic: ${secret.isDynamic})`,
    });
    if (lease) await auditLeaseIssued(v, lease, actor);
    return { ...secret };
  }

  async function initialize(): Promise<PersistedVault> {
    clearKeys();
    submittedShares.clear();
    const root = randomBytes(KEY_BYTES);
    const kek = randomBytes(KEY_BYTES);
    const v: PersistedVault = {
      version: 1,
      status: 'UNSEALED',
      demoShares: splitSecret(root, TOTAL_SHARES, UNSEAL_THRESHOLD),
      activeKekVersion: 1,
      keks: [{ version: 1, encryptedKek: await wrapKey(kek, root), createdAt: nowIso(), isActive: true }],
      secrets: [],
      leases: [],
      audit: [],
    };
    rootKey = root;
    keks = new Map([[1, kek]]);

    await recordAudit(v, {
      action: 'VAULT_INIT',
      actor: 'system/bootstrap',
      details: `Vault initialized with ${UNSEAL_THRESHOLD}-of-${TOTAL_SHARES} Shamir threshold and KEK v1`,
    });
    for (const sample of SAMPLE_SECRETS) {
      await createSecretIn(v, sample, 'system/seeder');
    }
    save(v);
    return v;
  }

  /**
   * Loads the latest persisted vault before every operation, so changes from
   * another tab are picked up, and brings in-memory keys in line with it.
   */
  async function load(): Promise<PersistedVault> {
    const stored = readStored();
    if (!stored) {
      vault = await initialize();
      return vault;
    }

    const sameVault = vault !== null && vault.demoShares[0] === stored.demoShares[0];
    if (!sameVault) {
      clearKeys();
      submittedShares.clear();
    }
    vault = stored;

    if (vault.status === 'SEALED') {
      clearKeys();
      return vault;
    }
    submittedShares.clear();

    try {
      if (!rootKey) {
        // Like a server restart: an unsealed vault is reopened from the stored demo shares.
        const root = combineShares(vault.demoShares.slice(0, UNSEAL_THRESHOLD));
        keks = await unwrapKeks(vault, root);
        rootKey = root;
      } else {
        for (const stored of vault.keks) {
          if (!keks.has(stored.version)) keks.set(stored.version, await unwrapKey(stored.encryptedKek, rootKey));
        }
      }
    } catch {
      // Stored data that cannot be decrypted is unusable, so start over.
      vault = await initialize();
    }
    return vault;
  }

  async function sweepExpiredLeases(v: PersistedVault): Promise<boolean> {
    const now = Date.now();
    let changed = false;
    for (const lease of v.leases) {
      if (lease.status === 'ACTIVE' && Date.parse(lease.expiresAt) <= now) {
        lease.status = 'EXPIRED';
        changed = true;
        await recordAudit(v, {
          action: 'LEASE_EXPIRE',
          actor: 'system/lease-reaper',
          secretPath: lease.secretPath,
          details: `Lease "${lease.id}" expired`,
        });
      }
    }
    return changed;
  }

  /** Serializes tasks so async crypto steps from different calls never interleave. */
  function enqueue<T>(task: () => Promise<T>): Promise<T> {
    const result = queue.then(task);
    queue = result.catch(() => undefined);
    return result;
  }

  /**
   * Runs one API operation on the latest vault. Writes are saved only when the
   * operation succeeds; a failed operation leaves stored data untouched, and the
   * next call reloads from storage.
   */
  function run<T>(operation: (v: PersistedVault) => Promise<T>, options: { write?: boolean } = {}): Promise<T> {
    return enqueue(async () => {
      const v = await load();
      if (await sweepExpiredLeases(v)) save(v);
      const value = await operation(v);
      if (options.write) save(v);
      return value;
    });
  }

  function state(v: PersistedVault): VaultState {
    return {
      status: v.status,
      threshold: UNSEAL_THRESHOLD,
      totalShares: TOTAL_SHARES,
      sharesSubmitted: submittedShares.size,
      submittedShareIndexes: [...submittedShares.keys()].sort((a, b) => a - b),
      activeKekVersion: v.activeKekVersion,
      totalSecrets: v.secrets.length,
      activeLeases: v.leases.filter((lease) => lease.status === 'ACTIVE').length,
      isInitialized: true,
    };
  }

  function progress(v: PersistedVault): UnsealProgress {
    const unsealed = v.status === 'UNSEALED';
    const sharesSubmitted = unsealed ? UNSEAL_THRESHOLD : submittedShares.size;
    return {
      status: v.status,
      sharesSubmitted,
      submittedShareIndexes: [...submittedShares.keys()].sort((a, b) => a - b),
      threshold: UNSEAL_THRESHOLD,
      sharesRemaining: UNSEAL_THRESHOLD - sharesSubmitted,
      unsealed,
    };
  }

  function findSecret(v: PersistedVault, pathOrId: string) {
    return v.secrets.find((secret) => secret.path === pathOrId || secret.id === pathOrId);
  }

  return {
    status: () => run(async (v) => state(v)),

    demoShares: () => run(async (v) => ({ shares: [...v.demoShares] })),

    seal: () =>
      run(
        async (v) => {
          if (v.status === 'UNSEALED') {
            clearKeys();
            submittedShares.clear();
            v.status = 'SEALED';
            await recordAudit(v, {
              action: 'VAULT_SEAL',
              actor: 'security-operator',
              details: 'Vault sealed. The root key and KEKs were cleared from memory.',
            });
          }
          return { message: 'Vault sealed', state: state(v) };
        },
        { write: true }
      ),

    unseal: (share) =>
      run(
        async (v) => {
          if (typeof share !== 'string' || !share) throw badRequest('share is required and must be a string');
          let point;
          try {
            point = parseShare(share, KEY_BYTES);
          } catch (error) {
            throw badRequest(error instanceof Error ? error.message : 'Invalid share');
          }
          if (v.status === 'UNSEALED') return progress(v);
          if (submittedShares.has(point.x)) {
            throw conflict(`Share ${point.x} was already submitted. Use a different custodian share.`);
          }
          submittedShares.set(point.x, formatShare(point));
          if (submittedShares.size < UNSEAL_THRESHOLD) return progress(v);

          const shares = [...submittedShares.values()];
          submittedShares.clear();
          let candidate: Uint8Array | null = null;
          try {
            candidate = combineShares(shares);
            keks = await unwrapKeks(v, candidate);
            rootKey = candidate;
          } catch {
            candidate?.fill(0);
            await recordAudit(v, {
              action: 'VAULT_UNSEAL',
              actor: 'custodian',
              status: 'FAILED',
              details: 'Unseal failed: the submitted shares did not reconstruct the root key',
            });
            save(v);
            throw badRequest(
              'The submitted shares do not reconstruct the root key. Progress was reset, so submit three valid shares again.'
            );
          }
          v.status = 'UNSEALED';
          await recordAudit(v, {
            action: 'VAULT_UNSEAL',
            actor: 'custodian',
            details: `Vault unsealed with ${UNSEAL_THRESHOLD} custodian shares`,
          });
          return progress(v);
        },
        { write: true }
      ),

    resetUnseal: () =>
      run(async () => {
        submittedShares.clear();
        return { message: 'Unseal attempts reset' };
      }),

    rotateKek: () =>
      run(
        async (v): Promise<KekVersionInfo> => {
          requireKeys(v);
          const version = Math.max(...v.keks.map((k) => k.version)) + 1;
          const kek = randomBytes(KEY_BYTES);
          const createdAt = nowIso();
          const encryptedKek = await wrapKey(kek, rootKey!);
          for (const stored of v.keks) stored.isActive = false;
          v.keks.push({ version, encryptedKek, createdAt, isActive: true });
          v.activeKekVersion = version;
          keks.set(version, kek);
          await recordAudit(v, {
            action: 'KEK_ROTATE',
            actor: 'security-admin',
            details: `Active KEK rotated to version ${version}`,
          });
          return { version, createdAt, secretsCount: 0, isActive: true };
        },
        { write: true }
      ),

    rewrapSecrets: () =>
      run(
        async (v) => {
          const activeKek = requireKeys(v);
          let rewrappedCount = 0;
          for (const secret of v.secrets) {
            if (secret.kekVersion >= v.activeKekVersion) continue;
            const oldKek = keks.get(secret.kekVersion);
            if (!oldKek) throw new VaultError(500, `KEK v${secret.kekVersion} is not loaded`);
            const fromVersion = secret.kekVersion;
            secret.encryptedDek = await rewrapDek(secret.encryptedDek, oldKek, activeKek);
            secret.kekVersion = v.activeKekVersion;
            secret.updatedAt = nowIso();
            rewrappedCount++;
            await recordAudit(v, {
              action: 'SECRET_REWRAP',
              actor: 'security-admin',
              secretPath: secret.path,
              details: `Re-wrapped DEK from KEK v${fromVersion} to KEK v${v.activeKekVersion} without decrypting the secret`,
            });
          }
          return { rewrappedCount, activeVersion: v.activeKekVersion };
        },
        { write: true }
      ),

    keks: () =>
      run(async (v) =>
        [...v.keks]
          .sort((a, b) => b.version - a.version)
          .map((k) => ({
            version: k.version,
            createdAt: k.createdAt,
            secretsCount: v.secrets.filter((s) => s.kekVersion === k.version).length,
            isActive: k.isActive,
          }))
      ),

    secrets: () =>
      run(async (v) =>
        [...v.secrets].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).map((s) => ({ ...s }))
      ),

    readSecret: (path) =>
      run(
        async (v): Promise<DecryptedSecret> => {
          const query = parseSecretPath(path);
          requireKeys(v);
          const secret = findSecret(v, query);
          if (!secret) {
            await recordAudit(v, {
              action: 'SECRET_READ',
              actor: 'developer',
              status: 'DENIED',
              secretPath: query,
              details: `Secret not found at path: ${query}`,
            });
            save(v);
            throw notFound(`Secret not found at path "${query}"`);
          }
          const kek = keks.get(secret.kekVersion);
          if (!kek) throw new VaultError(500, `KEK v${secret.kekVersion} is not loaded`);
          const plaintext = await decryptEnvelope(secret, kek);

          let parsedData: Record<string, unknown> | undefined;
          try {
            parsedData = JSON.parse(plaintext);
          } catch {
            // Not JSON: return the plain string only.
          }

          let lease: SecretLease | undefined;
          let issued = false;
          if (secret.isDynamic) {
            const now = Date.now();
            lease = v.leases
              .filter((l) => l.secretId === secret.id && l.status === 'ACTIVE' && Date.parse(l.expiresAt) > now)
              .sort((a, b) => Date.parse(b.expiresAt) - Date.parse(a.expiresAt))[0];
            if (!lease) {
              lease = newLease(secret);
              v.leases.push(lease);
              issued = true;
            }
          }

          await recordAudit(v, {
            action: 'SECRET_READ',
            actor: 'developer',
            secretPath: secret.path,
            details: `Read and decrypted secret with KEK v${secret.kekVersion}`,
          });
          if (lease && issued) await auditLeaseIssued(v, lease, 'developer');

          return {
            id: secret.id,
            path: secret.path,
            name: secret.name,
            description: secret.description,
            kekVersion: secret.kekVersion,
            plaintext,
            ...(parsedData !== undefined ? { parsedData } : {}),
            version: secret.version,
            isDynamic: secret.isDynamic,
            ...(lease ? { lease: { ...lease } } : {}),
            createdAt: secret.createdAt,
            updatedAt: secret.updatedAt,
          };
        },
        { write: true }
      ),

    createSecret: (dto) => run((v) => createSecretIn(v, dto, 'developer'), { write: true }),

    deleteSecret: (path) =>
      run(
        async (v) => {
          const query = parseSecretPath(path);
          requireKeys(v);
          const secret = findSecret(v, query);
          if (!secret) throw notFound(`Secret not found at path "${query}"`);
          v.leases = v.leases.filter((lease) => lease.secretId !== secret.id);
          v.secrets = v.secrets.filter((s) => s.id !== secret.id);
          await recordAudit(v, {
            action: 'SECRET_DELETE',
            actor: 'developer',
            secretPath: secret.path,
            details: `Secret at path "${secret.path}" was permanently deleted`,
          });
          return { message: 'Secret deleted', path: secret.path };
        },
        { write: true }
      ),

    leases: () =>
      run(async (v) =>
        [...v.leases]
          .sort((a, b) => Date.parse(b.issuedAt) - Date.parse(a.issuedAt))
          .slice(0, MAX_LEASES_LISTED)
          .map((lease) => ({ ...lease }))
      ),

    renewLease: (id, incrementSeconds) =>
      run(
        async (v) => {
          const increment = parseRenewIncrement(incrementSeconds);
          requireKeys(v);
          const lease = v.leases.find((l) => l.id === id);
          if (!lease) throw notFound(`Lease "${id}" not found`);
          const maxTtlSeconds = v.secrets.find((s) => s.id === lease.secretId)?.maxTtlSeconds ?? 0;
          const renewal = planLeaseRenewal(lease, maxTtlSeconds, increment, Date.now());
          lease.expiresAt = renewal.expiresAt;
          lease.renewCount = renewal.renewCount;
          await recordAudit(v, {
            action: 'LEASE_RENEW',
            actor: 'client-app',
            secretPath: lease.secretPath,
            details: `Lease "${lease.id}" renewed (${renewal.renewCount}/${lease.maxRenewals}) until ${renewal.expiresAt}`,
          });
          return { ...lease };
        },
        { write: true }
      ),

    revokeLease: (id) =>
      run(
        async (v) => {
          requireKeys(v);
          const lease = v.leases.find((l) => l.id === id);
          if (!lease) throw notFound(`Lease "${id}" not found`);
          assertLeaseRevocable(lease);
          lease.status = 'REVOKED';
          lease.revokedAt = nowIso();
          await recordAudit(v, {
            action: 'LEASE_REVOKE',
            actor: 'client-app',
            secretPath: lease.secretPath,
            details: `Lease "${lease.id}" revoked by client-app`,
          });
          return { ...lease };
        },
        { write: true }
      ),

    audit: (limit = DEFAULT_AUDIT_LIMIT) =>
      run(async (v) => {
        const count = parseAuditLimit(limit);
        return v.audit.slice(-count).reverse().map((entry) => ({ ...entry }));
      }),

    verifyAudit: () =>
      run(async (v) => {
        const hashes = await Promise.all(auditChainInputs(v.audit).map((input) => sha256Hex(input)));
        return checkAuditChain(v.audit, hashes, nowIso());
      }),

    reset: () =>
      enqueue(async () => {
        getStorage().removeItem(DEMO_STORAGE_KEY);
        clearKeys();
        submittedShares.clear();
        vault = null;
      }),
  };
}

// Marked pure so builds without demo mode can drop this module entirely.
export const demoApi = /* @__PURE__ */ createDemoApi();
