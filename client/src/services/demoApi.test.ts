import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultError } from '../../../shared/errors';
import { SAMPLE_SECRETS } from '../../../shared/seed';
import type { SecretLease } from '../../../shared/types';
import { createDemoApi, DEMO_STORAGE_KEY, memoryStorage, type StorageLike } from './demoApi';

function setup(storage: StorageLike = memoryStorage()) {
  return { api: createDemoApi(() => storage), storage };
}

async function expectVaultError(promise: Promise<unknown>, status: number, message: RegExp) {
  const error = await promise.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (e: unknown) => e
  );
  expect(error).toBeInstanceOf(VaultError);
  expect((error as VaultError).status).toBe(status);
  expect((error as VaultError).message).toMatch(message);
}

async function unsealWithShares(api: ReturnType<typeof createDemoApi>, shares: string[]) {
  let last;
  for (const share of shares) last = await api.unseal(share);
  return last;
}

afterEach(() => {
  vi.useRealTimers();
});

describe('demo API', () => {
  it('creates a sample vault with the same seed data as the server', async () => {
    const { api } = setup();

    const state = await api.status();
    expect(state).toMatchObject({
      status: 'UNSEALED',
      threshold: 3,
      totalShares: 5,
      sharesSubmitted: 0,
      submittedShareIndexes: [],
      activeKekVersion: 1,
      totalSecrets: SAMPLE_SECRETS.length,
      activeLeases: 1,
      isInitialized: true,
    });

    const secrets = await api.secrets();
    expect(secrets.map((s) => s.path)).toEqual(SAMPLE_SECRETS.map((s) => s.path).sort());
    for (const secret of secrets) {
      expect(secret.iv).toMatch(/^[0-9a-f]{24}$/);
      expect(secret.authTag).toMatch(/^[0-9a-f]{32}$/);
      expect(secret.encryptedDek).toMatch(/^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]{64}$/);
      expect(JSON.stringify(secret)).not.toContain('example-password-not-real');
    }

    expect((await api.demoShares()).shares).toHaveLength(5);
    const verification = await api.verifyAudit();
    expect(verification.isValid).toBe(true);
    // VAULT_INIT, three SECRET_CREATE and one LEASE_ISSUE for the dynamic sample
    expect(verification.totalEntries).toBe(5);
  });

  it('creates, reads and deletes a secret', async () => {
    const { api } = setup();

    const created = await api.createSecret({ path: '/secret/demo/token/', name: 'Token', plaintext: '{"token":"example"}' });
    expect(created).toMatchObject({ path: 'secret/demo/token', kekVersion: 1, isDynamic: false, ttlSeconds: 0 });
    expect(created.id).toMatch(/^sec_[0-9a-f]{16}$/);

    const read = await api.readSecret('secret/demo/token');
    expect(read.plaintext).toBe('{"token":"example"}');
    expect(read.parsedData).toEqual({ token: 'example' });
    expect(read).not.toHaveProperty('lease');
    expect((await api.readSecret(created.id)).path).toBe('secret/demo/token');

    await expectVaultError(api.createSecret({ path: 'secret/demo/token', name: 'Again', plaintext: 'x' }), 409, /already exists/);

    expect(await api.deleteSecret('secret/demo/token')).toEqual({ message: 'Secret deleted', path: 'secret/demo/token' });
    await expectVaultError(api.readSecret('secret/demo/token'), 404, /not found/);
    await expectVaultError(api.deleteSecret('secret/demo/token'), 404, /not found/);

    const audit = await api.audit(3);
    expect(audit.map((e) => `${e.action}:${e.status}`)).toEqual([
      'SECRET_READ:DENIED',
      'SECRET_DELETE:SUCCESS',
      'SECRET_READ:SUCCESS',
    ]);
  });

  it('denies sensitive reads without approval when a purpose is supplied', async () => {
    const api = createDemoApi(() => memoryStorage());

    await expectVaultError(
      api.readSecret('secret/production/database', { purpose: 'Incident follow-up' }),
      403,
      /approval code/
    );
    const approved = await api.readSecret('secret/production/database', {
      purpose: 'Incident follow-up',
      approvalCode: 'VM-APPROVED',
    });

    expect(approved.access).toMatchObject({ status: 'ALLOWED', approvalCodeRequired: true });
    const audit = await api.audit(2);
    expect(audit.map((entry) => `${entry.action}:${entry.status}`)).toEqual(['SECRET_READ:SUCCESS', 'SECRET_READ:DENIED']);
  });

  it('rejects invalid input with the same messages as the API', async () => {
    const { api } = setup();
    await expectVaultError(api.createSecret({ path: '///', name: 'x', plaintext: 'y' }), 400, /path must not be empty/);
    await expectVaultError(
      api.createSecret({ path: 'secret/x', name: 'x', plaintext: 'y', isDynamic: true, ttlSeconds: 5 }),
      400,
      /ttlSeconds must be a whole number between 10/
    );
    await expectVaultError(api.readSecret('secret/a b'), 400, /segments/);
    await expectVaultError(api.audit(0), 400, /limit/);
    await expectVaultError(api.unseal('nope'), 400, /Invalid share format/);
    expect((await api.secrets()).length).toBe(SAMPLE_SECRETS.length);
  });

  it('blocks key operations while sealed and unseals with any three shares', async () => {
    const { api } = setup();
    const { shares } = await api.demoShares();

    const sealed = await api.seal();
    expect(sealed).toMatchObject({ message: 'Vault sealed', state: { status: 'SEALED' } });

    await expectVaultError(api.readSecret('secret/production/database'), 503, /sealed/);
    await expectVaultError(api.rotateKek(), 503, /sealed/);
    await expectVaultError(api.createSecret({ path: 'secret/x', name: 'x', plaintext: 'y' }), 503, /sealed/);
    expect((await api.secrets()).length).toBe(SAMPLE_SECRETS.length);

    expect(await api.unseal(shares[4])).toMatchObject({ sharesSubmitted: 1, submittedShareIndexes: [5], unsealed: false });
    await expectVaultError(api.unseal(shares[4]), 409, /Share 5 was already submitted/);
    const progress = await unsealWithShares(api, [shares[1], shares[2]]);
    expect(progress).toMatchObject({ status: 'UNSEALED', unsealed: true, sharesRemaining: 0 });

    const read = await api.readSecret('secret/production/database');
    expect(read.plaintext).toContain('orders-db.example.internal');
  });

  it('resets unseal progress after a forged share', async () => {
    const { api } = setup();
    const { shares } = await api.demoShares();
    await api.seal();

    await unsealWithShares(api, [shares[0], shares[1]]);
    await expectVaultError(api.unseal(`vmshare-03-${'ab'.repeat(32)}`), 400, /do not reconstruct the root key/);
    expect(await api.status()).toMatchObject({ status: 'SEALED', sharesSubmitted: 0 });

    await api.unseal(shares[0]);
    await api.resetUnseal();
    expect((await api.status()).sharesSubmitted).toBe(0);

    expect(await unsealWithShares(api, [shares[2], shares[3], shares[4]])).toMatchObject({ unsealed: true });
    const audit = await api.audit(3);
    expect(audit.map((e) => `${e.action}:${e.status}`)).toEqual(['VAULT_UNSEAL:SUCCESS', 'VAULT_UNSEAL:FAILED', 'VAULT_SEAL:SUCCESS']);
  });

  it('rotates the KEK and re-wraps secrets without changing their ciphertext', async () => {
    const { api } = setup();
    const before = await api.secrets();

    expect(await api.rotateKek()).toMatchObject({ version: 2, isActive: true, secretsCount: 0 });
    expect(await api.keks()).toMatchObject([
      { version: 2, isActive: true, secretsCount: 0 },
      { version: 1, isActive: false, secretsCount: 3 },
    ]);

    expect(await api.rewrapSecrets()).toEqual({ rewrappedCount: 3, activeVersion: 2 });
    expect(await api.rewrapSecrets()).toEqual({ rewrappedCount: 0, activeVersion: 2 });

    const after = await api.secrets();
    for (const secret of after) {
      const old = before.find((s) => s.id === secret.id)!;
      expect(secret.kekVersion).toBe(2);
      expect(secret.ciphertext).toBe(old.ciphertext);
      expect(secret.encryptedDek).not.toBe(old.encryptedDek);
    }
    expect((await api.readSecret('secret/payments/gateway')).plaintext).toContain('example-api-key-not-real');
  });

  it('applies lease limits, expires leases and issues a new lease on read', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const start = Date.parse('2026-09-13T10:00:00.000Z');
    vi.setSystemTime(start);
    const { api } = setup();

    await api.createSecret({ path: 'secret/demo/dynamic', name: 'Dynamic', plaintext: 'x', isDynamic: true, ttlSeconds: 10, maxTtlSeconds: 25 });
    const lease = (await api.leases()).find((l) => l.secretPath === 'secret/demo/dynamic') as SecretLease;
    expect(lease).toMatchObject({ status: 'ACTIVE', ttlSeconds: 10, renewCount: 0 });

    const renewed = await api.renewLease(lease.id, 30);
    expect(Date.parse(renewed.expiresAt) - start).toBe(25_000);
    await expectVaultError(api.renewLease(lease.id, 30), 409, /max TTL of 25 seconds/);
    await expectVaultError(api.renewLease(lease.id, 0), 400, /incrementSeconds/);
    await expectVaultError(api.renewLease('lease_missing', 5), 404, /not found/);

    vi.setSystemTime(start + 26_000);
    const leases = await api.leases();
    expect(leases.find((l) => l.id === lease.id)?.status).toBe('EXPIRED');
    await expectVaultError(api.revokeLease(lease.id), 409, /status "EXPIRED"/);

    const read = await api.readSecret('secret/demo/dynamic');
    expect(read.lease).toMatchObject({ status: 'ACTIVE', renewCount: 0 });
    expect(read.lease?.id).not.toBe(lease.id);
    expect((await api.readSecret('secret/demo/dynamic')).lease?.id).toBe(read.lease?.id);

    const revoked = await api.revokeLease(read.lease!.id);
    expect(revoked.status).toBe('REVOKED');
    expect(revoked.revokedAt).toBeTruthy();

    const actions = (await api.audit(50)).filter((e) => e.secretPath === 'secret/demo/dynamic').map((e) => e.action).reverse();
    expect(actions).toEqual([
      'SECRET_CREATE',
      'LEASE_ISSUE',
      'LEASE_RENEW',
      'LEASE_EXPIRE',
      'SECRET_READ',
      'LEASE_ISSUE',
      'SECRET_READ',
      'LEASE_REVOKE',
    ]);
    expect((await api.verifyAudit()).isValid).toBe(true);
  });

  it('persists the vault and restores it like a server restart', async () => {
    const storage = memoryStorage();
    const first = createDemoApi(() => storage);
    await first.createSecret({ path: 'secret/demo/kept', name: 'Kept', plaintext: 'still here' });
    await first.rotateKek();

    const second = createDemoApi(() => storage);
    expect((await second.readSecret('secret/demo/kept')).plaintext).toBe('still here');
    expect((await second.status()).activeKekVersion).toBe(2);

    await second.seal();
    const third = createDemoApi(() => storage);
    expect((await third.status()).status).toBe('SEALED');
    expect(JSON.parse(storage.getItem(DEMO_STORAGE_KEY)!).secrets.some((s: { plaintext?: string }) => 'plaintext' in s)).toBe(false);
  });

  it('picks up changes made by another tab', async () => {
    const storage = memoryStorage();
    const tabA = createDemoApi(() => storage);
    const tabB = createDemoApi(() => storage);
    await tabA.status();

    await tabB.rotateKek();
    await tabB.createSecret({ path: 'secret/demo/from-b', name: 'From B', plaintext: 'hello' });

    expect((await tabA.readSecret('secret/demo/from-b')).plaintext).toBe('hello');
    await tabA.seal();
    await expectVaultError(tabB.readSecret('secret/demo/from-b'), 503, /sealed/);
    expect((await tabB.verifyAudit()).isValid).toBe(true);
  });

  it('detects tampering with the stored audit log', async () => {
    const { api, storage } = setup();
    await api.status();
    const stored = JSON.parse(storage.getItem(DEMO_STORAGE_KEY)!);
    stored.audit[2].details = 'nothing happened';
    storage.setItem(DEMO_STORAGE_KEY, JSON.stringify(stored));

    expect(await api.verifyAudit()).toMatchObject({ isValid: false, brokenIndex: 2 });
  });

  it('starts over when stored data is corrupt, and on reset', async () => {
    const storage = memoryStorage();
    storage.setItem(DEMO_STORAGE_KEY, '{not json');
    const api = createDemoApi(() => storage);
    expect((await api.status()).totalSecrets).toBe(SAMPLE_SECRETS.length);

    const sharesBefore = (await api.demoShares()).shares;
    await api.createSecret({ path: 'secret/demo/temp', name: 'Temp', plaintext: 'x' });
    await api.reset();
    expect((await api.status()).totalSecrets).toBe(SAMPLE_SECRETS.length);
    expect((await api.demoShares()).shares).not.toEqual(sharesBefore);
  });

  it('keeps every write when calls overlap', async () => {
    const { api } = setup();
    await Promise.all(
      Array.from({ length: 6 }, (_, i) => api.createSecret({ path: `secret/parallel/s${i}`, name: `S${i}`, plaintext: `v${i}` }))
    );
    expect((await api.secrets()).filter((s) => s.path.startsWith('secret/parallel/'))).toHaveLength(6);
    expect((await api.verifyAudit()).isValid).toBe(true);
  });

  it('keeps working when localStorage is unavailable', async () => {
    const broken: StorageLike = {
      getItem: () => null,
      setItem: () => {
        throw new DOMException('Quota exceeded', 'QuotaExceededError');
      },
      removeItem: () => {},
    };
    const api = createDemoApi(() => broken);
    await api.createSecret({ path: 'secret/demo/memory', name: 'Memory', plaintext: 'kept in memory' });
    expect((await api.readSecret('secret/demo/memory')).plaintext).toBe('kept in memory');
  });
});
