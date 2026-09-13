import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecretLease } from '../../shared/types.js';
import { VaultError } from '../../shared/errors.js';
import { isLeaseExpired, planLeaseRenewal } from '../../shared/leases.js';
import { createTestApp } from './helpers.js';

const T0 = Date.parse('2026-01-01T00:00:00.000Z');

function lease(overrides: Partial<SecretLease> = {}): SecretLease {
  return {
    id: 'lease_test',
    secretId: 'sec_test',
    secretPath: 'secret/test',
    issuedAt: new Date(T0).toISOString(),
    expiresAt: new Date(T0 + 60_000).toISOString(),
    ttlSeconds: 60,
    renewCount: 0,
    maxRenewals: 5,
    status: 'ACTIVE',
    ...overrides,
  };
}

function expectConflict(fn: () => unknown, message: RegExp) {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultError).status).toBe(409);
    expect((error as VaultError).message).toMatch(message);
    return;
  }
  throw new Error('expected a 409 VaultError');
}

describe('planLeaseRenewal', () => {
  it('adds the increment to the current expiry', () => {
    const plan = planLeaseRenewal(lease(), 300, 30, T0 + 10_000);
    expect(plan).toEqual({ expiresAt: new Date(T0 + 90_000).toISOString(), renewCount: 1 });
  });

  it('caps the new expiry at issuedAt plus max TTL', () => {
    const plan = planLeaseRenewal(lease(), 75, 30, T0 + 10_000);
    expect(plan.expiresAt).toBe(new Date(T0 + 75_000).toISOString());
  });

  it('treats a max TTL of 0 as no cap', () => {
    const plan = planLeaseRenewal(lease(), 0, 3600, T0);
    expect(plan.expiresAt).toBe(new Date(T0 + 3_660_000).toISOString());
  });

  it('refuses leases that reached the max TTL', () => {
    const atCap = lease({ expiresAt: new Date(T0 + 120_000).toISOString() });
    expectConflict(() => planLeaseRenewal(atCap, 120, 30, T0 + 1_000), /max TTL of 120 seconds/);
  });

  it('refuses expired, revoked and exhausted leases', () => {
    expectConflict(() => planLeaseRenewal(lease(), 300, 30, T0 + 60_000), /already expired/);
    expectConflict(() => planLeaseRenewal(lease({ status: 'REVOKED' }), 300, 30, T0), /status "REVOKED"/);
    expectConflict(() => planLeaseRenewal(lease({ status: 'EXPIRED' }), 300, 30, T0), /status "EXPIRED"/);
    expectConflict(() => planLeaseRenewal(lease({ renewCount: 5 }), 300, 30, T0), /Maximum renewal count \(5\)/);
  });

  it('detects expired leases that have not been swept yet', () => {
    expect(isLeaseExpired(lease(), T0 + 59_999)).toBe(false);
    expect(isLeaseExpired(lease(), T0 + 60_000)).toBe(true);
    expect(isLeaseExpired(lease({ status: 'REVOKED' }), T0 + 120_000)).toBe(false);
  });
});

describe('lease API', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    vi.useRealTimers();
    t.close();
  });

  async function createDynamic(path: string, ttlSeconds: number, maxTtlSeconds: number) {
    await t.request
      .post('/api/secrets')
      .send({ path, name: path, plaintext: '{"user":"demo"}', isDynamic: true, ttlSeconds, maxTtlSeconds })
      .expect(201);
    const leases = await t.request.get('/api/leases');
    return leases.body.find((l: SecretLease) => l.secretPath === path) as SecretLease;
  }

  it('issues a lease when a dynamic secret is created', async () => {
    const created = await createDynamic('secret/dyn/create', 20, 100);
    expect(created).toMatchObject({ status: 'ACTIVE', ttlSeconds: 20, renewCount: 0, maxRenewals: 5 });
    expect(Date.parse(created.expiresAt) - Date.parse(created.issuedAt)).toBe(20_000);

    const audit = await t.request.get('/api/audit?limit=2');
    expect(audit.body.map((e: { action: string }) => e.action)).toEqual(['LEASE_ISSUE', 'SECRET_CREATE']);
  });

  it('caps renewals at the secret max TTL, then refuses further renewals', async () => {
    const created = await createDynamic('secret/dyn/cap', 10, 25);

    const first = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 30 });
    expect(first.status).toBe(200);
    expect(Date.parse(first.body.expiresAt) - Date.parse(created.issuedAt)).toBe(25_000);

    const second = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 30 });
    expect(second.status).toBe(409);
    expect(second.body.error).toMatch(/max TTL of 25 seconds/);
  });

  it('refuses renewal after the maximum renewal count', async () => {
    const created = await createDynamic('secret/dyn/count', 10, 86400);
    for (let i = 1; i <= 5; i++) {
      const res = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 1 });
      expect(res.body.renewCount).toBe(i);
    }
    const sixth = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 1 });
    expect(sixth.status).toBe(409);
    expect(sixth.body.error).toMatch(/Maximum renewal count/);
  });

  it('refuses to renew a lease whose expiry has passed', async () => {
    const created = await createDynamic('secret/dyn/late', 10, 100);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse(created.expiresAt) + 1_000);

    const res = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 5 });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/expired/i);
  });

  it('only revokes active leases', async () => {
    const created = await createDynamic('secret/dyn/revoke', 10, 100);
    const revoked = await t.request.post(`/api/leases/${created.id}/revoke`);
    expect(revoked.status).toBe(200);
    expect(revoked.body).toMatchObject({ status: 'REVOKED' });
    expect(revoked.body.revokedAt).toBeTruthy();

    const again = await t.request.post(`/api/leases/${created.id}/revoke`);
    expect(again.status).toBe(409);
    expect(again.body.error).toMatch(/status "REVOKED"/);

    const renew = await t.request.post(`/api/leases/${created.id}/renew`).send({ incrementSeconds: 5 });
    expect(renew.status).toBe(409);
  });

  it('marks expired leases in the sweep and issues a new lease on the next read', async () => {
    const created = await createDynamic('secret/dyn/reissue', 10, 100);
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse(created.expiresAt) + 1_000);

    expect(t.service.sweepExpiredLeases()).toBeGreaterThanOrEqual(1);
    const afterSweep = await t.request.get('/api/leases');
    expect(afterSweep.body.find((l: SecretLease) => l.id === created.id).status).toBe('EXPIRED');

    const read = await t.request.get('/api/secrets/secret/dyn/reissue');
    expect(read.status).toBe(200);
    expect(read.body.lease).toMatchObject({ status: 'ACTIVE', ttlSeconds: 10, renewCount: 0 });
    expect(read.body.lease.id).not.toBe(created.id);

    // A second read reuses the lease issued by the first one.
    const reread = await t.request.get('/api/secrets/secret/dyn/reissue');
    expect(reread.body.lease.id).toBe(read.body.lease.id);

    const audit = await t.request.get('/api/audit?limit=50');
    const actions = audit.body
      .filter((e: { secretPath?: string }) => e.secretPath === 'secret/dyn/reissue')
      .map((e: { action: string }) => e.action)
      .reverse();
    expect(actions).toEqual(['SECRET_CREATE', 'LEASE_ISSUE', 'LEASE_EXPIRE', 'SECRET_READ', 'LEASE_ISSUE', 'SECRET_READ']);
    expect((await t.request.get('/api/audit/verify')).body.isValid).toBe(true);
  });

  it('does not attach leases to static secrets', async () => {
    const read = await t.request.get('/api/secrets/secret/production/database');
    expect(read.status).toBe(200);
    expect(read.body.lease).toBeUndefined();
  });
});
