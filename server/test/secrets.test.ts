import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { StoredSecret } from '../../shared/types.js';
import { createTestApp } from './helpers.js';

describe('secrets and key rotation API', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    t.close();
  });

  it('starts initialized and unsealed with KEK v1', async () => {
    const res = await t.request.get('/api/vault/status');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: 'UNSEALED',
      threshold: 3,
      totalShares: 5,
      sharesSubmitted: 0,
      activeKekVersion: 1,
      totalSecrets: 3,
      activeLeases: 1,
      isInitialized: true,
    });
    expect((await t.request.get('/health')).body).toEqual({ status: 'ok', service: 'vaultmesh' });
  });

  it('creates a secret, reads it by path and by id, and deletes it', async () => {
    const created = await t.request.post('/api/secrets').send({
      path: '/secret/custom/api_token/',
      name: 'Custom API token',
      description: 'Used by the integration tests',
      plaintext: 'example-token-not-real',
    });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ path: 'secret/custom/api_token', kekVersion: 1, isDynamic: false, version: 1 });
    expect(created.body.id).toMatch(/^sec_[0-9a-f]{16}$/);

    const byPath = await t.request.get('/api/secrets/secret/custom/api_token');
    expect(byPath.status).toBe(200);
    expect(byPath.body.plaintext).toBe('example-token-not-real');
    expect(byPath.body.parsedData).toBeUndefined();

    const byId = await t.request.get(`/api/secrets/${created.body.id}`);
    expect(byId.body.path).toBe('secret/custom/api_token');

    const deleted = await t.request.delete('/api/secrets/secret/custom/api_token');
    expect(deleted.status).toBe(200);
    expect(deleted.body).toEqual({ message: 'Secret deleted', path: 'secret/custom/api_token' });

    expect((await t.request.get('/api/secrets/secret/custom/api_token')).status).toBe(404);
  });

  it('parses JSON plaintext into parsedData on read', async () => {
    await t.request
      .post('/api/secrets')
      .send({ path: 'secret/json/config', name: 'Config', plaintext: { region: 'eu-north-1', replicas: 2 } })
      .expect(201);
    const read = await t.request.get('/api/secrets/secret/json/config');
    expect(read.body.parsedData).toEqual({ region: 'eu-north-1', replicas: 2 });
  });

  it('lists envelopes without plaintext', async () => {
    await t.request
      .post('/api/secrets')
      .send({ path: 'secret/list/check', name: 'List check', plaintext: 'never-in-list-output' })
      .expect(201);
    const list = await t.request.get('/api/secrets');
    expect(list.status).toBe(200);
    expect(JSON.stringify(list.body)).not.toContain('never-in-list-output');
    const item = list.body.find((s: StoredSecret) => s.path === 'secret/list/check');
    expect(item).not.toHaveProperty('plaintext');
    expect(item.encryptedDek.split(':')).toHaveLength(3);
    expect(list.body.map((s: StoredSecret) => s.path)).toEqual([...list.body.map((s: StoredSecret) => s.path)].sort());
  });

  it('removes the leases of a deleted dynamic secret', async () => {
    const before = (await t.request.get('/api/leases')).body.length;
    await t.request.delete('/api/secrets/secret/cloud/deploy-credential').expect(200);
    const after = await t.request.get('/api/leases');
    expect(after.body).toHaveLength(before - 1);
    expect((await t.request.get('/api/vault/status')).body.activeLeases).toBe(0);
  });

  it('rotates the KEK and re-wraps only secrets on older versions', async () => {
    const rotated = await t.request.post('/api/vault/keks/rotate');
    expect(rotated.status).toBe(200);
    expect(rotated.body).toMatchObject({ version: 2, isActive: true, secretsCount: 0 });

    // New secrets use the active KEK right away.
    await t.request.post('/api/secrets').send({ path: 'secret/after/rotation', name: 'After', plaintext: 'v2' }).expect(201);

    const keks = await t.request.get('/api/vault/keks');
    expect(keks.body).toMatchObject([
      { version: 2, isActive: true, secretsCount: 1 },
      { version: 1, isActive: false, secretsCount: 3 },
    ]);

    const rewrap = await t.request.post('/api/vault/keks/rewrap');
    expect(rewrap.status).toBe(200);
    expect(rewrap.body).toEqual({ rewrappedCount: 3, activeVersion: 2 });

    const again = await t.request.post('/api/vault/keks/rewrap');
    expect(again.body).toEqual({ rewrappedCount: 0, activeVersion: 2 });

    const read = await t.request.get('/api/secrets/secret/production/database');
    expect(read.body.kekVersion).toBe(2);
    expect(read.body.plaintext).toContain('orders-db.example.internal');
  });

  it('keeps secrets readable across several rotations before a re-wrap', async () => {
    await t.request.post('/api/vault/keks/rotate').expect(200);
    await t.request.post('/api/vault/keks/rotate').expect(200);
    const read = await t.request.get('/api/secrets/secret/payments/gateway');
    expect(read.status).toBe(200);
    expect(read.body.kekVersion).toBe(1);
    await t.request.post('/api/vault/keks/rewrap').expect(200);
    expect((await t.request.get('/api/secrets/secret/payments/gateway')).body.kekVersion).toBe(3);
  });

  it('blocks reads, writes and key operations while sealed but keeps metadata visible', async () => {
    const sealed = await t.request.post('/api/vault/seal');
    expect(sealed.body.state.status).toBe('SEALED');

    expect((await t.request.get('/api/secrets/secret/production/database')).status).toBe(503);
    expect((await t.request.delete('/api/secrets/secret/production/database')).status).toBe(503);
    const leases = await t.request.get('/api/leases');
    expect((await t.request.post(`/api/leases/${leases.body[0].id}/renew`).send({})).status).toBe(503);
    expect((await t.request.post(`/api/leases/${leases.body[0].id}/revoke`)).status).toBe(503);

    expect((await t.request.get('/api/secrets')).status).toBe(200);
    expect((await t.request.get('/api/vault/keks')).status).toBe(200);
    expect((await t.request.get('/api/audit/verify')).body.isValid).toBe(true);
  });
});
