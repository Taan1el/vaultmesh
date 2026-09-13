import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestApp } from './helpers.js';

describe('API error responses', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    t.close();
  });

  it('answers malformed JSON with a 400 JSON error and no stack trace', async () => {
    const res = await t.request
      .post('/api/secrets')
      .set('Content-Type', 'application/json')
      .send('{"path": "secret/a", "plaintext": "hunter2"');

    expect(res.status).toBe(400);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toEqual({ error: 'Request body must be valid JSON' });
    expect(res.text).not.toMatch(/at |node_modules|hunter2/);
  });

  it('answers unknown API routes with a 404 JSON error', async () => {
    const res = await t.request.get('/api/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
  });

  it('hides unexpected internal errors behind a generic 500', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(t.service, 'listSecrets').mockImplementation(() => {
      throw new Error('SQLITE_CORRUPT: database disk image is malformed');
    });

    const res = await t.request.get('/api/secrets');

    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Internal server error' });
    expect(consoleError).toHaveBeenCalled();
  });

  it('returns 503 for key operations while sealed', async () => {
    await t.request.post('/api/vault/seal').expect(200);

    for (const call of [
      t.request.post('/api/vault/keks/rotate'),
      t.request.post('/api/vault/keks/rewrap'),
      t.request.post('/api/secrets').send({ path: 'secret/a', name: 'A', plaintext: 'x' }),
    ]) {
      const res = await call;
      expect(res.status).toBe(503);
      expect(res.body.error).toMatch(/sealed/i);
    }
  });

  it('returns 404 for unknown secrets and leases', async () => {
    const secret = await t.request.get('/api/secrets/secret/missing');
    expect(secret.status).toBe(404);

    const deleted = await t.request.delete('/api/secrets/secret/missing');
    expect(deleted.status).toBe(404);

    const renew = await t.request.post('/api/leases/lease_missing/renew').send({ incrementSeconds: 30 });
    expect(renew.status).toBe(404);

    const revoke = await t.request.post('/api/leases/lease_missing/revoke');
    expect(revoke.status).toBe(404);
  });

  it('returns 409 when a secret path already exists', async () => {
    const body = { path: 'secret/dup', name: 'Dup', plaintext: 'x' };
    await t.request.post('/api/secrets').send(body).expect(201);
    const res = await t.request.post('/api/secrets').send(body);
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already exists/);
  });

  it('rejects a share with the wrong format as a 400', async () => {
    await t.request.post('/api/vault/seal').expect(200);
    const res = await t.request.post('/api/vault/unseal').send({ share: 'not-a-share' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/share/i);
  });
});
