import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp } from './helpers.js';

describe('API input validation', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    t.close();
  });

  it.each([
    [{ path: 123, name: 'x', plaintext: 'y' }, /path must be a string/],
    [{ path: '///', name: 'x', plaintext: 'y' }, /path must not be empty/],
    [{ path: 'secret/a b', name: 'x', plaintext: 'y' }, /segments/],
    [{ path: 'secret/ok', plaintext: 'y' }, /name is required/],
    [{ path: 'secret/ok', name: 'x', plaintext: 'y', isDynamic: 'false' }, /isDynamic/],
    [{ path: 'secret/ok', name: 'x', plaintext: 'y', isDynamic: true, ttlSeconds: -50 }, /ttlSeconds/],
  ])('rejects create body %j with 400', async (body, message) => {
    const res = await t.request.post('/api/secrets').send(body);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(message);
  });

  it('does not store anything for a rejected body', async () => {
    const before = await t.request.get('/api/secrets');
    await t.request.post('/api/secrets').send({ path: '///', name: 'x', plaintext: 'y' }).expect(400);
    const after = await t.request.get('/api/secrets');
    expect(after.body).toHaveLength(before.body.length);
  });

  it('rejects oversized request bodies with 413', async () => {
    const res = await t.request
      .post('/api/secrets')
      .send({ path: 'secret/big', name: 'Big', plaintext: 'x'.repeat(200 * 1024) });
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ error: 'Request body is too large' });
  });

  it('rejects secret reads with an invalid path', async () => {
    const res = await t.request.get('/api/secrets/secret/a%20b');
    expect(res.status).toBe(400);
  });

  it('rejects invalid lease renewal increments', async () => {
    const leases = await t.request.get('/api/leases');
    const leaseId = leases.body[0].id;

    for (const incrementSeconds of ['abc', -100000, 0, 3601]) {
      const res = await t.request.post(`/api/leases/${leaseId}/renew`).send({ incrementSeconds });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/incrementSeconds/);
    }

    const unchanged = await t.request.get('/api/leases');
    expect(unchanged.body[0].expiresAt).toBe(leases.body[0].expiresAt);
    expect(unchanged.body[0].renewCount).toBe(0);
  });

  it('validates the audit limit query', async () => {
    expect((await t.request.get('/api/audit?limit=abc')).status).toBe(400);
    expect((await t.request.get('/api/audit?limit=-1')).status).toBe(400);
    const ok = await t.request.get('/api/audit?limit=2');
    expect(ok.status).toBe(200);
    expect(ok.body).toHaveLength(2);
  });

  it('sanitizes the self-reported actor header before writing the audit log', async () => {
    await t.request
      .post('/api/vault/keks/rotate')
      .set('x-actor', `mallory${'x'.repeat(100)}`)
      .expect(200);
    const audit = await t.request.get('/api/audit?limit=1');
    expect(audit.body[0].action).toBe('KEK_ROTATE');
    expect(audit.body[0].actor).toHaveLength(64);
  });
});
