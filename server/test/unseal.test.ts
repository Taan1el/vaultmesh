import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { createTestApp } from './helpers.js';

describe('custodian unseal flow', () => {
  let t: ReturnType<typeof createTestApp>;
  let shares: string[];

  beforeEach(async () => {
    t = createTestApp();
    shares = (await t.request.get('/api/vault/demo-shares')).body.shares;
    await t.request.post('/api/vault/seal').expect(200);
  });

  afterEach(() => {
    t.close();
  });

  const submit = (share: string) => t.request.post('/api/vault/unseal').send({ share });

  it('reports which share indexes were submitted', async () => {
    const res = await submit(shares[3]);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: 'SEALED',
      sharesSubmitted: 1,
      submittedShareIndexes: [4],
      sharesRemaining: 2,
      unsealed: false,
    });

    const state = await t.request.get('/api/vault/status');
    expect(state.body.submittedShareIndexes).toEqual([4]);
  });

  it('rejects the same share index twice, even with different letter case', async () => {
    await submit(shares[0]).expect(200);

    const again = await submit(shares[0]);
    expect(again.status).toBe(409);
    expect(again.body.error).toMatch(/Share 1 was already submitted/);

    const upper = await submit(`vmshare-01-${shares[0].slice('vmshare-01-'.length).toUpperCase()}`);
    expect(upper.status).toBe(409);

    const state = await t.request.get('/api/vault/status');
    expect(state.body.sharesSubmitted).toBe(1);
  });

  it('rejects shares that are too short without counting them', async () => {
    const res = await submit('vmshare-02-abc123');
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/32 bytes/);
    expect((await t.request.get('/api/vault/status')).body.sharesSubmitted).toBe(0);
  });

  it('resets progress after a forged share so valid shares can unseal afterwards', async () => {
    const forged = `vmshare-04-${crypto.randomBytes(32).toString('hex')}`;
    await submit(shares[0]).expect(200);
    await submit(shares[1]).expect(200);

    const failed = await submit(forged);
    expect(failed.status).toBe(400);
    expect(failed.body.error).toMatch(/do not reconstruct the root key/);
    expect(failed.body.error).not.toMatch(/authenticate|Unsupported state/);

    const state = await t.request.get('/api/vault/status');
    expect(state.body).toMatchObject({ status: 'SEALED', sharesSubmitted: 0, submittedShareIndexes: [] });

    await submit(shares[0]).expect(200);
    await submit(shares[2]).expect(200);
    const unsealed = await submit(shares[4]);
    expect(unsealed.status).toBe(200);
    expect(unsealed.body).toMatchObject({ status: 'UNSEALED', unsealed: true, sharesRemaining: 0 });

    const read = await t.request.get('/api/secrets/secret/production/database');
    expect(read.status).toBe(200);
  });

  it('records failed and successful unseal attempts in the audit log', async () => {
    await submit(shares[0]);
    await submit(shares[1]);
    await submit(`vmshare-03-${crypto.randomBytes(32).toString('hex')}`);
    await submit(shares[0]);
    await submit(shares[1]);
    await submit(shares[2]);

    const audit = await t.request.get('/api/audit?limit=2');
    expect(audit.body.map((e: { action: string; status: string }) => `${e.action}:${e.status}`)).toEqual([
      'VAULT_UNSEAL:SUCCESS',
      'VAULT_UNSEAL:FAILED',
    ]);
    expect((await t.request.get('/api/audit/verify')).body.isValid).toBe(true);
  });

  it('clears submitted shares with the reset endpoint', async () => {
    await submit(shares[0]).expect(200);
    await t.request.post('/api/vault/unseal/reset').expect(200);
    expect((await t.request.get('/api/vault/status')).body.sharesSubmitted).toBe(0);
    await submit(shares[0]).expect(200);
  });
});
