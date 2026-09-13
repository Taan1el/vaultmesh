import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createTestApp } from './helpers.js';

describe('vault state across restarts', () => {
  let dir: string;
  let dbPath: string;
  const open: Array<ReturnType<typeof createTestApp>> = [];

  const start = () => {
    const t = createTestApp(dbPath);
    open.push(t);
    return t;
  };

  const stop = (t: ReturnType<typeof createTestApp>) => {
    t.close();
    open.splice(open.indexOf(t), 1);
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultmesh-test-'));
    dbPath = path.join(dir, 'vault.db');
  });

  afterEach(() => {
    for (const t of open.splice(0)) t.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('keeps a sealed vault sealed after a restart', async () => {
    const first = start();
    const shares: string[] = (await first.request.get('/api/vault/demo-shares')).body.shares;
    await first.request.post('/api/vault/seal').expect(200);
    stop(first);

    const second = start();
    const status = await second.request.get('/api/vault/status');
    expect(status.body.status).toBe('SEALED');
    expect((await second.request.get('/api/secrets/secret/production/database')).status).toBe(503);

    for (const share of shares.slice(0, 3)) {
      await second.request.post('/api/vault/unseal').send({ share }).expect(200);
    }
    expect((await second.request.get('/api/secrets/secret/production/database')).status).toBe(200);
    stop(second);

    const third = start();
    expect((await third.request.get('/api/vault/status')).body.status).toBe('UNSEALED');
  });

  it('keeps stored secrets readable after a restart', async () => {
    const first = start();
    await first.request
      .post('/api/secrets')
      .send({ path: 'secret/restart/check', name: 'Restart check', plaintext: 'still here' })
      .expect(201);
    await first.request.post('/api/vault/keks/rotate').expect(200);
    stop(first);

    const second = start();
    const read = await second.request.get('/api/secrets/secret/restart/check');
    expect(read.status).toBe(200);
    expect(read.body.plaintext).toBe('still here');
    expect((await second.request.get('/api/vault/status')).body.activeKekVersion).toBe(2);
  });

  it('does not add an audit entry when sealing an already sealed vault', async () => {
    const t = start();
    await t.request.post('/api/vault/seal').expect(200);
    const before = (await t.request.get('/api/audit/verify')).body.totalEntries;
    const again = await t.request.post('/api/vault/seal');
    expect(again.status).toBe(200);
    expect(again.body.state.status).toBe('SEALED');
    expect((await t.request.get('/api/audit/verify')).body.totalEntries).toBe(before);
  });
});
