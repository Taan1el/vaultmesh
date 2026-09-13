import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { EnvelopeEncryption } from '../src/crypto/envelope.js';
import { GENESIS_HASH, auditChainInputs, checkAuditChain } from '../../shared/audit.js';
import type { AuditEntry } from '../../shared/types.js';
import { createTestApp } from './helpers.js';

const sha256 = (input: string) => crypto.createHash('sha256').update(input).digest('hex');

describe('audit hash chain', () => {
  it('keeps the original serialization so existing ledgers still verify', () => {
    const payload = {
      id: 'aud_1',
      timestamp: '2026-09-10T10:00:00.000Z',
      action: 'SECRET_READ' as const,
      secretPath: 'secret/a',
      actor: 'developer',
      ip: '127.0.0.1',
      status: 'SUCCESS' as const,
      details: 'Read secret',
    };
    const legacySerialized = JSON.stringify(payload, Object.keys(payload).sort());
    expect(EnvelopeEncryption.computeAuditHash(GENESIS_HASH, payload)).toBe(sha256(`${GENESIS_HASH}|${legacySerialized}`));
  });

  it('flags the first entry whose link or hash does not match', () => {
    const entries: AuditEntry[] = [];
    let previous = GENESIS_HASH;
    for (let i = 0; i < 3; i++) {
      const fields = {
        id: `aud_${i}`,
        timestamp: `2026-09-10T10:00:0${i}.000Z`,
        action: 'KEK_ROTATE' as const,
        actor: 'admin',
        ip: '127.0.0.1',
        status: 'SUCCESS' as const,
        details: `rotation ${i}`,
      };
      const entryHash = EnvelopeEncryption.computeAuditHash(previous, fields);
      entries.push({ ...fields, previousHash: previous, entryHash });
      previous = entryHash;
    }

    const verify = (list: AuditEntry[]) => checkAuditChain(list, auditChainInputs(list).map(sha256), 'now');
    expect(verify(entries)).toEqual({ isValid: true, totalEntries: 3, verifiedAt: 'now' });
    expect(verify([])).toEqual({ isValid: true, totalEntries: 0, verifiedAt: 'now' });

    const edited = entries.map((e, i) => (i === 1 ? { ...e, details: 'rotation 1 (edited)' } : e));
    expect(verify(edited)).toMatchObject({ isValid: false, brokenIndex: 1 });

    expect(verify([entries[0], entries[2]])).toMatchObject({ isValid: false, brokenIndex: 1 });
    expect(verify([entries[1], entries[0], entries[2]])).toMatchObject({ isValid: false, brokenIndex: 0 });
  });
});

describe('audit API', () => {
  let t: ReturnType<typeof createTestApp>;

  beforeEach(() => {
    t = createTestApp();
  });

  afterEach(() => {
    t.close();
  });

  it('returns newest entries first and never includes secret values', async () => {
    await t.request
      .post('/api/secrets')
      .send({ path: 'secret/audit/check', name: 'Audit check', plaintext: 'do-not-log-this-value' })
      .expect(201);
    await t.request.get('/api/secrets/secret/audit/check').expect(200);

    const audit = await t.request.get('/api/audit?limit=200');
    expect(audit.body[0]).toMatchObject({ action: 'SECRET_READ', secretPath: 'secret/audit/check' });
    expect(audit.body[1]).toMatchObject({ action: 'SECRET_CREATE', secretPath: 'secret/audit/check' });
    expect(JSON.stringify(audit.body)).not.toContain('do-not-log-this-value');
  });

  it('detects an edited audit row', async () => {
    t.db.getDb().prepare("UPDATE audit_log SET details = 'nothing happened' WHERE rowid = 2").run();
    const res = await t.request.get('/api/audit/verify');
    expect(res.body).toMatchObject({ isValid: false, brokenIndex: 1 });
  });

  it('detects a deleted audit row', async () => {
    t.db.getDb().prepare('DELETE FROM audit_log WHERE rowid = 3').run();
    const res = await t.request.get('/api/audit/verify');
    expect(res.body).toMatchObject({ isValid: false, brokenIndex: 2 });
  });
});
