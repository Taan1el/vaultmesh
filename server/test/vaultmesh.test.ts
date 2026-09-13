import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import supertest from 'supertest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createApp } from '../src/app.js';
import { ShamirSecretSharing } from '../src/crypto/shamir.js';
import { EnvelopeEncryption } from '../src/crypto/envelope.js';

describe('VaultMesh Core Test Suite', () => {
  const testDbPath = path.resolve(process.cwd(), 'data', `test-vault-${Date.now()}.db`);
  let instance: ReturnType<typeof createApp>;
  let request: supertest.SuperTest<supertest.Test>;

  beforeEach(() => {
    instance = createApp(testDbPath);
    request = supertest(instance.app);
  });

  afterEach(() => {
    instance.service.destroy();
    instance.db.close();
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch {}
    }
  });

  describe('1. Shamir Secret Sharing (GF(256) Polynomial Threshold)', () => {
    it('should split a 32-byte key into 5 shares and reconstruct with any 3 shares', () => {
      const originalKey = crypto.randomBytes(32);
      const shares = ShamirSecretSharing.split(originalKey, 5, 3);
      expect(shares).toHaveLength(5);

      // Reconstruct with shares [0, 2, 4]
      const recovered1 = ShamirSecretSharing.combine([shares[0], shares[2], shares[4]]);
      expect(recovered1).toEqual(originalKey);

      // Reconstruct with shares [1, 2, 3]
      const recovered2 = ShamirSecretSharing.combine([shares[1], shares[2], shares[3]]);
      expect(recovered2).toEqual(originalKey);

      // Reconstruct with 4 shares
      const recovered3 = ShamirSecretSharing.combine([shares[0], shares[1], shares[3], shares[4]]);
      expect(recovered3).toEqual(originalKey);
    });

    it('should reject invalid share strings or duplicate shares', () => {
      expect(() => ShamirSecretSharing.parseShare('invalid-share')).toThrow();

      const key = crypto.randomBytes(32);
      const shares = ShamirSecretSharing.split(key, 5, 3);
      expect(() => ShamirSecretSharing.combine([shares[0], shares[0], shares[1]])).toThrow(/Duplicate/);
    });
  });

  describe('2. Envelope Encryption & Key Wrapping', () => {
    it('should encrypt with single-use DEK and decrypt correctly', () => {
      const kek = EnvelopeEncryption.generateKek();
      const plaintext = 'Super-Sensitive-Secret-Data-12345';
      const pkg = EnvelopeEncryption.encrypt(plaintext, kek, 1);

      expect(pkg.kekVersion).toBe(1);
      expect(pkg.encryptedDek).toBeDefined();
      expect(pkg.ciphertext).not.toBe(plaintext);

      const decrypted = EnvelopeEncryption.decrypt(pkg, kek);
      expect(decrypted).toBe(plaintext);
    });

    it('should support zero-plaintext DEK re-wrapping during key rotation', () => {
      const kekV1 = EnvelopeEncryption.generateKek();
      const kekV2 = EnvelopeEncryption.generateKek();
      const plaintext = 'Permanent-Financial-Record';

      const pkg = EnvelopeEncryption.encrypt(plaintext, kekV1, 1);

      // Re-wrap DEK with KEK v2 without touching ciphertext
      const rewrappedDek = EnvelopeEncryption.rewrapDek(pkg.encryptedDek, kekV1, kekV2);

      const updatedPkg = {
        ...pkg,
        kekVersion: 2,
        encryptedDek: rewrappedDek,
      };

      // Ciphertext, IV, Tag remain completely untouched
      expect(updatedPkg.ciphertext).toBe(pkg.ciphertext);
      expect(updatedPkg.iv).toBe(pkg.iv);

      // Decrypt using KEK v2
      const decrypted = EnvelopeEncryption.decrypt(updatedPkg, kekV2);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('3. Vault FSM: Seal, Unseal & Guard', () => {
    it('should initialize in UNSEALED state with seed data', async () => {
      const res = await request.get('/api/vault/status');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('UNSEALED');
      expect(res.body.threshold).toBe(3);
      expect(res.body.activeKekVersion).toBe(1);
    });

    it('should block secret reading and writing when SEALED', async () => {
      // Seal the vault
      const sealRes = await request.post('/api/vault/seal');
      expect(sealRes.status).toBe(200);
      expect(sealRes.body.state.status).toBe('SEALED');

      // Attempt to read a secret -> HTTP 503
      const readRes = await request.get('/api/secrets/secret/production/database');
      expect(readRes.status).toBe(503);
      expect(readRes.body.error).toMatch(/sealed/);

      // Attempt to create a secret -> HTTP 503
      const createRes = await request.post('/api/secrets').send({
        path: 'secret/test/blocked',
        name: 'Blocked Secret',
        plaintext: 'test',
      });
      expect(createRes.status).toBe(503);
    });

    it('should unseal through progressive custodian share submission', async () => {
      const demoSharesRes = await request.get('/api/vault/demo-shares');
      const shares: string[] = demoSharesRes.body.shares;
      expect(shares).toHaveLength(5);

      // Seal vault
      await request.post('/api/vault/seal');

      // Submit Share 1
      const res1 = await request.post('/api/vault/unseal').send({ share: shares[0] });
      expect(res1.body.unsealed).toBe(false);
      expect(res1.body.sharesRemaining).toBe(2);

      // Submit Share 2
      const res2 = await request.post('/api/vault/unseal').send({ share: shares[2] });
      expect(res2.body.unsealed).toBe(false);
      expect(res2.body.sharesRemaining).toBe(1);

      // Submit Share 3 -> Unsealed!
      const res3 = await request.post('/api/vault/unseal').send({ share: shares[4] });
      expect(res3.body.unsealed).toBe(true);
      expect(res3.body.status).toBe('UNSEALED');

      // Now reading secrets works normally
      const readRes = await request.get('/api/secrets/secret/production/database');
      expect(readRes.status).toBe(200);
      expect(readRes.body.plaintext).toContain('orders-db.example.internal');
    });
  });

  describe('4. Secrets Management & Key Rotation', () => {
    it('should create, read, and delete a secret', async () => {
      const createRes = await request.post('/api/secrets').send({
        path: 'secret/custom/api_token',
        name: 'Custom API Token',
        description: 'Test integration secret',
        plaintext: 'example-token-not-real',
      });
      expect(createRes.status).toBe(201);
      expect(createRes.body.path).toBe('secret/custom/api_token');
      expect(createRes.body.kekVersion).toBe(1);

      const readRes = await request.get('/api/secrets/secret/custom/api_token');
      expect(readRes.status).toBe(200);
      expect(readRes.body.plaintext).toBe('example-token-not-real');

      const delRes = await request.delete('/api/secrets/secret/custom/api_token');
      expect(delRes.status).toBe(200);

      const readAfterDel = await request.get('/api/secrets/secret/custom/api_token');
      expect(readAfterDel.status).toBe(404);
    });

    it('should rotate KEK and re-wrap secrets seamlessly', async () => {
      const rotateRes = await request.post('/api/vault/keks/rotate');
      expect(rotateRes.status).toBe(200);
      expect(rotateRes.body.version).toBe(2);

      const rewrapRes = await request.post('/api/vault/keks/rewrap');
      expect(rewrapRes.status).toBe(200);
      expect(rewrapRes.body.rewrappedCount).toBeGreaterThan(0);
      expect(rewrapRes.body.activeVersion).toBe(2);

      // Verify all secrets are still decryptable
      const readRes = await request.get('/api/secrets/secret/production/database');
      expect(readRes.status).toBe(200);
      expect(readRes.body.kekVersion).toBe(2);
      expect(readRes.body.plaintext).toContain('orders-db.example.internal');
    });
  });

  describe('5. Dynamic Leases & Cryptographic Audit Ledger', () => {
    it('should issue dynamic lease and allow renewal and revocation', async () => {
      const leasesRes = await request.get('/api/leases');
      expect(leasesRes.status).toBe(200);
      expect(leasesRes.body.length).toBeGreaterThan(0);

      const targetLease = leasesRes.body[0];
      expect(targetLease.status).toBe('ACTIVE');

      // Renew lease
      const renewRes = await request.post(`/api/leases/${targetLease.id}/renew`).send({ incrementSeconds: 45 });
      expect(renewRes.status).toBe(200);
      expect(renewRes.body.renewCount).toBe(1);

      // Revoke lease
      const revokeRes = await request.post(`/api/leases/${targetLease.id}/revoke`);
      expect(revokeRes.status).toBe(200);
      expect(revokeRes.body.status).toBe('REVOKED');
    });

    it('should maintain a cryptographically chained tamper-evident audit ledger', async () => {
      const auditRes = await request.get('/api/audit');
      expect(auditRes.status).toBe(200);
      expect(auditRes.body.length).toBeGreaterThan(2);

      const verifyRes = await request.get('/api/audit/verify');
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.isValid).toBe(true);
      expect(verifyRes.body.totalEntries).toBe(auditRes.body.length);
    });
  });
});