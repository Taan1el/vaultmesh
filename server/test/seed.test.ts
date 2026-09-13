import { afterEach, describe, expect, it } from 'vitest';
import { SAMPLE_SECRETS } from '../../shared/seed.js';
import { parseCreateSecretInput } from '../../shared/validation.js';
import { createTestApp } from './helpers.js';

// Prefixes used by real credential formats that secret scanners look for.
const REAL_KEY_PATTERNS = [/sk_live/i, /pk_live/i, /rk_live/i, /whsec_/i, /\bAKIA/, /\bASIA/, /ghp_/, /xox[bp]-/];
const CREDENTIAL_FIELD = /password|key|secret|token/i;

describe('sample secrets', () => {
  let t: ReturnType<typeof createTestApp> | undefined;

  afterEach(() => {
    t?.close();
    t = undefined;
  });

  it('pass the same validation as API input', () => {
    for (const sample of SAMPLE_SECRETS) {
      expect(() => parseCreateSecretInput(sample)).not.toThrow();
    }
  });

  it('only contain placeholder credential values', () => {
    for (const sample of SAMPLE_SECRETS) {
      const fields = Object.entries(JSON.parse(sample.plaintext) as Record<string, unknown>);
      for (const pattern of REAL_KEY_PATTERNS) {
        expect(sample.plaintext).not.toMatch(pattern);
      }
      for (const [field, value] of fields) {
        if (CREDENTIAL_FIELD.test(field)) {
          expect(String(value)).toMatch(/example/i);
        }
      }
    }
  });

  it('are written into a new vault with one lease for the dynamic secret', async () => {
    t = createTestApp();
    const secrets = await t.request.get('/api/secrets');
    expect(secrets.body.map((s: { path: string }) => s.path).sort()).toEqual(SAMPLE_SECRETS.map((s) => s.path).sort());
    const leases = await t.request.get('/api/leases');
    expect(leases.body).toHaveLength(1);
    expect(leases.body[0]).toMatchObject({ secretPath: 'secret/cloud/deploy-credential', status: 'ACTIVE', ttlSeconds: 60 });
  });
});
