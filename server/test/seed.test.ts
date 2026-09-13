import { afterEach, describe, expect, it } from 'vitest';
import { SAMPLE_SECRETS } from '../../shared/seed.js';
import { parseCreateSecretInput } from '../../shared/validation.js';
import { createTestApp } from './helpers.js';

// Prefixes used by real credential formats that secret scanners look for.
const REAL_KEY_PATTERNS = [/sk_live/i, /pk_live/i, /rk_live/i, /whsec_/i, /\bAKIA/, /\bASIA/, /ghp_/, /xox[bp]-/];

function stringValues(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (value && typeof value === 'object') return Object.values(value).flatMap(stringValues);
  return [];
}

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
      const values = stringValues(JSON.parse(sample.plaintext));
      for (const pattern of REAL_KEY_PATTERNS) {
        expect(values.join(' ')).not.toMatch(pattern);
      }
      const credentialValues = values.filter((v) => /password|key|secret|token/i.test(Object.keys(JSON.parse(sample.plaintext)).find((k) => JSON.parse(sample.plaintext)[k] === v) ?? ''));
      for (const value of credentialValues) {
        expect(value).toMatch(/example/i);
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
