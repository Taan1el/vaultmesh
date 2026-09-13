import { describe, expect, it } from 'vitest';
import { VaultError } from '../../shared/errors.js';
import {
  MAX_AUDIT_LIMIT,
  MAX_TTL_SECONDS,
  PLAINTEXT_MAX_BYTES,
  parseAuditLimit,
  parseCreateSecretInput,
  parseRenewIncrement,
  parseSecretPath,
  sanitizeActor,
} from '../../shared/validation.js';

function expectBadRequest(fn: () => unknown, message: RegExp) {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultError).status).toBe(400);
    expect((error as VaultError).message).toMatch(message);
    return;
  }
  throw new Error('expected a 400 VaultError');
}

describe('parseSecretPath', () => {
  it('strips surrounding slashes and whitespace', () => {
    expect(parseSecretPath('  /secret/apps/web/  ')).toBe('secret/apps/web');
  });

  it('accepts secret ids and dotted names', () => {
    expect(parseSecretPath('sec_0123456789abcdef')).toBe('sec_0123456789abcdef');
    expect(parseSecretPath('secret/tls/api.example.com')).toBe('secret/tls/api.example.com');
  });

  it.each([
    [undefined, /required/],
    ['', /required/],
    ['///', /empty/],
    [42, /string/],
    ['secret//double', /segments/],
    ['secret/../escape', /segments/],
    ['secret/with space', /segments/],
    ['secret/-dash-first', /segments/],
    ['a'.repeat(201), /at most 200/],
  ])('rejects %j', (value, message) => {
    expectBadRequest(() => parseSecretPath(value), message);
  });
});

describe('parseCreateSecretInput', () => {
  const base = { path: 'secret/app/token', name: 'App token', plaintext: 'value' };

  it('applies defaults for a static secret', () => {
    expect(parseCreateSecretInput(base)).toEqual({
      path: 'secret/app/token',
      name: 'App token',
      description: '',
      plaintext: 'value',
      isDynamic: false,
      ttlSeconds: 0,
      maxTtlSeconds: 0,
    });
  });

  it('ignores TTL fields on static secrets', () => {
    const input = parseCreateSecretInput({ ...base, ttlSeconds: -5, maxTtlSeconds: 'x' });
    expect(input.ttlSeconds).toBe(0);
    expect(input.maxTtlSeconds).toBe(0);
  });

  it('defaults dynamic secrets to a 60 second TTL and 5x max TTL', () => {
    const input = parseCreateSecretInput({ ...base, isDynamic: true });
    expect(input.ttlSeconds).toBe(60);
    expect(input.maxTtlSeconds).toBe(300);
  });

  it('caps the default max TTL at the upper limit', () => {
    const input = parseCreateSecretInput({ ...base, isDynamic: true, ttlSeconds: MAX_TTL_SECONDS });
    expect(input.maxTtlSeconds).toBe(MAX_TTL_SECONDS);
  });

  it('serializes JSON object plaintext', () => {
    const input = parseCreateSecretInput({ ...base, plaintext: { user: 'app', port: 5432 } });
    expect(input.plaintext).toBe('{"user":"app","port":5432}');
  });

  it('trims name and description', () => {
    const input = parseCreateSecretInput({ ...base, name: '  Token ', description: ' Used by CI ' });
    expect(input.name).toBe('Token');
    expect(input.description).toBe('Used by CI');
  });

  it.each([
    [null, /JSON object/],
    [[], /JSON object/],
    [{ ...base, name: undefined }, /name is required/],
    [{ ...base, name: '   ' }, /name must not be empty/],
    [{ ...base, name: 'n'.repeat(101) }, /name must be at most 100/],
    [{ ...base, description: 7 }, /description must be a string/],
    [{ ...base, plaintext: undefined }, /plaintext is required/],
    [{ ...base, plaintext: '  ' }, /plaintext must not be empty/],
    [{ ...base, plaintext: 12 }, /plaintext must be a string/],
    [{ ...base, plaintext: 'x'.repeat(PLAINTEXT_MAX_BYTES + 1) }, /at most 32768 bytes/],
    [{ ...base, isDynamic: 'false' }, /isDynamic must be true or false/],
    [{ ...base, isDynamic: true, ttlSeconds: -50 }, /ttlSeconds/],
    [{ ...base, isDynamic: true, ttlSeconds: 9 }, /ttlSeconds/],
    [{ ...base, isDynamic: true, ttlSeconds: 30.5 }, /ttlSeconds/],
    [{ ...base, isDynamic: true, ttlSeconds: '60' }, /ttlSeconds/],
    [{ ...base, isDynamic: true, ttlSeconds: 60, maxTtlSeconds: 59 }, /maxTtlSeconds/],
    [{ ...base, isDynamic: true, ttlSeconds: 60, maxTtlSeconds: MAX_TTL_SECONDS + 1 }, /maxTtlSeconds/],
  ])('rejects %j', (body, message) => {
    expectBadRequest(() => parseCreateSecretInput(body), message);
  });

  it('counts plaintext size in UTF-8 bytes', () => {
    // Each "e with acute accent" is 2 bytes in UTF-8.
    const multiByte = String.fromCharCode(0xe9).repeat(PLAINTEXT_MAX_BYTES / 2 + 1);
    expectBadRequest(() => parseCreateSecretInput({ ...base, plaintext: multiByte }), /bytes/);
  });
});

describe('parseRenewIncrement', () => {
  it('defaults to 30 seconds', () => {
    expect(parseRenewIncrement(undefined)).toBe(30);
  });

  it.each(['abc', '30', -100, 0, 1.5, 3601])('rejects %j', (value) => {
    expectBadRequest(() => parseRenewIncrement(value), /incrementSeconds/);
  });
});

describe('parseAuditLimit', () => {
  it('defaults to 50 and parses query strings', () => {
    expect(parseAuditLimit(undefined)).toBe(50);
    expect(parseAuditLimit('8')).toBe(8);
    expect(parseAuditLimit(String(MAX_AUDIT_LIMIT))).toBe(MAX_AUDIT_LIMIT);
  });

  it.each(['abc', '-1', '0', '1.5', '201', ['1', '2']])('rejects %j', (value) => {
    expectBadRequest(() => parseAuditLimit(value), /limit/);
  });
});

describe('sanitizeActor', () => {
  it('keeps short printable names', () => {
    expect(sanitizeActor('  ops-alice ', 'developer')).toBe('ops-alice');
  });

  it('falls back for missing, empty or non-string values', () => {
    expect(sanitizeActor(undefined, 'developer')).toBe('developer');
    expect(sanitizeActor(String.fromCharCode(0, 7), 'developer')).toBe('developer');
    expect(sanitizeActor(['a', 'b'], 'developer')).toBe('developer');
  });

  it('strips control characters and truncates to 64 characters', () => {
    expect(sanitizeActor(`bob${String.fromCharCode(13, 10)}forged-entry`, 'x')).toBe('bobforged-entry');
    expect(sanitizeActor('a'.repeat(100), 'x')).toHaveLength(64);
  });
});
