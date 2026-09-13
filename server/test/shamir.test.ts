import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { combineShares, formatShare, parseShare, splitSecret } from '../../shared/shamir.js';
import { bytesToHex, hexToBytes, parseWrappedKey } from '../../shared/encoding.js';

const secret = () => new Uint8Array(crypto.randomBytes(32));

describe('shared Shamir implementation', () => {
  it('rebuilds the secret from every 3-of-5 combination', () => {
    const key = secret();
    const shares = splitSecret(key, 5, 3);
    expect(shares).toHaveLength(5);

    for (let a = 0; a < 5; a++) {
      for (let b = a + 1; b < 5; b++) {
        for (let c = b + 1; c < 5; c++) {
          expect(bytesToHex(combineShares([shares[a], shares[b], shares[c]]))).toBe(bytesToHex(key));
        }
      }
    }
  });

  it('does not rebuild the secret from fewer shares than the threshold', () => {
    const key = secret();
    const shares = splitSecret(key, 5, 3);
    expect(bytesToHex(combineShares([shares[0], shares[1]]))).not.toBe(bytesToHex(key));
  });

  it('produces different shares for the same secret on each split', () => {
    const key = secret();
    expect(splitSecret(key, 5, 3)).not.toEqual(splitSecret(key, 5, 3));
  });

  it('rejects invalid split parameters', () => {
    expect(() => splitSecret(secret(), 5, 1)).toThrow(/at least 2/);
    expect(() => splitSecret(secret(), 2, 3)).toThrow(/cannot exceed total/);
    expect(() => splitSecret(secret(), 256, 3)).toThrow(/255/);
  });

  it('formats and parses shares round trip, case-insensitively', () => {
    const [share] = splitSecret(secret(), 5, 3);
    const point = parseShare(share.toUpperCase().replace('VMSHARE', 'vmshare'), 32);
    expect(point.x).toBe(1);
    expect(formatShare(point)).toBe(share);
  });

  it.each([
    'invalid-share',
    'vmshare-01-',
    'vmshare-1-aabb',
    'vmshare-00-aabb',
    'vmshare-01-abc',
    'vmshare-01-zz',
    'vmshare-01-aabb-extra',
  ])('rejects malformed share %j', (share) => {
    expect(() => parseShare(share)).toThrow();
  });

  it('enforces the expected share length when given', () => {
    expect(() => parseShare('vmshare-02-abcd', 32)).toThrow(/32 bytes/);
  });

  it('rejects duplicate indexes and inconsistent lengths when combining', () => {
    const shares = splitSecret(secret(), 5, 3);
    expect(() => combineShares([shares[0], shares[0], shares[1]])).toThrow(/Duplicate/);
    expect(() => combineShares([shares[0], 'vmshare-02-aabb', shares[2]])).toThrow(/Inconsistent/);
    expect(() => combineShares([])).toThrow(/No shares/);
  });
});

describe('hex and wrapped key encoding', () => {
  it('round trips bytes through hex', () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 255]);
    expect(bytesToHex(bytes)).toBe('00017f80ff');
    expect(hexToBytes('00017F80ff')).toEqual(bytes);
  });

  it('rejects odd-length or non-hex strings', () => {
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
  });

  it('parses iv:authTag:ciphertext and rejects other layouts', () => {
    expect(parseWrappedKey('aa:bb:cc')).toEqual({ iv: 'aa', authTag: 'bb', ciphertext: 'cc' });
    expect(() => parseWrappedKey('aa:bb')).toThrow(/Malformed/);
    expect(() => parseWrappedKey('aa::cc')).toThrow(/Malformed/);
    expect(() => parseWrappedKey('aa:bb:xyz')).toThrow(/Malformed/);
  });
});
