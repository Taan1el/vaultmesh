import { describe, expect, it } from 'vitest';
import { EnvelopeEncryption } from '../src/crypto/envelope.js';

describe('envelope encryption', () => {
  it('encrypts with a fresh DEK and IV and decrypts back to the plaintext', () => {
    const kek = EnvelopeEncryption.generateKek();
    const plaintext = '{"user":"orders_app","password":"example-password-not-real"}';

    const a = EnvelopeEncryption.encrypt(plaintext, kek, 1);
    const b = EnvelopeEncryption.encrypt(plaintext, kek, 1);

    expect(a.kekVersion).toBe(1);
    expect(a.iv).toMatch(/^[0-9a-f]{24}$/);
    expect(a.authTag).toMatch(/^[0-9a-f]{32}$/);
    expect(a.ciphertext).not.toContain('example-password');
    expect(a.iv).not.toBe(b.iv);
    expect(a.encryptedDek).not.toBe(b.encryptedDek);
    expect(a.ciphertext).not.toBe(b.ciphertext);

    expect(EnvelopeEncryption.decrypt(a, kek)).toBe(plaintext);
    expect(EnvelopeEncryption.decrypt(b, kek)).toBe(plaintext);
  });

  it('round trips unicode plaintext', () => {
    const kek = EnvelopeEncryption.generateKek();
    const plaintext = 'pässwörd ✓';
    expect(EnvelopeEncryption.decrypt(EnvelopeEncryption.encrypt(plaintext, kek, 1), kek)).toBe(plaintext);
  });

  it('fails to decrypt with the wrong KEK', () => {
    const pkg = EnvelopeEncryption.encrypt('value', EnvelopeEncryption.generateKek(), 1);
    expect(() => EnvelopeEncryption.decrypt(pkg, EnvelopeEncryption.generateKek())).toThrow();
  });

  it('detects tampered ciphertext, auth tags and wrapped keys', () => {
    const kek = EnvelopeEncryption.generateKek();
    const pkg = EnvelopeEncryption.encrypt('value', kek, 1);
    const flip = (hex: string) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);

    expect(() => EnvelopeEncryption.decrypt({ ...pkg, ciphertext: flip(pkg.ciphertext) }, kek)).toThrow();
    expect(() => EnvelopeEncryption.decrypt({ ...pkg, authTag: flip(pkg.authTag) }, kek)).toThrow();
    expect(() => EnvelopeEncryption.decrypt({ ...pkg, iv: flip(pkg.iv) }, kek)).toThrow();

    const [iv, tag, wrapped] = pkg.encryptedDek.split(':');
    expect(() => EnvelopeEncryption.decrypt({ ...pkg, encryptedDek: `${iv}:${tag}:${flip(wrapped)}` }, kek)).toThrow();
    expect(() => EnvelopeEncryption.decrypt({ ...pkg, encryptedDek: `${iv}:${tag}` }, kek)).toThrow(/Malformed/);
  });

  it('re-wraps a DEK for a new KEK without changing the ciphertext', () => {
    const kekV1 = EnvelopeEncryption.generateKek();
    const kekV2 = EnvelopeEncryption.generateKek();
    const pkg = EnvelopeEncryption.encrypt('rotate me', kekV1, 1);

    const rewrapped = { ...pkg, kekVersion: 2, encryptedDek: EnvelopeEncryption.rewrapDek(pkg.encryptedDek, kekV1, kekV2) };

    expect(rewrapped.ciphertext).toBe(pkg.ciphertext);
    expect(rewrapped.iv).toBe(pkg.iv);
    expect(rewrapped.encryptedDek).not.toBe(pkg.encryptedDek);
    expect(EnvelopeEncryption.decrypt(rewrapped, kekV2)).toBe('rotate me');
    expect(() => EnvelopeEncryption.decrypt(rewrapped, kekV1)).toThrow();
  });
});
