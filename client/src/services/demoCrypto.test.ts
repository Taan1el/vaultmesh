import { describe, expect, it } from 'vitest';
import { randomBytes as nodeRandomBytes, createHash } from 'node:crypto';
import { EnvelopeEncryption } from '../../../server/src/crypto/envelope';
import { decryptEnvelope, encryptEnvelope, rewrapDek, sha256Hex, unwrapKey, wrapKey } from './demoCrypto';

// The demo must read and write the same envelope format as the server.
describe('Web Crypto envelopes match the server format', () => {
  it('lets the server decrypt envelopes made in the browser', async () => {
    const kek = new Uint8Array(nodeRandomBytes(32));
    const envelope = await encryptEnvelope('{"user":"demo","password":"example-not-real"}', kek, 3);

    expect(EnvelopeEncryption.decrypt(envelope, Buffer.from(kek))).toBe('{"user":"demo","password":"example-not-real"}');
  });

  it('decrypts envelopes and wrapped keys made by the server', async () => {
    const kek = EnvelopeEncryption.generateKek();
    const envelope = EnvelopeEncryption.encrypt('from node:crypto', kek, 1);
    expect(await decryptEnvelope(envelope, new Uint8Array(kek))).toBe('from node:crypto');

    const root = EnvelopeEncryption.generateKek();
    const wrapped = EnvelopeEncryption.wrapKey(kek, root);
    expect(Buffer.from(await unwrapKey(wrapped, new Uint8Array(root))).equals(kek)).toBe(true);

    const browserWrapped = await wrapKey(new Uint8Array(kek), new Uint8Array(root));
    expect(EnvelopeEncryption.unwrapKey(browserWrapped, root).equals(kek)).toBe(true);
  });

  it('re-wraps a DEK so only the new KEK can open the envelope', async () => {
    const oldKek = new Uint8Array(nodeRandomBytes(32));
    const newKek = new Uint8Array(nodeRandomBytes(32));
    const envelope = await encryptEnvelope('rotate me', oldKek, 1);
    const moved = { ...envelope, kekVersion: 2, encryptedDek: await rewrapDek(envelope.encryptedDek, oldKek, newKek) };

    expect(moved.ciphertext).toBe(envelope.ciphertext);
    expect(await decryptEnvelope(moved, newKek)).toBe('rotate me');
    await expect(decryptEnvelope(moved, oldKek)).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const kek = new Uint8Array(nodeRandomBytes(32));
    const envelope = await encryptEnvelope('value', kek, 1);
    const flipped = (envelope.ciphertext[0] === '0' ? '1' : '0') + envelope.ciphertext.slice(1);
    await expect(decryptEnvelope({ ...envelope, ciphertext: flipped }, kek)).rejects.toThrow();
  });

  it('hashes like node:crypto', async () => {
    expect(await sha256Hex('audit|chain')).toBe(createHash('sha256').update('audit|chain').digest('hex'));
  });
});
