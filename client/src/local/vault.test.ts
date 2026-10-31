// @vitest-environment node
import { createDecipheriv, pbkdf2Sync, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createVault, KDF_ITERATIONS, MAX_VAULT_BYTES, parseVault, putEntry, recoverVault, recoveryShares, rotatePassphrase, sealData, serializeVault, unlockVault } from './vault';

const phrase = 'synthetic long passphrase';
beforeEach(() => vi.stubGlobal('crypto', webcrypto));
afterEach(() => vi.unstubAllGlobals());

describe('encrypted browser vault', () => {
  it('stores neither secret paths, values, passphrases nor raw keys in its envelope', async () => {
    const { file, session } = await createVault(phrase);
    const data = putEntry(session.data, 'synthetic/database', 'synthetic-secret-value');
    const encrypted = await sealData(file, session.key, data);
    const text = serializeVault(encrypted);
    for (const plain of [phrase, 'synthetic/database', 'synthetic-secret-value', Buffer.from(session.key).toString('hex')]) expect(text).not.toContain(plain);
    expect(encrypted.kdf.iterations).toBe(KDF_ITERATIONS);
    expect(await unlockVault(parseVault(text, 'roundtrip.json'), phrase)).toMatchObject({ data });
    session.key.fill(0);
  });

  it('interoperates with independent native PBKDF2 and AES-GCM decryption', async () => {
    const { file, session } = await createVault(phrase);
    const wrappingKey = pbkdf2Sync(phrase, Buffer.from(file.kdf.salt, 'hex'), 600_000, 32, 'sha256');
    function decrypt(key: Uint8Array, sealed: typeof file.payload, aad: object) {
      const ciphertext = Buffer.from(sealed.ciphertext, 'hex');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.nonce, 'hex'));
      decipher.setAAD(Buffer.from(JSON.stringify(aad)));
      decipher.setAuthTag(ciphertext.subarray(-16));
      return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
    }
    const header = { version: file.version, id: file.id, cipher: file.cipher };
    const key = decrypt(wrappingKey, file.wrappedKey, { ...header, purpose: 'key', kdf: file.kdf });
    expect(new Uint8Array(key)).toEqual(session.key);
    expect(JSON.parse(decrypt(key, file.payload, { ...header, purpose: 'payload' }).toString())).toEqual(session.data);
    wrappingKey.fill(0); key.fill(0); session.key.fill(0);
  });

  it('rejects the wrong passphrase and changed ciphertext, tag, nonce or authenticated header', async () => {
    const { file, session } = await createVault(phrase);
    await expect(unlockVault(file, 'different synthetic phrase')).rejects.toThrow('Unable to unlock');
    const replacements = ['id', 'payload', 'wrappedKey', 'nonce', 'salt'] as const;
    for (const field of replacements) {
      const changed = structuredClone(file);
      if (field === 'id') changed.id = 'ab'.repeat(16);
      else if (field === 'salt') changed.kdf.salt = 'ab'.repeat(16);
      else if (field === 'nonce') changed.payload.nonce = 'ab'.repeat(12);
      else changed[field].ciphertext = (changed[field].ciphertext.startsWith('00') ? '01' : '00') + changed[field].ciphertext.slice(2);
      await expect(unlockVault(changed, phrase)).rejects.toThrow('Unable to unlock');
    }
    session.key.fill(0);
  });

  it('rotates only the wrapped key and KDF while preserving encrypted payload and recovery access', async () => {
    const { file, session } = await createVault(phrase);
    session.data = putEntry(session.data, 'example/key', 'example value');
    const stored = await sealData(file, session.key, session.data);
    const shares = recoveryShares(stored, session);
    const rotated = await rotatePassphrase(stored, session, 'another synthetic passphrase');
    expect(rotated.payload).toEqual(stored.payload);
    expect(rotated.kdf.salt).not.toBe(stored.kdf.salt);
    expect(rotated.wrappedKey).not.toEqual(stored.wrappedKey);
    await expect(unlockVault(rotated, phrase)).rejects.toThrow();
    expect((await unlockVault(rotated, 'another synthetic passphrase')).data).toEqual(session.data);
    const recovered = await recoverVault(rotated, [shares[4], shares[1], shares[3]], 'recovered synthetic passphrase');
    expect(recovered.file.payload).toEqual(rotated.payload);
    expect(recovered.session.data).toEqual(session.data);
    expect((await unlockVault(recovered.file, 'recovered synthetic passphrase')).data).toEqual(session.data);
    recovered.session.key.fill(0); session.key.fill(0);
  });

  it('rejects insufficient, duplicate, mixed-vault, malformed and forged recovery shares', async () => {
    const { file, session } = await createVault(phrase);
    const shares = recoveryShares(file, session);
    await expect(recoverVault(file, shares.slice(0, 2), phrase)).rejects.toThrow('3 to 5');
    await expect(recoverVault(file, [shares[0], shares[0], shares[2]], phrase)).rejects.toThrow('Duplicate');
    await expect(recoverVault(file, [shares[0].replace(file.id, 'ab'.repeat(16)), shares[1], shares[2]], phrase)).rejects.toThrow('belong');
    await expect(recoverVault(file, ['bad', shares[1], shares[2]], phrase)).rejects.toThrow('belong');
    const forged = shares[0].slice(0, -2) + (shares[0].endsWith('00') ? '01' : '00');
    await expect(recoverVault(file, [forged, shares[1], shares[2]], phrase)).rejects.toThrow('do not unlock');
    session.key.fill(0);
  });

  it('creates fresh salts, data keys and nonces, even for identical contents and passphrases', async () => {
    const one = await createVault(phrase); const two = await createVault(phrase);
    expect(one.file.id).not.toBe(two.file.id);
    expect(one.file.kdf.salt).not.toBe(two.file.kdf.salt);
    expect(one.session.key).not.toEqual(two.session.key);
    const next = await sealData(one.file, one.session.key, one.session.data);
    expect(next.payload.nonce).not.toBe(one.file.payload.nonce);
    one.session.key.fill(0); two.session.key.fill(0);
  });

  it('validates imported fields and bounds before cryptographic work', () => {
    expect(() => parseVault('{', 'broken.json')).toThrow('broken.json: JSON');
    expect(() => parseVault('{"version":2}', 'version.json')).toThrow('version.json: version');
    expect(() => parseVault(' '.repeat(MAX_VAULT_BYTES + 1), 'large.json')).toThrow('large.json: file');
  });

  it('rejects unsafe KDF parameters, private extra fields, malformed nonces and unsupported ciphers', async () => {
    const { file, session } = await createVault(phrase);
    for (const iterations of [0, 599999, 600000.5, 2000001]) expect(() => parseVault(JSON.stringify({ ...file, kdf: { ...file.kdf, iterations } }), 'params.json')).toThrow('params.json: kdf.iterations');
    expect(() => parseVault(JSON.stringify({ ...file, key: 'not allowed' }))).toThrow('vault.key');
    expect(() => parseVault(JSON.stringify({ ...file, payload: { ...file.payload, nonce: 'aa' } }))).toThrow('payload.nonce');
    expect(() => parseVault(JSON.stringify({ ...file, payload: { ...file.payload, ciphertext: 'ab'.repeat(1024 * 1024 + 17) } }), 'oversized.json')).toThrow('oversized.json: payload.ciphertext');
    expect(() => parseVault(JSON.stringify({ ...file, cipher: 'unsupported' }))).toThrow('cipher');
    session.key.fill(0);
  });

  it('validates paths, duplicate entries and edits without mutating the current data', async () => {
    const { file, session } = await createVault(phrase);
    const data = putEntry(session.data, ' service/token ', 'value');
    expect(session.data.entries).toHaveLength(0);
    expect(data.entries[0].path).toBe('service/token');
    expect(() => putEntry(data, 'service/token', 'duplicate')).toThrow('unique');
    expect(() => putEntry(data, 'bad\npath', 'value')).toThrow('path');
    const edited = putEntry(data, 'service/token', 'changed', data.entries[0].id);
    expect(edited.entries).toHaveLength(1);
    const encrypted = await sealData(file, session.key, edited);
    expect((await unlockVault(encrypted, phrase)).data).toEqual(edited);
    session.key.fill(0);
  });
});
