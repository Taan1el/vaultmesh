// @vitest-environment node
import { createCipheriv, createDecipheriv, pbkdf2Sync, webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checksumHex, splitSecret } from '../../../shared/shamir';
import { createVault, KDF_ITERATIONS, MAX_VAULT_BYTES, parseVault, putEntry, recoverVault, recoveryShares, rekeyVault, rotatePassphrase, sealData, serializeVault, unlockVault } from './vault';

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
    // A forged share with a matching checksum gets past the typo check and fails when the vault is opened.
    const body = shares[0].split(':').slice(0, 4).concat(shares[0].split(':')[4].slice(0, -2) + (shares[0].split(':')[4].endsWith('00') ? '01' : '00')).join(':');
    const forged = `${body}:${checksumHex(body)}`;
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

describe('recovery share sets', () => {
  async function sample() {
    const { file, session } = await createVault(phrase);
    session.data = putEntry(session.data, 'example/key', 'example value');
    return { file: await sealData(file, session.key, session.data), session };
  }
  it('issues shares with the vault ID, one set ID and a checksum each, and any three recover the vault', async () => {
    const { file, session } = await sample();
    const shares = recoveryShares(file, session);
    expect(shares).toHaveLength(5);
    const sets = new Set(shares.map((share) => share.split(':')[3]));
    expect(sets.size).toBe(1); expect([...sets][0]).toMatch(/^[0-9a-f]{8}$/);
    for (const share of shares) {
      const parts = share.split(':');
      expect(parts[0]).toBe('vmrecovery-2'); expect(parts[1]).toBe(file.id); expect(parts[2]).toBe('3');
      expect(parts[5]).toBe(checksumHex(parts.slice(0, 5).join(':')));
    }
    expect(new Set(recoveryShares(file, session).map((share) => share.split(':')[3])).has([...sets][0])).toBe(false);
    const recovered = await recoverVault(file, [shares[4], shares[0], shares[2]], 'recovered synthetic passphrase');
    expect(recovered.session.data).toEqual(session.data);
    recovered.session.key.fill(0); session.key.fill(0);
  });
  it('still accepts shares issued in the older format', async () => {
    const { file, session } = await sample();
    const older = splitSecret(session.key, 5, 3).map((share) => `vmrecovery-1:${file.id}:3:${share}`);
    const recovered = await recoverVault(file, [older[1], older[3], older[4]], 'recovered synthetic passphrase');
    expect(recovered.session.data).toEqual(session.data);
    recovered.session.key.fill(0); session.key.fill(0);
  });
  it('names the share with a typo', async () => {
    const { file, session } = await sample();
    const shares = recoveryShares(file, session);
    const parts = shares[1].split(':'); parts[4] = parts[4].slice(0, -1) + (parts[4].endsWith('a') ? 'b' : 'a');
    await expect(recoverVault(file, [shares[0], parts.join(':'), shares[2]], 'recovered synthetic passphrase')).rejects.toThrow('line 2 has a typo');
    const checksum = shares[2].split(':'); checksum[5] = checksum[5].replace(/^./, checksum[5][0] === '0' ? '1' : '0');
    await expect(recoverVault(file, [shares[0], shares[1], checksum.join(':')], 'recovered synthetic passphrase')).rejects.toThrow('line 3 has a typo');
    session.key.fill(0);
  });
  it('names the share from another set of the same vault', async () => {
    const { file, session } = await sample();
    const first = recoveryShares(file, session); const second = recoveryShares(file, session);
    const error = await recoverVault(file, [first[0], first[1], second[2]], 'recovered synthetic passphrase').catch((reason: Error) => reason.message);
    expect(error).toContain('line 3 is from set'); expect(error).toContain(first[0].split(':')[3]); expect(error).toContain(second[2].split(':')[3]);
    session.key.fill(0);
  });
  it('names the share from another vault, and rejects mixing formats or repeating a share', async () => {
    const { file, session } = await sample(); const other = await createVault('another synthetic passphrase');
    const shares = recoveryShares(file, session); const foreign = recoveryShares(other.file, other.session);
    await expect(recoverVault(file, [shares[0], foreign[1], shares[2]], 'recovered synthetic passphrase')).rejects.toThrow('line 2 belongs to a different vault');
    const older = `vmrecovery-1:${file.id}:3:${splitSecret(session.key, 5, 3)[0]}`;
    await expect(recoverVault(file, [shares[0], shares[1], older], 'recovered synthetic passphrase')).rejects.toThrow('line 3 uses the older format');
    await expect(recoverVault(file, [shares[0], shares[1], shares[1]], 'recovered synthetic passphrase')).rejects.toThrow('line 3 repeats line 2');
    other.session.key.fill(0); session.key.fill(0);
  });
});

describe('re-keying', () => {
  it('re-encrypts everything under a new key and vault ID, and cuts off earlier shares and exports', async () => {
    const { file, session } = await createVault(phrase);
    session.data = putEntry(putEntry(session.data, 'example/one', 'first value'), 'example/two', 'second value');
    const before = await sealData(file, session.key, session.data); const oldShares = recoveryShares(before, session);
    const oldKey = new Uint8Array(session.key);
    const next = await rekeyVault(before, session, 'rekeyed synthetic passphrase');
    expect(next.file.id).not.toBe(before.id); expect(next.session.key).not.toEqual(oldKey);
    expect(next.file.payload.ciphertext).not.toBe(before.payload.ciphertext); expect(next.file.wrappedKey.ciphertext).not.toBe(before.wrappedKey.ciphertext);
    expect(serializeVault(next.file)).not.toContain('first value');
    // The new file opens with the new passphrase and has every entry.
    expect((await unlockVault(next.file, 'rekeyed synthetic passphrase')).data).toEqual(session.data);
    await expect(unlockVault(next.file, phrase)).rejects.toThrow('Unable to unlock');
    // Earlier shares and exports do not open the new vault, but still open the old contents.
    await expect(recoverVault(next.file, [oldShares[0], oldShares[1], oldShares[2]], 'recovered synthetic passphrase')).rejects.toThrow('belongs to a different vault');
    const old = await recoverVault(before, [oldShares[0], oldShares[1], oldShares[2]], 'recovered synthetic passphrase');
    expect(old.session.data).toEqual(session.data);
    expect((await unlockVault(before, phrase)).data).toEqual(session.data);
    // The old key cannot decrypt the new payload even when the old vault ID is put back.
    await expect(unlockVault({ ...next.file, id: before.id, wrappedKey: before.wrappedKey, kdf: before.kdf }, phrase)).rejects.toThrow('Unable to unlock');
    // New shares work with the new file.
    const shares = recoveryShares(next.file, next.session);
    const recovered = await recoverVault(next.file, [shares[2], shares[3], shares[4]], 'recovered synthetic passphrase');
    expect(recovered.session.data).toEqual(session.data);
    for (const held of [recovered.session.key, old.session.key, next.session.key, session.key]) held.fill(0);
  });
  it('rejects a weak passphrase and a session that does not match the file, leaving the inputs untouched', async () => {
    const { file, session } = await createVault(phrase); const other = await createVault('another synthetic passphrase');
    const key = new Uint8Array(session.key);
    await expect(rekeyVault(file, session, 'aaaaaaaaaaaa')).rejects.toThrow('repeated');
    await expect(rekeyVault(file, other.session, 'rekeyed synthetic passphrase')).rejects.toThrow();
    expect(session.key).toEqual(key); expect((await unlockVault(file, phrase)).data).toEqual(session.data);
    session.key.fill(0); other.session.key.fill(0);
  });
});

describe('passphrase strength for new passphrases', () => {
  it('rejects one repeated character, few distinct characters and simple sequences with a specific message', async () => {
    await expect(createVault('aaaaaaaaaaaa')).rejects.toThrow('one character repeated');
    await expect(createVault('abababababab')).rejects.toThrow('at least 5 different characters');
    await expect(createVault('abcdabcdabcd')).rejects.toThrow('at least 5 different characters');
    await expect(createVault('abcdefghijkl')).rejects.toThrow('simple sequence');
    await expect(createVault('LKJIHGFEDCBA')).rejects.toThrow('simple sequence');
    await expect(createVault('123456789012')).rejects.toThrow('simple sequence');
    await expect(createVault('210987654321')).rejects.toThrow('simple sequence');
    await expect(createVault('short one')).rejects.toThrow('12 to 1024');
  });
  it('keeps the 12 character minimum, accepts ordinary phrases and does not lock out an existing weak passphrase', async () => {
    const created = await createVault('a b c d e f g h'); expect(created.file.id).toHaveLength(32);
    const { file, session } = await createVault(phrase);
    // A vault made before the strength check, wrapped with a repeated-character passphrase.
    const weak = 'aaaaaaaaaaaa'; const kdf = { ...file.kdf, salt: 'cd'.repeat(16) };
    const wrapping = pbkdf2Sync(weak, Buffer.from(kdf.salt, 'hex'), kdf.iterations, 32, 'sha256');
    const nonce = Buffer.alloc(12, 7);
    const cipher = createCipheriv('aes-256-gcm', wrapping, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify({ version: file.version, id: file.id, cipher: file.cipher, purpose: 'key', kdf })));
    const sealedKey = Buffer.concat([cipher.update(session.key), cipher.final(), cipher.getAuthTag()]).toString('hex');
    const legacy = { ...file, kdf, wrappedKey: { nonce: nonce.toString('hex'), ciphertext: sealedKey } };
    expect((await unlockVault(legacy, weak)).data).toEqual(session.data);
    for (const held of [created.session.key, session.key]) held.fill(0);
  });
});
