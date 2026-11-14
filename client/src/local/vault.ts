import { checksumHex, combineShares, parseShare, splitSecret } from '../../../shared/shamir';

export const KDF_ITERATIONS = 600_000;
export const MAX_VAULT_BYTES = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export interface Entry { id: string; path: string; value: string; updatedAt: string }
export interface Payload { version: 1; entries: Entry[] }
interface Sealed { nonce: string; ciphertext: string }
export interface VaultFile {
  version: 1;
  id: string;
  cipher: 'AES-256-GCM';
  kdf: { name: 'PBKDF2'; hash: 'SHA-256'; iterations: number; salt: string };
  wrappedKey: Sealed;
  payload: Sealed;
}
export interface VaultSession { key: Uint8Array<ArrayBuffer>; data: Payload }

function api() {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable. Open this app over HTTPS or on localhost.');
  return globalThis.crypto.subtle;
}
function random(size: number) { return globalThis.crypto.getRandomValues(new Uint8Array(size)); }
function hex(bytes: Uint8Array) { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(''); }
function bytes(value: string) { return Uint8Array.from(value.match(/../g) ?? [], (pair) => parseInt(pair, 16)); }
function invalid(source: string, field: string, message: string): never { throw new Error(`${source}: ${field} ${message}`); }
function object(value: unknown, source: string, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid(source, field, 'must be an object.');
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, allowed: string[], source: string, field: string) {
  for (const key of Object.keys(value)) if (!allowed.includes(key)) invalid(source, `${field}.${key}`, 'is not supported.');
}
function hexField(value: unknown, size: number | null, source: string, field: string): asserts value is string {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(value) || (size !== null && value.length !== size * 2)) {
    invalid(source, field, size === null ? 'must be lowercase hexadecimal bytes.' : `must contain ${size} lowercase hexadecimal bytes.`);
  }
}
function sealed(value: unknown, source: string, field: string, key = false): Sealed {
  const record = object(value, source, field);
  fields(record, ['nonce', 'ciphertext'], source, field);
  hexField(record.nonce, 12, source, `${field}.nonce`);
  hexField(record.ciphertext, key ? 48 : null, source, `${field}.ciphertext`);
  if (record.ciphertext.length < 32) invalid(source, `${field}.ciphertext`, 'must include a 16-byte authentication tag.');
  if (!key && record.ciphertext.length > (MAX_PLAINTEXT_BYTES + 16) * 2) invalid(source, `${field}.ciphertext`, 'exceeds the 1 MiB encrypted-content limit.');
  return { nonce: record.nonce, ciphertext: record.ciphertext };
}

export function parseVault(text: string, source = 'vault.json'): VaultFile {
  if (text.length > MAX_VAULT_BYTES || encoder.encode(text).byteLength > MAX_VAULT_BYTES) invalid(source, 'file', 'must be at most 4 MiB.');
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { invalid(source, 'JSON', 'is invalid.'); }
  const file = object(parsed, source, 'vault');
  fields(file, ['version', 'id', 'cipher', 'kdf', 'wrappedKey', 'payload'], source, 'vault');
  if (file.version !== 1) invalid(source, 'version', 'must be 1.');
  if (file.cipher !== 'AES-256-GCM') invalid(source, 'cipher', 'must be AES-256-GCM.');
  hexField(file.id, 16, source, 'id');
  const kdf = object(file.kdf, source, 'kdf');
  fields(kdf, ['name', 'hash', 'iterations', 'salt'], source, 'kdf');
  if (kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256') invalid(source, 'kdf', 'must use PBKDF2 with SHA-256.');
  if (typeof kdf.iterations !== 'number' || !Number.isInteger(kdf.iterations) || kdf.iterations < KDF_ITERATIONS || kdf.iterations > 2_000_000) {
    invalid(source, 'kdf.iterations', 'must be an integer from 600000 to 2000000.');
  }
  hexField(kdf.salt, 16, source, 'kdf.salt');
  return { version: 1, id: file.id, cipher: 'AES-256-GCM',
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: kdf.salt },
    wrappedKey: sealed(file.wrappedKey, source, 'wrappedKey', true), payload: sealed(file.payload, source, 'payload') };
}
export function serializeVault(file: VaultFile) { return JSON.stringify(parseVault(JSON.stringify(file)), null, 2) + '\n'; }
function aad(file: Pick<VaultFile, 'version' | 'id' | 'cipher'>, purpose: 'payload' | 'key', kdf?: VaultFile['kdf']) {
  return encoder.encode(JSON.stringify({ version: file.version, id: file.id, cipher: file.cipher, purpose, ...(kdf ? { kdf } : {}) }));
}
function passphrase(value: string) {
  if (value.length < 12 || value.length > 1024) throw new Error('Passphrase must contain 12 to 1024 characters.');
}
/** True when every character follows the previous one by +1 or -1, wrapping 9 to 0 for digits and z to a for letters. */
function isSimpleSequence(characters: string[]) {
  const lower = characters.map((character) => character.toLowerCase());
  const digits = lower.every((character) => /^[0-9]$/.test(character));
  const letters = lower.every((character) => /^[a-z]$/.test(character));
  const modulus = digits ? 10 : letters ? 26 : 0;
  const values = lower.map((character) => digits ? Number(character) : character.codePointAt(0)!);
  const step = (index: number) => modulus ? (values[index] - values[index - 1] + modulus) % modulus : values[index] - values[index - 1];
  const first = step(1);
  return (first === 1 || first === (modulus ? modulus - 1 : -1)) && values.every((_, index) => index === 0 || step(index) === first);
}
/** Extra checks for a passphrase being chosen now. Existing vaults still unlock with whatever they were created with. */
function chosenPassphrase(value: string) {
  passphrase(value);
  const characters = Array.from(value);
  const distinct = new Set(characters).size;
  if (distinct === 1) throw new Error('Passphrase cannot be one character repeated. Use a longer phrase of several words.');
  if (distinct < 5) throw new Error('Passphrase needs at least 5 different characters. Use a longer phrase of several words.');
  if (isSimpleSequence(characters)) {
    throw new Error('Passphrase cannot be a simple sequence such as abcdefghijkl or 123456789012. Use a longer phrase of several words.');
  }
}
async function derive(value: string, kdf: VaultFile['kdf']) {
  passphrase(value);
  const raw = encoder.encode(value);
  try {
    const material = await api().importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
    return await api().deriveKey({ name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: bytes(kdf.salt) }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { raw.fill(0); }
}
async function dataKey(raw: Uint8Array<ArrayBuffer>) { return api().importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); }
async function encrypt(key: CryptoKey, plain: Uint8Array<ArrayBuffer>, additionalData: Uint8Array<ArrayBuffer>): Promise<Sealed> {
  const nonce = random(12);
  const result = await api().encrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, key, plain);
  return { nonce: hex(nonce), ciphertext: hex(new Uint8Array(result)) };
}
async function decrypt(key: CryptoKey, value: Sealed, additionalData: Uint8Array<ArrayBuffer>) {
  return new Uint8Array(await api().decrypt({ name: 'AES-GCM', iv: bytes(value.nonce), additionalData, tagLength: 128 }, key, bytes(value.ciphertext)));
}
function payload(value: unknown): Payload {
  const record = object(value, 'Decrypted vault', 'payload');
  fields(record, ['version', 'entries'], 'Decrypted vault', 'payload');
  if (record.version !== 1 || !Array.isArray(record.entries) || record.entries.length > 500) throw new Error('Decrypted vault must contain version 1 and at most 500 entries.');
  const seen = new Set<string>();
  const paths = new Set<string>();
  const entries = record.entries.map((value, index) => {
    const item = object(value, 'Decrypted vault', `entries[${index}]`);
    fields(item, ['id', 'path', 'value', 'updatedAt'], 'Decrypted vault', `entries[${index}]`);
    hexField(item.id, 16, 'Decrypted vault', `entries[${index}].id`);
    if (typeof item.path !== 'string' || !item.path.trim() || item.path !== item.path.trim() || item.path.length > 200 || /[\u0000-\u001f\u007f]/.test(item.path)) throw new Error('Secret path must contain 1 to 200 characters without control characters.');
    if (typeof item.value !== 'string' || item.value.length > 65_536) throw new Error('Secret value must be text of at most 65536 characters.');
    if (typeof item.updatedAt !== 'string' || !Number.isFinite(Date.parse(item.updatedAt))) throw new Error('Secret timestamp is invalid.');
    if (seen.has(item.id) || paths.has(item.path)) throw new Error('Secret IDs and paths must be unique.');
    seen.add(item.id); paths.add(item.path);
    return { id: item.id, path: item.path, value: item.value, updatedAt: item.updatedAt };
  });
  return { version: 1, entries };
}
async function openPayload(file: VaultFile, key: Uint8Array<ArrayBuffer>) {
  const plain = await decrypt(await dataKey(key), file.payload, aad(file, 'payload'));
  try {
    if (plain.byteLength > MAX_PLAINTEXT_BYTES) throw new Error('Vault contents exceed the 1 MiB limit.');
    return payload(JSON.parse(decoder.decode(plain)));
  } finally { plain.fill(0); }
}
export async function sealData(file: VaultFile, key: Uint8Array<ArrayBuffer>, data: Payload): Promise<VaultFile> {
  const valid = payload(data);
  const plain = encoder.encode(JSON.stringify(valid));
  try {
    if (plain.byteLength > MAX_PLAINTEXT_BYTES) throw new Error('Vault contents exceed the 1 MiB limit. Export or remove entries before adding more.');
    return { ...file, payload: await encrypt(await dataKey(key), plain, aad(file, 'payload')) };
  } finally { plain.fill(0); }
}
async function rewrap(file: VaultFile, key: Uint8Array<ArrayBuffer>, nextPassphrase: string): Promise<VaultFile> {
  chosenPassphrase(nextPassphrase);
  const kdf: VaultFile['kdf'] = { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS, salt: hex(random(16)) };
  return { ...file, kdf, wrappedKey: await encrypt(await derive(nextPassphrase, kdf), key, aad(file, 'key', kdf)) };
}
export async function createVault(value: string): Promise<{ file: VaultFile; session: VaultSession }> {
  chosenPassphrase(value);
  const key = random(32);
  try {
    const header = { version: 1 as const, id: hex(random(16)), cipher: 'AES-256-GCM' as const };
    const data: Payload = { version: 1, entries: [] };
    const skeleton = { ...header } as VaultFile;
    const file = await sealData(await rewrap(skeleton, key, value), key, data);
    return { file, session: { key, data } };
  } catch (error) { key.fill(0); throw error; }
}
export async function unlockVault(value: VaultFile, secret: string): Promise<VaultSession> {
  const file = parseVault(JSON.stringify(value));
  let key: Uint8Array<ArrayBuffer> | undefined;
  try {
    key = await decrypt(await derive(secret, file.kdf), file.wrappedKey, aad(file, 'key', file.kdf));
    return { key, data: await openPayload(file, key) };
  } catch { key?.fill(0); throw new Error('Unable to unlock: passphrase is incorrect or the encrypted vault was changed.'); }
}
export async function rotatePassphrase(file: VaultFile, session: VaultSession, secret: string) {
  await openPayload(file, session.key);
  return rewrap(file, session.key, secret);
}
const SHARE_FORMAT_V1 = 'vmrecovery-1';
const SHARE_FORMAT_V2 = 'vmrecovery-2';
/** Issues five shares of the data key (any three recover it) as one set. Each carries the vault ID, a set ID and a checksum. */
export function recoveryShares(file: VaultFile, session: VaultSession): string[] {
  const setId = hex(random(4));
  return splitSecret(session.key, 5, 3).map((share) => {
    const body = `${SHARE_FORMAT_V2}:${file.id}:3:${setId}:${share}`;
    return `${body}:${checksumHex(body)}`;
  });
}
interface ReadShare { line: number; raw: string; setId?: string }
function readShare(text: string, line: number, file: VaultFile): ReadShare {
  const name = `Recovery share on line ${line}`;
  const parts = text.trim().split(':');
  const version = parts[0];
  if (!((version === SHARE_FORMAT_V1 && parts.length === 4) || (version === SHARE_FORMAT_V2 && parts.length === 6))) {
    throw new Error(`${name} is not in a recognized format, so it cannot belong to this vault. Copy the whole line, starting with ${SHARE_FORMAT_V2}.`);
  }
  if (parts[2] !== '3') throw new Error(`${name} is not part of a 3-of-5 set.`);
  const current = version === SHARE_FORMAT_V2;
  const checksumOk = !current || checksumHex(parts.slice(0, 5).join(':')) === parts[5];
  if (parts[1] !== file.id) {
    throw new Error(`${name} belongs to a different vault${checksumOk ? '' : ' or has a typo in its vault ID'}. It may also have been issued before this vault was re-keyed. Use shares issued for this vault.`);
  }
  if (!checksumOk) throw new Error(`${name} has a typo: its checksum does not match. Compare it with your saved copy, character by character.`);
  const setId = current ? parts[3] : undefined;
  if (current && !/^[0-9a-f]{8}$/.test(setId!)) throw new Error(`${name} has a damaged set ID.`);
  const raw = current ? parts[4] : parts[3];
  try { parseShare(raw, 32); } catch { throw new Error(`${name} is damaged: its share data is not valid. Check it against your saved copy.`); }
  return { line, raw, setId };
}
function checkSet(shares: ReadShare[]) {
  const mixed = shares.find((share) => (share.setId === undefined) !== (shares[0].setId === undefined));
  if (mixed) {
    const older = mixed.setId === undefined ? mixed : shares[0];
    throw new Error(`Recovery share on line ${older.line} uses the older format without a set ID, so it cannot be combined with shares that have one. Use three shares from one set.`);
  }
  const counts = new Map<string | undefined, number>();
  for (const share of shares) counts.set(share.setId, (counts.get(share.setId) ?? 0) + 1);
  const majority = [...counts.entries()].sort((left, right) => right[1] - left[1])[0][0];
  const odd = shares.find((share) => share.setId !== majority);
  if (odd) throw new Error(`Recovery share on line ${odd.line} is from set ${odd.setId}, but the other shares are from set ${majority}. Use three shares from one set.`);
  const seen = new Map<string, number>();
  for (const share of shares) {
    const index = share.raw.slice(8, 10);
    const first = seen.get(index);
    if (first !== undefined) throw new Error(`Duplicate recovery share: line ${share.line} repeats line ${first}. Enter three different shares.`);
    seen.set(index, share.line);
  }
}
export async function recoverVault(value: VaultFile, shares: string[], nextPassphrase: string): Promise<{ file: VaultFile; session: VaultSession }> {
  const file = parseVault(JSON.stringify(value));
  chosenPassphrase(nextPassphrase);
  if (shares.length < 3 || shares.length > 5) throw new Error('Enter 3 to 5 distinct recovery shares.');
  const read = shares.map((share, index) => readShare(share, index + 1, file));
  checkSet(read);
  const key = combineShares(read.map((share) => share.raw)) as Uint8Array<ArrayBuffer>;
  try {
    const data = await openPayload(file, key);
    return { file: await rewrap(file, key, nextPassphrase), session: { key, data } };
  } catch { key.fill(0); throw new Error('Recovery shares do not unlock this encrypted vault. Check the shares and file. If they came from different sets, use three shares from one set.'); }
}
/**
 * Makes a new data key, re-encrypts every entry under it and wraps it with the given passphrase. The result gets a
 * new vault ID. Recovery shares and backup files made earlier hold the old key, so they no longer open this vault,
 * although they still open the contents they were made from. The caller saves the result in one revision-checked write.
 */
export async function rekeyVault(file: VaultFile, session: VaultSession, nextPassphrase: string): Promise<{ file: VaultFile; session: VaultSession }> {
  chosenPassphrase(nextPassphrase);
  await openPayload(file, session.key);
  const key = random(32);
  try {
    const header = { version: 1 as const, id: hex(random(16)), cipher: 'AES-256-GCM' as const };
    const data = payload(session.data);
    const next = await sealData(await rewrap({ ...header } as VaultFile, key, nextPassphrase), key, data);
    return { file: next, session: { key, data } };
  } catch (error) { key.fill(0); throw error; }
}
export function putEntry(data: Payload, path: string, value: string, id?: string): Payload {
  const entry: Entry = { id: id ?? hex(random(16)), path: path.trim(), value, updatedAt: new Date().toISOString() };
  if (id && !data.entries.some((item) => item.id === id)) throw new Error('The selected secret no longer exists.');
  return payload({ version: 1, entries: [...data.entries.filter((item) => item.id !== entry.id), entry] });
}
