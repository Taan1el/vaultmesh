// AES-256-GCM envelope encryption with the Web Crypto API. It produces the same
// storage format as the server's node:crypto implementation: wrapped keys are
// "iv:authTag:ciphertext" in hex, and secret payloads keep iv, authTag and
// ciphertext as separate hex fields.
import { bytesToHex, formatWrappedKey, hexToBytes, parseWrappedKey } from '../../../shared/encoding';

export const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface Envelope {
  kekVersion: number;
  encryptedDek: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

// Byte arrays here are never backed by a SharedArrayBuffer, so this cast only
// narrows the type for Web Crypto. It avoids copying key material.
const source = (bytes: Uint8Array) => bytes as Uint8Array<ArrayBuffer>;

function subtle(): SubtleCrypto {
  const api = globalThis.crypto?.subtle;
  if (!api) {
    throw new Error('Web Crypto is not available. Open the demo over HTTPS or on localhost.');
  }
  return api;
}

export function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function importAesKey(raw: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return subtle().importKey('raw', source(raw), { name: 'AES-GCM' }, false, [usage]);
}

async function gcmEncrypt(key: Uint8Array, plaintext: Uint8Array) {
  const iv = randomBytes(IV_BYTES);
  const cryptoKey = await importAesKey(key, 'encrypt');
  // Web Crypto appends the auth tag to the ciphertext; the stored format keeps it separate.
  const sealed = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: source(iv), tagLength: TAG_BYTES * 8 }, cryptoKey, source(plaintext))
  );
  return {
    iv,
    ciphertext: sealed.slice(0, sealed.length - TAG_BYTES),
    authTag: sealed.slice(sealed.length - TAG_BYTES),
  };
}

async function gcmDecrypt(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array, authTag: Uint8Array) {
  const cryptoKey = await importAesKey(key, 'decrypt');
  const sealed = new Uint8Array(ciphertext.length + authTag.length);
  sealed.set(ciphertext);
  sealed.set(authTag, ciphertext.length);
  return new Uint8Array(
    await subtle().decrypt({ name: 'AES-GCM', iv: source(iv), tagLength: TAG_BYTES * 8 }, cryptoKey, sealed)
  );
}

export async function wrapKey(key: Uint8Array, wrappingKey: Uint8Array): Promise<string> {
  const { iv, authTag, ciphertext } = await gcmEncrypt(wrappingKey, key);
  return formatWrappedKey({ iv: bytesToHex(iv), authTag: bytesToHex(authTag), ciphertext: bytesToHex(ciphertext) });
}

export async function unwrapKey(wrapped: string, wrappingKey: Uint8Array): Promise<Uint8Array> {
  const parts = parseWrappedKey(wrapped);
  return gcmDecrypt(wrappingKey, hexToBytes(parts.iv), hexToBytes(parts.ciphertext), hexToBytes(parts.authTag));
}

/** Encrypts with a single-use DEK and wraps the DEK with the KEK. */
export async function encryptEnvelope(plaintext: string, kek: Uint8Array, kekVersion: number): Promise<Envelope> {
  const dek = randomBytes(KEY_BYTES);
  try {
    const payload = await gcmEncrypt(dek, new TextEncoder().encode(plaintext));
    return {
      kekVersion,
      encryptedDek: await wrapKey(dek, kek),
      iv: bytesToHex(payload.iv),
      authTag: bytesToHex(payload.authTag),
      ciphertext: bytesToHex(payload.ciphertext),
    };
  } finally {
    dek.fill(0);
  }
}

export async function decryptEnvelope(envelope: Envelope, kek: Uint8Array): Promise<string> {
  const dek = await unwrapKey(envelope.encryptedDek, kek);
  try {
    const plaintext = await gcmDecrypt(
      dek,
      hexToBytes(envelope.iv),
      hexToBytes(envelope.ciphertext),
      hexToBytes(envelope.authTag)
    );
    return new TextDecoder().decode(plaintext);
  } finally {
    dek.fill(0);
  }
}

/** Moves a DEK to a new KEK. The secret payload is not decrypted. */
export async function rewrapDek(wrapped: string, oldKek: Uint8Array, newKek: Uint8Array): Promise<string> {
  const dek = await unwrapKey(wrapped, oldKek);
  try {
    return await wrapKey(dek, newKek);
  } finally {
    dek.fill(0);
  }
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await subtle().digest('SHA-256', source(new TextEncoder().encode(input)));
  return bytesToHex(new Uint8Array(digest));
}
