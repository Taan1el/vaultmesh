const HEX_PATTERN = /^(?:[0-9a-f]{2})*$/i;

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  if (!HEX_PATTERN.test(hex)) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** A key wrapped with AES-256-GCM is stored as "iv:authTag:ciphertext" in hex. */
export interface WrappedKeyParts {
  iv: string;
  authTag: string;
  ciphertext: string;
}

export function formatWrappedKey(parts: WrappedKeyParts): string {
  return `${parts.iv}:${parts.authTag}:${parts.ciphertext}`;
}

export function parseWrappedKey(value: string): WrappedKeyParts {
  const parts = value.split(':');
  if (parts.length !== 3 || parts.some((part) => !part || !HEX_PATTERN.test(part))) {
    throw new Error('Malformed wrapped key. Expected iv:authTag:ciphertext in hex');
  }
  const [iv, authTag, ciphertext] = parts;
  return { iv, authTag, ciphertext };
}
