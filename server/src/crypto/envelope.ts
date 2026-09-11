import crypto from 'node:crypto';

export interface EnvelopeEncryptedPackage {
  kekVersion: number;
  encryptedDek: string; // iv:tag:ciphertext
  iv: string;           // hex
  authTag: string;      // hex
  ciphertext: string;   // hex
}

export class EnvelopeEncryption {
  private static ALGORITHM = 'aes-256-gcm';
  private static IV_LENGTH = 12; // 96 bits for GCM
  private static KEY_LENGTH = 32; // 256 bits

  /**
   * Generate a secure random 256-bit Key Encryption Key (KEK)
   */
  static generateKek(): Buffer {
    return crypto.randomBytes(this.KEY_LENGTH);
  }

  /**
   * Wrap (encrypt) a Data Encryption Key (DEK) with a Master Key (KEK) using AES-256-GCM
   */
  static wrapKey(dek: Buffer, kek: Buffer): string {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, kek, iv) as crypto.CipherGCM;
    const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  /**
   * Unwrap (decrypt) an encrypted Data Encryption Key (DEK) with the corresponding KEK
   */
  static unwrapKey(wrappedDekStr: string, kek: Buffer): Buffer {
    const parts = wrappedDekStr.split(':');
    if (parts.length !== 3) {
      throw new Error('Malformed wrapped key format. Expected iv:tag:ciphertext');
    }

    const [ivHex, tagHex, cipherHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const ciphertext = Buffer.from(cipherHex, 'hex');

    const decipher = crypto.createDecipheriv(this.ALGORITHM, kek, iv) as crypto.DecipherGCM;
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * Encrypt a plaintext secret using Envelope Encryption:
   * 1. Generate unique single-use DEK
   * 2. Encrypt plaintext with DEK (AES-256-GCM)
   * 3. Wrap DEK with active KEK (AES-256-GCM)
   * 4. Zeroize DEK from memory
   */
  static encrypt(plaintext: string, kek: Buffer, kekVersion: number): EnvelopeEncryptedPackage {
    const dek = crypto.randomBytes(this.KEY_LENGTH);
    try {
      // 1. Encrypt payload with DEK
      const payloadIv = crypto.randomBytes(this.IV_LENGTH);
      const cipher = crypto.createCipheriv(this.ALGORITHM, dek, payloadIv) as crypto.CipherGCM;
      const ciphertextBuf = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // 2. Wrap DEK with KEK
      const encryptedDek = this.wrapKey(dek, kek);

      return {
        kekVersion,
        encryptedDek,
        iv: payloadIv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: ciphertextBuf.toString('hex'),
      };
    } finally {
      // Ephemeral DEK zeroization
      dek.fill(0);
    }
  }

  /**
   * Decrypt an envelope-encrypted package:
   * 1. Unwrap DEK using KEK
   * 2. Decrypt payload with DEK
   * 3. Zeroize DEK from memory
   */
  static decrypt(pkg: EnvelopeEncryptedPackage, kek: Buffer): string {
    const dek = this.unwrapKey(pkg.encryptedDek, kek);
    try {
      const iv = Buffer.from(pkg.iv, 'hex');
      const tag = Buffer.from(pkg.authTag, 'hex');
      const ciphertextBuf = Buffer.from(pkg.ciphertext, 'hex');

      const decipher = crypto.createDecipheriv(this.ALGORITHM, dek, iv) as crypto.DecipherGCM;
      decipher.setAuthTag(tag);
      const decryptedBuf = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
      return decryptedBuf.toString('utf8');
    } finally {
      // Zeroize unwrapped DEK
      dek.fill(0);
    }
  }

  /**
   * Re-wrap an encrypted DEK with a new KEK version WITHOUT exposing or decrypting the underlying plaintext!
   * This is the cornerstone of zero-downtime key rotation in enterprise KMS.
   */
  static rewrapDek(wrappedDekStr: string, oldKek: Buffer, newKek: Buffer): string {
    const dek = this.unwrapKey(wrappedDekStr, oldKek);
    try {
      return this.wrapKey(dek, newKek);
    } finally {
      dek.fill(0);
    }
  }

  /**
   * Compute a deterministic SHA-256 hash for audit ledger chaining
   */
  static computeAuditHash(previousHash: string, entryPayload: Record<string, any>): string {
    const serialized = JSON.stringify(entryPayload, Object.keys(entryPayload).sort());
    return crypto
      .createHash('sha256')
      .update(`${previousHash}|${serialized}`)
      .digest('hex');
  }
}
