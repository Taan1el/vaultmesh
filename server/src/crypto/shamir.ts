import { combineShares, parseShare, splitSecret, type SharePoint } from '../../../shared/shamir.js';

export type { SharePoint };

/** Buffer-friendly wrapper around the shared Shamir implementation. */
export class ShamirSecretSharing {
  static split(secret: Buffer, totalShares: number, threshold: number): string[] {
    return splitSecret(secret, totalShares, threshold);
  }

  static parseShare(share: string, expectedBytes?: number): SharePoint {
    return parseShare(share, expectedBytes);
  }

  static combine(shares: string[]): Buffer {
    const bytes = combineShares(shares);
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
}
