import crypto from 'node:crypto';

// Primitive polynomial 0x11d with generator 2 for GF(2^8)
const POLY = 0x11d;
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    let next = x << 1;
    if (next & 0x100) next ^= POLY;
    x = next;
  }
  for (let i = 255; i < 512; i++) {
    EXP[i] = EXP[i - 255];
  }
})();

function mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function div(a: number, b: number): number {
  if (b === 0) throw new Error('Division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

export interface SharePoint {
  x: number;
  y: Uint8Array;
}

export class ShamirSecretSharing {
  /**
   * Split a secret buffer into `totalShares` shares where any `threshold`
   * shares can reconstruct the secret (Shamir's Secret Sharing over GF(256)).
   */
  static split(secret: Buffer, totalShares: number, threshold: number): string[] {
    if (threshold < 2) throw new Error('Threshold must be at least 2');
    if (threshold > totalShares) throw new Error('Threshold cannot exceed total shares');
    if (totalShares > 255) throw new Error('Total shares cannot exceed 255');

    const shares: SharePoint[] = Array.from({ length: totalShares }, (_, i) => ({
      x: i + 1,
      y: new Uint8Array(secret.length),
    }));

    for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
      const secretByte = secret[byteIdx];
      const coeffs = new Uint8Array(threshold);
      coeffs[0] = secretByte;
      const randBytes = crypto.randomBytes(threshold - 1);
      for (let c = 1; c < threshold; c++) {
        coeffs[c] = randBytes[c - 1];
      }

      for (let s = 0; s < totalShares; s++) {
        const xVal = shares[s].x;
        let yVal = 0;
        let xPow = 1;
        for (let c = 0; c < threshold; c++) {
          yVal ^= mul(coeffs[c], xPow);
          xPow = mul(xPow, xVal);
        }
        shares[s].y[byteIdx] = yVal;
      }
    }

    return shares.map((s) => `vmshare-${s.x.toString(16).padStart(2, '0')}-${Buffer.from(s.y).toString('hex')}`);
  }

  /**
   * Parse a share string formatted as `vmshare-XX-HEXDATA`
   */
  static parseShare(shareStr: string): SharePoint {
    const trimmed = shareStr.trim();
    const parts = trimmed.split('-');
    if (parts.length !== 3 || parts[0] !== 'vmshare') {
      throw new Error('Invalid share format. Expected format: vmshare-{index}-{hex}');
    }
    const x = parseInt(parts[1], 16);
    if (isNaN(x) || x < 1 || x > 255) {
      throw new Error('Invalid share index');
    }
    const y = new Uint8Array(Buffer.from(parts[2], 'hex'));
    if (y.length === 0) {
      throw new Error('Empty share data');
    }
    return { x, y };
  }

  /**
   * Reconstruct original secret from at least `threshold` shares using Lagrange interpolation.
   */
  static combine(shareStrings: string[]): Buffer {
    if (shareStrings.length === 0) {
      throw new Error('No shares provided for reconstruction');
    }

    const shares = shareStrings.map((s) => this.parseShare(s));

    // Ensure all share x coordinates are unique
    const xSet = new Set<number>();
    for (const s of shares) {
      if (xSet.has(s.x)) {
        throw new Error(`Duplicate share index detected: ${s.x}`);
      }
      xSet.add(s.x);
    }

    const secretLen = shares[0].y.length;
    for (const s of shares) {
      if (s.y.length !== secretLen) {
        throw new Error('Inconsistent share lengths');
      }
    }

    const k = shares.length;
    const result = Buffer.alloc(secretLen);

    for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
      let secretByte = 0;
      for (let i = 0; i < k; i++) {
        const xi = shares[i].x;
        const yi = shares[i].y[byteIdx];
        let num = 1;
        let den = 1;
        for (let j = 0; j < k; j++) {
          if (i === j) continue;
          const xj = shares[j].x;
          num = mul(num, xj);
          den = mul(den, xi ^ xj);
        }
        const basis = div(num, den);
        secretByte ^= mul(yi, basis);
      }
      result[byteIdx] = secretByte;
    }

    return result;
  }
}