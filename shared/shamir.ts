// Shamir's Secret Sharing over GF(2^8). Pure TypeScript so the server and the
// in-browser demo share one implementation. Randomness comes from the Web
// Crypto API, which Node.js and browsers both expose as globalThis.crypto.
import { bytesToHex, hexToBytes } from './encoding.js';

// Primitive polynomial 0x11d with generator 2.
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

const SHARE_PATTERN = /^vmshare-([0-9a-f]{2})-((?:[0-9a-f]{2})+)$/i;

export function formatShare(point: SharePoint): string {
  return `vmshare-${point.x.toString(16).padStart(2, '0')}-${bytesToHex(point.y)}`;
}

/**
 * Parses a share formatted as `vmshare-{index as 2 hex digits}-{hex data}`.
 * Pass `expectedBytes` to require a specific secret length.
 */
export function parseShare(share: string, expectedBytes?: number): SharePoint {
  const match = SHARE_PATTERN.exec(share.trim());
  if (!match) {
    throw new Error('Invalid share format. Expected vmshare-{index}-{hex}');
  }
  const x = parseInt(match[1], 16);
  if (x < 1) throw new Error('Invalid share index');
  const y = hexToBytes(match[2]);
  if (expectedBytes !== undefined && y.length !== expectedBytes) {
    throw new Error(`Invalid share length. Expected ${expectedBytes} bytes of share data`);
  }
  return { x, y };
}

/** Splits `secret` into `totalShares` shares; any `threshold` of them rebuild it. */
export function splitSecret(secret: Uint8Array, totalShares: number, threshold: number): string[] {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  if (threshold > totalShares) throw new Error('Threshold cannot exceed total shares');
  if (totalShares > 255) throw new Error('Total shares cannot exceed 255');

  const points: SharePoint[] = Array.from({ length: totalShares }, (_, i) => ({
    x: i + 1,
    y: new Uint8Array(secret.length),
  }));
  const coeffs = new Uint8Array(threshold);

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    coeffs[0] = secret[byteIdx];
    globalThis.crypto.getRandomValues(coeffs.subarray(1));

    for (const point of points) {
      let yVal = 0;
      let xPow = 1;
      for (let c = 0; c < threshold; c++) {
        yVal ^= mul(coeffs[c], xPow);
        xPow = mul(xPow, point.x);
      }
      point.y[byteIdx] = yVal;
    }
  }
  coeffs.fill(0);

  return points.map(formatShare);
}

/** Rebuilds the secret from shares with Lagrange interpolation at x = 0. */
export function combineShares(shares: string[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error('No shares provided for reconstruction');
  }

  const points = shares.map((share) => parseShare(share));

  const seen = new Set<number>();
  for (const point of points) {
    if (seen.has(point.x)) {
      throw new Error(`Duplicate share index detected: ${point.x}`);
    }
    seen.add(point.x);
  }

  const secretLen = points[0].y.length;
  if (points.some((point) => point.y.length !== secretLen)) {
    throw new Error('Inconsistent share lengths');
  }

  const result = new Uint8Array(secretLen);
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let secretByte = 0;
    for (let i = 0; i < points.length; i++) {
      let num = 1;
      let den = 1;
      for (let j = 0; j < points.length; j++) {
        if (i === j) continue;
        num = mul(num, points[j].x);
        den = mul(den, points[i].x ^ points[j].x);
      }
      secretByte ^= mul(points[i].y[byteIdx], div(num, den));
    }
    result[byteIdx] = secretByte;
  }

  return result;
}
