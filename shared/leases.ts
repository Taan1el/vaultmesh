import { conflict } from './errors.js';
import type { SecretLease } from './types.js';

export const LEASE_MAX_RENEWALS = 5;

/** True when an active lease has passed its expiry but has not been swept yet. */
export function isLeaseExpired(lease: Pick<SecretLease, 'status' | 'expiresAt'>, now: number): boolean {
  return lease.status === 'ACTIVE' && Date.parse(lease.expiresAt) <= now;
}

export interface LeaseRenewal {
  expiresAt: string;
  renewCount: number;
}

/**
 * Works out a lease renewal. Renewing adds `incrementSeconds` to the current
 * expiry, but never past `issuedAt + maxTtlSeconds` (0 means no cap).
 * Throws a 409 VaultError when the lease cannot be renewed.
 */
export function planLeaseRenewal(
  lease: SecretLease,
  maxTtlSeconds: number,
  incrementSeconds: number,
  now: number
): LeaseRenewal {
  if (lease.status !== 'ACTIVE') {
    throw conflict(`Cannot renew lease with status "${lease.status}"`);
  }
  const currentExpiry = Date.parse(lease.expiresAt);
  if (currentExpiry <= now) {
    throw conflict(`Lease "${lease.id}" has already expired`);
  }
  if (lease.renewCount >= lease.maxRenewals) {
    throw conflict(`Maximum renewal count (${lease.maxRenewals}) reached for lease "${lease.id}"`);
  }

  let nextExpiry = currentExpiry + incrementSeconds * 1000;
  if (maxTtlSeconds > 0) {
    const maxExpiry = Date.parse(lease.issuedAt) + maxTtlSeconds * 1000;
    if (currentExpiry >= maxExpiry) {
      throw conflict(`Lease "${lease.id}" already reached its max TTL of ${maxTtlSeconds} seconds`);
    }
    nextExpiry = Math.min(nextExpiry, maxExpiry);
  }

  return { expiresAt: new Date(nextExpiry).toISOString(), renewCount: lease.renewCount + 1 };
}

export function assertLeaseRevocable(lease: SecretLease): void {
  if (lease.status !== 'ACTIVE') {
    throw conflict(`Cannot revoke lease with status "${lease.status}"`);
  }
}
