// Audit entries form a hash chain: each entry hash is SHA-256 over the previous
// entry hash and the entry fields. Changing, removing or reordering a stored
// entry breaks the chain from that entry on. The hashing itself is left to the
// caller (node:crypto on the server, Web Crypto in the browser demo).
import type { AuditEntry, AuditVerificationResult } from './types.js';

export const GENESIS_HASH = '0'.repeat(64);

export type AuditEntryFields = Omit<AuditEntry, 'previousHash' | 'entryHash'>;

/** The exact string that is hashed to produce an entry hash. */
export function auditHashInput(previousHash: string, entry: AuditEntryFields): string {
  const payload: Record<string, unknown> = {
    id: entry.id,
    timestamp: entry.timestamp,
    action: entry.action,
    secretPath: entry.secretPath || null,
    actor: entry.actor,
    ip: entry.ip,
    status: entry.status,
    details: entry.details,
  };
  // Sorted keys keep the serialization stable.
  const serialized = JSON.stringify(payload, Object.keys(payload).sort());
  return `${previousHash}|${serialized}`;
}

/**
 * Hash inputs for stored entries in insertion order. Each input uses the stored
 * hash of the entry before it, so all hashes can be computed up front.
 */
export function auditChainInputs(entries: AuditEntry[]): string[] {
  return entries.map((entry, i) => auditHashInput(i === 0 ? GENESIS_HASH : entries[i - 1].entryHash, entry));
}

/** Compares stored links and hashes with freshly computed hashes. */
export function checkAuditChain(
  entries: AuditEntry[],
  computedHashes: string[],
  verifiedAt: string
): AuditVerificationResult {
  for (let i = 0; i < entries.length; i++) {
    const expectedPrevious = i === 0 ? GENESIS_HASH : entries[i - 1].entryHash;
    if (entries[i].previousHash !== expectedPrevious || entries[i].entryHash !== computedHashes[i]) {
      return { isValid: false, totalEntries: entries.length, brokenIndex: i, verifiedAt };
    }
  }
  return { isValid: true, totalEntries: entries.length, verifiedAt };
}
