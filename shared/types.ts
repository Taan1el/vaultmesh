export type VaultStatus = 'SEALED' | 'UNSEALED';

export type LeaseStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

export type AuditAction =
  | 'VAULT_INIT'
  | 'VAULT_UNSEAL'
  | 'VAULT_SEAL'
  | 'SECRET_CREATE'
  | 'SECRET_READ'
  | 'SECRET_DELETE'
  | 'SECRET_REWRAP'
  | 'KEK_ROTATE'
  | 'LEASE_ISSUE'
  | 'LEASE_RENEW'
  | 'LEASE_REVOKE'
  | 'LEASE_EXPIRE';

export interface VaultState {
  status: VaultStatus;
  threshold: number;
  totalShares: number;
  sharesSubmitted: number;
  /** Indexes of the custodian shares submitted in the current unseal attempt. */
  submittedShareIndexes: number[];
  activeKekVersion: number;
  totalSecrets: number;
  activeLeases: number;
  isInitialized: boolean;
}

export interface UnsealProgress {
  status: VaultStatus;
  sharesSubmitted: number;
  submittedShareIndexes: number[];
  threshold: number;
  sharesRemaining: number;
  unsealed: boolean;
}

export interface StoredSecret {
  id: string;
  path: string;
  name: string;
  description: string;
  kekVersion: number;
  encryptedDek: string; // hex
  iv: string;           // hex
  authTag: string;      // hex
  ciphertext: string;   // hex
  version: number;
  isDynamic: boolean;
  ttlSeconds: number;
  maxTtlSeconds: number;
  createdAt: string;
  updatedAt: string;
}

export interface SecretLease {
  id: string;
  secretId: string;
  secretPath: string;
  issuedAt: string;
  expiresAt: string;
  ttlSeconds: number;
  renewCount: number;
  maxRenewals: number;
  status: LeaseStatus;
  revokedAt?: string;
}

export interface DecryptedSecret {
  id: string;
  path: string;
  name: string;
  description: string;
  kekVersion: number;
  plaintext: string;
  parsedData?: Record<string, any>;
  access: SecretAccessDecision;
  version: number;
  isDynamic: boolean;
  lease?: SecretLease;
  createdAt: string;
  updatedAt: string;
}

export interface CreateSecretDto {
  path: string;
  name: string;
  description?: string;
  plaintext: string;
  isDynamic?: boolean;
  ttlSeconds?: number;
  maxTtlSeconds?: number;
}

export interface ReadSecretOptions {
  purpose?: string;
  approvalCode?: string;
}

export interface SecretAccessDecision {
  status: 'ALLOWED' | 'APPROVAL_REQUIRED';
  reason: string;
  purpose: string;
  approvalCodeRequired: boolean;
}

export interface KekVersionInfo {
  version: number;
  createdAt: string;
  secretsCount: number;
  isActive: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: AuditAction;
  secretPath?: string;
  actor: string;
  ip: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
  details: string;
  previousHash: string;
  entryHash: string;
}

export interface AuditVerificationResult {
  isValid: boolean;
  totalEntries: number;
  brokenIndex?: number;
  verifiedAt: string;
}
