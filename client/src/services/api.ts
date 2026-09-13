import type {
  AuditEntry,
  AuditVerificationResult,
  CreateSecretDto,
  DecryptedSecret,
  KekVersionInfo,
  SecretLease,
  StoredSecret,
  UnsealProgress,
  VaultState,
} from '../../../shared/types';

// The API rejects POSTs that are not JSON, so every POST sends this header.
const jsonHeaders = { 'Content-Type': 'application/json' };

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = typeof payload.error === 'string' ? payload.error : `Request failed with ${response.status}`;
    throw new Error(message);
  }

  return payload as T;
}

export const api = {
  status: () => request<VaultState>('/api/vault/status'),
  demoShares: () => request<{ shares: string[] }>('/api/vault/demo-shares'),
  seal: () => request<{ message: string; state: VaultState }>('/api/vault/seal', { method: 'POST', headers: jsonHeaders }),
  unseal: (share: string) =>
    request<UnsealProgress>('/api/vault/unseal', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ share }),
    }),
  rotateKek: () => request<KekVersionInfo>('/api/vault/keks/rotate', { method: 'POST', headers: jsonHeaders }),
  rewrapSecrets: () =>
    request<{ rewrappedCount: number; activeVersion: number }>('/api/vault/keks/rewrap', { method: 'POST', headers: jsonHeaders }),
  keks: () => request<KekVersionInfo[]>('/api/vault/keks'),
  secrets: () => request<StoredSecret[]>('/api/secrets'),
  readSecret: (path: string) => request<DecryptedSecret>(`/api/secrets/${path}`),
  createSecret: (dto: CreateSecretDto) =>
    request<StoredSecret>('/api/secrets', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(dto),
    }),
  leases: () => request<SecretLease[]>('/api/leases'),
  renewLease: (id: string, incrementSeconds: number) =>
    request<SecretLease>(`/api/leases/${id}/renew`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ incrementSeconds }),
    }),
  revokeLease: (id: string) => request<SecretLease>(`/api/leases/${id}/revoke`, { method: 'POST', headers: jsonHeaders }),
  audit: () => request<AuditEntry[]>('/api/audit?limit=8'),
  verifyAudit: () => request<AuditVerificationResult>('/api/audit/verify'),
};
