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
import { demoApi } from './demoApi';

/** Everything the dashboard needs from a vault backend. */
export interface VaultApi {
  status(): Promise<VaultState>;
  demoShares(): Promise<{ shares: string[] }>;
  seal(): Promise<{ message: string; state: VaultState }>;
  unseal(share: string): Promise<UnsealProgress>;
  resetUnseal(): Promise<{ message: string }>;
  rotateKek(): Promise<KekVersionInfo>;
  rewrapSecrets(): Promise<{ rewrappedCount: number; activeVersion: number }>;
  keks(): Promise<KekVersionInfo[]>;
  secrets(): Promise<StoredSecret[]>;
  readSecret(path: string): Promise<DecryptedSecret>;
  createSecret(dto: CreateSecretDto): Promise<StoredSecret>;
  deleteSecret(path: string): Promise<{ message: string; path: string }>;
  leases(): Promise<SecretLease[]>;
  renewLease(id: string, incrementSeconds: number): Promise<SecretLease>;
  revokeLease(id: string): Promise<SecretLease>;
  audit(limit?: number): Promise<AuditEntry[]>;
  verifyAudit(): Promise<AuditVerificationResult>;
}

// The API rejects POSTs that are not JSON, so every POST sends this header.
const jsonHeaders = { 'Content-Type': 'application/json' };

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new Error('Could not reach the VaultMesh API. Check that the server is running.');
  }
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      payload && typeof payload.error === 'string' ? payload.error : `Request failed with status ${response.status}`;
    throw new Error(message);
  }

  return payload as T;
}

function post<T>(url: string, body?: unknown): Promise<T> {
  return request<T>(url, {
    method: 'POST',
    headers: jsonHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Encodes each path segment so the wildcard route receives the path unchanged. */
export function secretUrl(path: string): string {
  return `/api/secrets/${path.split('/').map(encodeURIComponent).join('/')}`;
}

export const httpApi: VaultApi = {
  status: () => request('/api/vault/status'),
  demoShares: () => request('/api/vault/demo-shares'),
  seal: () => post('/api/vault/seal'),
  unseal: (share) => post('/api/vault/unseal', { share }),
  resetUnseal: () => post('/api/vault/unseal/reset'),
  rotateKek: () => post('/api/vault/keks/rotate'),
  rewrapSecrets: () => post('/api/vault/keks/rewrap'),
  keks: () => request('/api/vault/keks'),
  secrets: () => request('/api/secrets'),
  readSecret: (path) => request(secretUrl(path)),
  createSecret: (dto) => post('/api/secrets', dto),
  deleteSecret: (path) => request(secretUrl(path), { method: 'DELETE' }),
  leases: () => request('/api/leases'),
  renewLease: (id, incrementSeconds) => post(`/api/leases/${encodeURIComponent(id)}/renew`, { incrementSeconds }),
  revokeLease: (id) => post(`/api/leases/${encodeURIComponent(id)}/revoke`),
  audit: (limit = 8) => request(`/api/audit?limit=${limit}`),
  verifyAudit: () => request('/api/audit/verify'),
};

/** True in the static GitHub Pages build, where the vault runs in the browser. */
export const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true';

// The one place that picks the backend for the whole dashboard.
export const api: VaultApi = isDemoMode ? demoApi : httpApi;

/** Clears the in-browser demo vault. Only available in demo mode. */
export const resetDemoData: (() => Promise<void>) | null = isDemoMode ? () => demoApi.reset() : null;
