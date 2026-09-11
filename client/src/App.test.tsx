import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';

const routes: Record<string, unknown> = {
  '/api/vault/status': {
    status: 'UNSEALED',
    threshold: 3,
    totalShares: 5,
    sharesSubmitted: 0,
    activeKekVersion: 1,
    totalSecrets: 1,
    activeLeases: 1,
    isInitialized: true,
  },
  '/api/secrets': [
    {
      id: 'sec_1',
      path: 'secret/test/api',
      name: 'Test API Key',
      description: 'Example secret',
      kekVersion: 1,
      encryptedDek: 'dek',
      iv: 'iv',
      authTag: 'tag',
      ciphertext: 'abcdef1234567890abcdef1234567890',
      version: 1,
      isDynamic: false,
      ttlSeconds: 0,
      maxTtlSeconds: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ],
  '/api/leases': [
    {
      id: 'lease_1',
      secretId: 'sec_2',
      secretPath: 'secret/dynamic/token',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
      ttlSeconds: 60,
      renewCount: 0,
      maxRenewals: 5,
      status: 'ACTIVE',
    },
  ],
  '/api/vault/keks': [{ version: 1, createdAt: new Date().toISOString(), secretsCount: 1, isActive: true }],
  '/api/audit?limit=8': [
    {
      id: 'aud_1',
      timestamp: new Date().toISOString(),
      action: 'VAULT_INIT',
      actor: 'system',
      ip: '127.0.0.1',
      status: 'SUCCESS',
      details: 'Vault initialized',
      previousHash: '0',
      entryHash: 'abc123def456abc123def456',
    },
  ],
  '/api/audit/verify': { isValid: true, totalEntries: 1, verifiedAt: new Date().toISOString() },
  '/api/vault/demo-shares': { shares: ['vmshare-01-aabbcc'] },
};

describe('App', () => {
  it('renders vault state and loaded secret inventory', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(routes[url]),
        });
      })
    );

    render(<App />);

    expect(await screen.findByText('UNSEALED')).toBeInTheDocument();
    expect(screen.getByText('Test API Key')).toBeInTheDocument();
    expect(screen.getByText('Dynamic leases')).toBeInTheDocument();
    expect(screen.getByText('Verified')).toBeInTheDocument();
  });
});
