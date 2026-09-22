import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpApi, secretUrl } from './api';

function mockFetch(response: { ok: boolean; status: number; body?: unknown; invalidJson?: boolean }) {
  const fetchMock = vi.fn(async () => ({
    ok: response.ok,
    status: response.status,
    json: async () => {
      if (response.invalidJson) throw new SyntaxError('Unexpected token <');
      return response.body;
    },
  }));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('httpApi', () => {
  it('sends POSTs as JSON, including bodiless ones', async () => {
    const fetchMock = mockFetch({ ok: true, status: 200, body: { message: 'Vault sealed' } });

    await httpApi.seal();
    await httpApi.renewLease('lease_1', 45);

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/vault/seal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: undefined,
    });
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/leases/lease_1/renew', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"incrementSeconds":45}',
    });
  });

  it('uses the error message from the API response', async () => {
    mockFetch({ ok: false, status: 409, body: { error: 'Secret at path "secret/a" already exists' } });
    await expect(httpApi.createSecret({ path: 'secret/a', name: 'A', plaintext: 'x' })).rejects.toThrow(
      'Secret at path "secret/a" already exists'
    );
  });

  it('falls back to the status code when the error body is not JSON', async () => {
    mockFetch({ ok: false, status: 502, invalidJson: true });
    await expect(httpApi.status()).rejects.toThrow('Request failed with status 502');
  });

  it('explains network failures', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))));
    await expect(httpApi.secrets()).rejects.toThrow('Could not reach the VaultMesh API');
  });

  it('builds secret URLs segment by segment', async () => {
    expect(secretUrl('secret/apps/web')).toBe('/api/secrets/secret/apps/web');
    expect(secretUrl('secret/a b/c#d')).toBe('/api/secrets/secret/a%20b/c%23d');

    const fetchMock = mockFetch({ ok: true, status: 200, body: { message: 'Secret deleted', path: 'secret/x' } });
    await httpApi.deleteSecret('secret/x');
    expect(fetchMock).toHaveBeenCalledWith('/api/secrets/secret/x', { method: 'DELETE' });
  });

  it('adds read policy parameters to secret reads', async () => {
    const fetchMock = mockFetch({ ok: true, status: 200, body: {} });
    await httpApi.readSecret('secret/production/database', {
      purpose: 'Incident follow-up',
      approvalCode: 'VM-APPROVED',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/secrets/secret/production/database?purpose=Incident+follow-up&approvalCode=VM-APPROVED',
      undefined
    );
  });

  it('asks for a limited number of audit entries', async () => {
    const fetchMock = mockFetch({ ok: true, status: 200, body: [] });
    await httpApi.audit();
    await httpApi.audit(20);
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/audit?limit=8', undefined);
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/audit?limit=20', undefined);
  });
});
