import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { VaultApi } from './services/api';
import { App } from './App';
import { axe } from './test/axe';

const mocks = vi.hoisted(() => ({ api: {} as VaultApi }));
vi.mock('./services/api', () => ({
  api: mocks.api,
  isDemoMode: false,
  resetDemoData: null,
}));

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

beforeEach(() => {
  const secret = {
    id: 'sec_1',
    path: 'secret/test/api',
    name: 'Test API key',
    description: '',
    kekVersion: 1,
    encryptedDek: 'aa:bb:cc',
    iv: 'iv',
    authTag: 'tag',
    ciphertext: 'abcdef1234567890',
    version: 1,
    isDynamic: false,
    ttlSeconds: 0,
    maxTtlSeconds: 0,
    createdAt: iso(-60_000),
    updatedAt: iso(-60_000),
  };
  const lease = {
    id: 'lease_active',
    secretId: 'sec_2',
    secretPath: 'secret/dynamic/token',
    issuedAt: iso(-10_000),
    expiresAt: iso(50_000),
    ttlSeconds: 60,
    renewCount: 0,
    maxRenewals: 5,
    status: 'ACTIVE' as const,
  };
  Object.assign(mocks.api, {
    status: vi.fn(async () => ({
      status: 'UNSEALED',
      threshold: 3,
      totalShares: 5,
      sharesSubmitted: 0,
      submittedShareIndexes: [],
      activeKekVersion: 1,
      totalSecrets: 1,
      activeLeases: 1,
      isInitialized: true,
    })),
    demoShares: vi.fn(async () => ({ shares: [] })),
    keks: vi.fn(async () => [{ version: 1, createdAt: iso(-60_000), secretsCount: 1, isActive: true }]),
    secrets: vi.fn(async () => [secret]),
    readSecret: vi.fn(async (path: string) => ({
      ...secret,
      path,
      plaintext: '{"token":"example-token-not-real"}',
      parsedData: { token: 'example-token-not-real' },
      access: {
        status: 'ALLOWED',
        reason: 'No approval gate matched this path',
        purpose: 'Direct operator read',
        approvalCodeRequired: false,
      },
    })),
    leases: vi.fn(async () => [lease]),
    audit: vi.fn(async () => [
      {
        id: 'aud_1',
        timestamp: iso(-5_000),
        action: 'VAULT_INIT',
        actor: 'system/bootstrap',
        ip: '127.0.0.1',
        status: 'SUCCESS',
        details: 'Vault initialized',
        previousHash: '0'.repeat(64),
        entryHash: 'abc123def456abc123def456',
      },
    ]),
    verifyAudit: vi.fn(async () => ({ isValid: true, totalEntries: 1, verifiedAt: iso(0) })),
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function renderLoaded() {
  const user = userEvent.setup();
  const { container } = render(<App />);
  await screen.findByText('Test API key');
  const go = (section: string) =>
    user.click(
      within(screen.getByRole('navigation', { name: 'Sections' })).getByRole('button', { name: new RegExp(`^${section}`) })
    );
  return { container, user, go };
}

describe('accessibility', () => {
  it.each(['Status', 'Secrets', 'Keys', 'Leases', 'Audit'])('has no violations on the %s section', async (section) => {
    const { container, go } = await renderLoaded();
    await go(section);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('has no violations with the secret drawer open', async () => {
    const { user } = await renderLoaded();
    await user.click(screen.getByRole('button', { name: 'Inspect secret/test/api' }));
    await screen.findByRole('dialog', { name: 'Test API key' });
    expect(await axe(document.body)).toHaveNoViolations();
  });
});
