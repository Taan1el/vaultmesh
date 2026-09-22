import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  AuditEntry,
  AuditVerificationResult,
  DecryptedSecret,
  SecretLease,
  StoredSecret,
  VaultState,
} from '../../shared/types';
import type { VaultApi } from './services/api';
import { App } from './App';

const mocks = vi.hoisted(() => ({
  api: {} as VaultApi,
  demoMode: false,
  resetDemoData: null as null | (() => Promise<void>),
}));
vi.mock('./services/api', () => ({
  api: mocks.api,
  get isDemoMode() {
    return mocks.demoMode;
  },
  get resetDemoData() {
    return mocks.demoMode ? mocks.resetDemoData : null;
  },
}));

const now = Date.now();
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString();
const shares = [1, 2, 3, 4, 5].map((i) => `vmshare-0${i}-${String(i).repeat(64)}`);

function storedSecret(overrides: Partial<StoredSecret>): StoredSecret {
  return {
    id: 'sec_1',
    path: 'secret/test/api',
    name: 'Test API key',
    description: '',
    kekVersion: 1,
    encryptedDek: 'aa:bb:cc',
    iv: 'iv',
    authTag: 'tag',
    ciphertext: 'abcdef1234567890abcdef1234567890',
    version: 1,
    isDynamic: false,
    ttlSeconds: 0,
    maxTtlSeconds: 0,
    createdAt: iso(-60_000),
    updatedAt: iso(-60_000),
    ...overrides,
  };
}

function createFakeApi() {
  const vault: VaultState = {
    status: 'UNSEALED',
    threshold: 3,
    totalShares: 5,
    sharesSubmitted: 0,
    submittedShareIndexes: [],
    activeKekVersion: 1,
    totalSecrets: 2,
    activeLeases: 1,
    isInitialized: true,
  };
  let secrets = [
    storedSecret({}),
    storedSecret({ id: 'sec_2', path: 'secret/dynamic/token', name: 'Deploy token', isDynamic: true, ttlSeconds: 60 }),
  ];
  const leases: SecretLease[] = [
    {
      id: 'lease_active',
      secretId: 'sec_2',
      secretPath: 'secret/dynamic/token',
      issuedAt: iso(-10_000),
      expiresAt: iso(50_000),
      ttlSeconds: 60,
      renewCount: 0,
      maxRenewals: 5,
      status: 'ACTIVE',
    },
    {
      id: 'lease_old',
      secretId: 'sec_2',
      secretPath: 'secret/dynamic/token',
      issuedAt: iso(-200_000),
      expiresAt: iso(-140_000),
      ttlSeconds: 60,
      renewCount: 1,
      maxRenewals: 5,
      status: 'EXPIRED',
    },
  ];
  const audit: AuditEntry[] = [
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
  ];
  let verification: AuditVerificationResult = { isValid: true, totalEntries: 1, verifiedAt: iso(0) };

  const api = {
    status: vi.fn(async () => ({ ...vault, submittedShareIndexes: [...vault.submittedShareIndexes] })),
    demoShares: vi.fn(async () => ({ shares })),
    seal: vi.fn(async () => {
      vault.status = 'SEALED';
      return { message: 'Vault sealed', state: { ...vault } };
    }),
    unseal: vi.fn(async (share: string) => {
      const index = parseInt(share.slice(8, 10), 16);
      vault.submittedShareIndexes.push(index);
      vault.sharesSubmitted = vault.submittedShareIndexes.length;
      const unsealed = vault.sharesSubmitted >= 3;
      if (unsealed) {
        vault.status = 'UNSEALED';
        vault.submittedShareIndexes = [];
        vault.sharesSubmitted = 0;
      }
      return {
        status: vault.status,
        sharesSubmitted: unsealed ? 3 : vault.sharesSubmitted,
        submittedShareIndexes: [...vault.submittedShareIndexes],
        threshold: 3,
        sharesRemaining: unsealed ? 0 : 3 - vault.sharesSubmitted,
        unsealed,
      };
    }),
    resetUnseal: vi.fn(async () => {
      vault.submittedShareIndexes = [];
      vault.sharesSubmitted = 0;
      return { message: 'Unseal attempts reset' };
    }),
    rotateKek: vi.fn(async () => {
      vault.activeKekVersion += 1;
      return { version: vault.activeKekVersion, createdAt: iso(0), secretsCount: 0, isActive: true };
    }),
    rewrapSecrets: vi.fn(async () => ({ rewrappedCount: 2, activeVersion: vault.activeKekVersion })),
    keks: vi.fn(async () => [{ version: 1, createdAt: iso(-60_000), secretsCount: 2, isActive: true }]),
    secrets: vi.fn(async () => secrets),
    readSecret: vi.fn(
      async (path: string): Promise<DecryptedSecret> => ({
        id: 'sec_1',
        path,
        name: 'Test API key',
        description: '',
        kekVersion: 1,
        plaintext: '{"token":"example-token-not-real"}',
        parsedData: { token: 'example-token-not-real' },
        access: {
          status: 'ALLOWED',
          reason: 'No approval gate matched this path',
          purpose: 'Direct operator read',
          approvalCodeRequired: false,
        },
        version: 1,
        isDynamic: false,
        createdAt: iso(-60_000),
        updatedAt: iso(-60_000),
      })
    ),
    createSecret: vi.fn(async (dto) => storedSecret({ id: 'sec_new', path: dto.path, name: dto.name })),
    deleteSecret: vi.fn(async (path: string) => {
      secrets = secrets.filter((s) => s.path !== path);
      return { message: 'Secret deleted', path };
    }),
    leases: vi.fn(async () => leases),
    renewLease: vi.fn(async (id: string) => ({ ...leases[0], id, renewCount: 1 })),
    revokeLease: vi.fn(async (id: string) => ({ ...leases[0], id, status: 'REVOKED' as const })),
    audit: vi.fn(async () => audit),
    verifyAudit: vi.fn(async () => verification),
  };

  return {
    api,
    vault,
    breakAuditChain: () => {
      verification = { isValid: false, totalEntries: 9, brokenIndex: 4, verifiedAt: iso(0) };
    },
  };
}

let fake: ReturnType<typeof createFakeApi>;

beforeEach(() => {
  fake = createFakeApi();
  Object.assign(mocks.api, fake.api);
  mocks.demoMode = false;
  mocks.resetDemoData = null;
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function renderLoaded() {
  render(<App />);
  expect(await screen.findByText('Test API key')).toBeInTheDocument();
}

describe('App', () => {
  it('shows vault state, inventory, lease countdowns and the audit check', async () => {
    await renderLoaded();

    expect(screen.getByRole('status', { name: '' })).toHaveTextContent('UNSEALED');
    expect(screen.getByText('secret/dynamic/token', { selector: 'td small' })).toBeInTheDocument();
    expect(screen.getByText(/Expires in (49|50) s/)).toBeInTheDocument();
    expect(screen.getByText(/Expired at/)).toBeInTheDocument();
    expect(screen.getByText('Chain verified, 1 entry')).toBeInTheDocument();
    expect(screen.getByText('1 version')).toBeInTheDocument();
    expect(screen.getByText('2 paths')).toBeInTheDocument();
    // Only the active lease offers renew and revoke.
    expect(screen.getAllByRole('button', { name: /Renew lease/ })).toHaveLength(1);
  });

  it('opens the decrypted value in a dialog and returns focus when closed with Escape', async () => {
    await renderLoaded();
    const inspect = screen.getByRole('button', { name: 'Inspect secret/test/api' });

    fireEvent.click(inspect);

    const dialog = await screen.findByRole('dialog', { name: 'Test API key' });
    expect(within(dialog).getByText(/"token": "example-token-not-real"/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Access: No approval gate matched this path/)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Close' })).toHaveFocus();
    expect(fake.api.readSecret).toHaveBeenCalledWith('secret/test/api', undefined);

    fireEvent.keyDown(document, { key: 'Escape' });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(inspect).toHaveFocus();
  });

  it('passes purpose and approval code when read access review is enabled', async () => {
    await renderLoaded();

    fireEvent.click(screen.getByLabelText('Simulate approval policy on inspect'));
    fireEvent.change(screen.getByLabelText('Purpose'), { target: { value: 'Customer incident review' } });
    fireEvent.change(screen.getByLabelText('Approval code'), { target: { value: 'VM-APPROVED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect secret/test/api' }));

    await screen.findByRole('dialog', { name: 'Test API key' });
    expect(fake.api.readSecret).toHaveBeenCalledWith('secret/test/api', {
      purpose: 'Customer incident review',
      approvalCode: 'VM-APPROVED',
    });
  });

  it('creates a secret, confirms it and clears the form', async () => {
    await renderLoaded();
    const path = screen.getByLabelText('Path');
    fireEvent.change(path, { target: { value: 'secret/ci/token' } });

    fireEvent.click(screen.getByRole('button', { name: 'Encrypt secret' }));

    expect(await screen.findByText('Encrypted and stored secret/ci/token')).toHaveAttribute('role', 'status');
    expect(fake.api.createSecret).toHaveBeenCalledWith(
      expect.objectContaining({ path: 'secret/ci/token', name: 'Reporting API token', isDynamic: false })
    );
    expect(screen.getByLabelText('Path')).toHaveValue('');
  });

  it('shows API errors as alerts and keeps the form input', async () => {
    fake.api.createSecret.mockRejectedValueOnce(new Error('Secret at path "secret/apps/reporting" already exists'));
    await renderLoaded();

    fireEvent.click(screen.getByRole('button', { name: 'Encrypt secret' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('already exists');
    expect(screen.getByLabelText('Path')).toHaveValue('secret/apps/reporting');
  });

  it('sends TTL only for dynamic secrets', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByLabelText('Issue a dynamic lease'));
    fireEvent.change(screen.getByLabelText('Lease TTL (seconds)'), { target: { value: '120' } });

    fireEvent.click(screen.getByRole('button', { name: 'Encrypt secret' }));

    await waitFor(() =>
      expect(fake.api.createSecret).toHaveBeenCalledWith(expect.objectContaining({ isDynamic: true, ttlSeconds: 120 }))
    );
  });

  it('seals the vault, hides decrypted data and disables key operations', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect secret/test/api' }));
    await screen.findByRole('dialog');

    fireEvent.click(screen.getByRole('button', { name: 'Seal' }));

    expect(await screen.findByText('Vault sealed')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Rotate KEK' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Inspect secret/test/api' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Encrypt secret' })).toBeDisabled();
  });

  it('unseals with sample shares, skipping shares that were already submitted', async () => {
    fake.vault.status = 'SEALED';
    fake.vault.submittedShareIndexes = [1];
    fake.vault.sharesSubmitted = 1;
    await renderLoaded();

    expect(screen.getByText('1 of 3 shares')).toBeInTheDocument();
    const shareInput = screen.getByLabelText('Custodian share');

    fireEvent.click(screen.getByRole('button', { name: 'Load next sample share' }));
    expect(shareInput).toHaveValue(shares[1]);

    fireEvent.click(screen.getByRole('button', { name: 'Submit share' }));
    expect(await screen.findByText('Share accepted. 1 more share needed.')).toBeInTheDocument();
    expect(screen.getByLabelText('Custodian share')).toHaveValue('');

    fireEvent.click(screen.getByRole('button', { name: 'Load next sample share' }));
    expect(screen.getByLabelText('Custodian share')).toHaveValue(shares[2]);
    fireEvent.click(screen.getByRole('button', { name: 'Submit share' }));

    expect(await screen.findByText('Vault unsealed')).toBeInTheDocument();
    expect(fake.api.unseal).toHaveBeenLastCalledWith(shares[2]);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Rotate KEK' })).toBeEnabled());
  });

  it('clears submitted shares on request', async () => {
    fake.vault.status = 'SEALED';
    fake.vault.submittedShareIndexes = [2];
    fake.vault.sharesSubmitted = 1;
    await renderLoaded();

    fireEvent.click(screen.getByRole('button', { name: 'Clear submitted shares' }));

    expect(await screen.findByText('Submitted shares cleared')).toBeInTheDocument();
    expect(fake.api.resetUnseal).toHaveBeenCalledTimes(1);
    expect(screen.getByText('0 of 3 shares')).toBeInTheDocument();
  });

  it('renews and revokes the active lease', async () => {
    await renderLoaded();

    fireEvent.click(screen.getByRole('button', { name: 'Renew lease for secret/dynamic/token' }));
    expect(await screen.findByText('Lease for secret/dynamic/token renewed')).toBeInTheDocument();
    expect(fake.api.renewLease).toHaveBeenCalledWith('lease_active', 30);

    fireEvent.click(screen.getByRole('button', { name: 'Revoke lease for secret/dynamic/token' }));
    expect(await screen.findByText('Lease for secret/dynamic/token revoked')).toBeInTheDocument();
    expect(fake.api.revokeLease).toHaveBeenCalledWith('lease_active');
  });

  it('deletes a secret only after confirmation', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    await renderLoaded();

    fireEvent.click(screen.getByRole('button', { name: 'Delete secret/test/api' }));
    expect(fake.api.deleteSecret).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Delete secret/test/api' }));
    expect(await screen.findByText('Deleted secret/test/api')).toBeInTheDocument();
    expect(confirm).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(screen.queryByText('Test API key')).not.toBeInTheDocument());
  });

  it('reports the re-wrap count from the API', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByRole('button', { name: /Re-wrap secrets/ }));
    expect(await screen.findByText('Re-wrapped 2 secrets to KEK v1')).toBeInTheDocument();
  });

  it('hides the demo banner when running against the API', async () => {
    await renderLoaded();
    expect(screen.queryByRole('complementary', { name: 'Demo mode' })).not.toBeInTheDocument();
  });

  it('shows the demo banner and resets demo data after confirmation', async () => {
    mocks.demoMode = true;
    mocks.resetDemoData = vi.fn(async () => {});
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    await renderLoaded();

    const banner = screen.getByRole('complementary', { name: 'Demo mode' });
    expect(banner).toHaveTextContent('Demo: everything runs in your browser with sample data.');
    expect(within(banner).getByRole('link', { name: 'Source on GitHub' })).toHaveAttribute(
      'href',
      'https://github.com/Taan1el/vaultmesh'
    );

    fireEvent.click(within(banner).getByRole('button', { name: 'Reset sample data' }));

    expect(await screen.findByText('Demo data reset')).toBeInTheDocument();
    expect(mocks.resetDemoData).toHaveBeenCalledTimes(1);
  });

  it('flags a broken audit chain', async () => {
    fake.breakAuditChain();
    await renderLoaded();
    expect(screen.getByText('Chain broken at entry 5')).toHaveClass('danger-text');
  });

  it('shows one alert when the vault state cannot be loaded and recovers on the next refresh', async () => {
    fake.api.status.mockRejectedValueOnce(new Error('Could not reach the VaultMesh API. Check that the server is running.'));
    render(<App />);

    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load vault state. Could not reach the VaultMesh API.');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
    expect(screen.getByText('Test API key')).toBeInTheDocument();
  });
});
