import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  AuditEntry,
  AuditVerificationResult,
  CreateSecretDto,
  DecryptedSecret,
  KekVersionInfo,
  SecretLease,
  StoredSecret,
  VaultState,
} from '../../shared/types';
import { api } from './services/api';
import { AuditLedger } from './components/AuditLedger';
import { CreateSecretForm } from './components/CreateSecretForm';
import { LeaseList } from './components/LeaseList';
import { SecretDrawer } from './components/SecretDrawer';
import { UnsealPanel } from './components/UnsealPanel';
import { errorMessage, formatDateTime, maskHex } from './components/format';

const REFRESH_INTERVAL_MS = 5000;
const AUDIT_ENTRIES_SHOWN = 8;

interface Snapshot {
  state: VaultState | null;
  secrets: StoredSecret[];
  leases: SecretLease[];
  keks: KekVersionInfo[];
  audit: AuditEntry[];
  auditVerification: AuditVerificationResult | null;
  shares: string[];
}

type Notice = { kind: 'success' | 'error'; text: string } | null;

const emptySnapshot: Snapshot = {
  state: null,
  secrets: [],
  leases: [],
  keks: [],
  audit: [],
  auditVerification: null,
  shares: [],
};

export function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(emptySnapshot);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [selectedSecret, setSelectedSecret] = useState<DecryptedSecret | null>(null);
  const latestRefresh = useRef(0);
  const lastRefreshFailed = useRef(false);
  const drawerTrigger = useRef<HTMLElement | null>(null);

  const refresh = useCallback(async () => {
    const refreshId = ++latestRefresh.current;
    try {
      const [state, secrets, leases, keks, audit, auditVerification, shares] = await Promise.all([
        api.status(),
        api.secrets(),
        api.leases(),
        api.keks(),
        api.audit(AUDIT_ENTRIES_SHOWN),
        api.verifyAudit(),
        api.demoShares(),
      ]);
      // Ignore results from a refresh that a newer one has overtaken.
      if (refreshId !== latestRefresh.current) return;
      setSnapshot({ state, secrets, leases, keks, audit, auditVerification, shares: shares.shares });
      if (lastRefreshFailed.current) setNotice(null);
      lastRefreshFailed.current = false;
    } catch (error) {
      if (refreshId !== latestRefresh.current) return;
      if (!lastRefreshFailed.current) {
        setNotice({ kind: 'error', text: `Unable to load vault state. ${errorMessage(error, '')}`.trim() });
      }
      lastRefreshFailed.current = true;
    } finally {
      if (refreshId === latestRefresh.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    // Poll so lease expiry and changes made elsewhere show up without a manual refresh.
    const id = window.setInterval(() => {
      if (document.visibilityState !== 'hidden') void refresh();
    }, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  async function runAction<T>(action: () => Promise<T>, success: string | ((result: T) => string)): Promise<boolean> {
    setBusy(true);
    setNotice(null);
    let ok = false;
    try {
      const result = await action();
      setNotice({ kind: 'success', text: typeof success === 'function' ? success(result) : success });
      ok = true;
    } catch (error) {
      setNotice({ kind: 'error', text: errorMessage(error, 'Action failed') });
    }
    await refresh();
    setBusy(false);
    return ok;
  }

  const closeDrawer = useCallback(() => {
    setSelectedSecret(null);
    drawerTrigger.current?.focus();
    drawerTrigger.current = null;
  }, []);

  async function inspectSecret(path: string, trigger: HTMLElement) {
    setNotice(null);
    try {
      const secret = await api.readSecret(path);
      drawerTrigger.current = trigger;
      setSelectedSecret(secret);
    } catch (error) {
      setNotice({ kind: 'error', text: errorMessage(error, 'Unable to read secret') });
    }
    // Reading a dynamic secret can issue a lease and always adds an audit entry.
    await refresh();
  }

  async function deleteSecret(secret: StoredSecret) {
    if (!window.confirm(`Delete ${secret.path}? Its leases are removed too. This cannot be undone.`)) return;
    if (selectedSecret?.id === secret.id) closeDrawer();
    await runAction(() => api.deleteSecret(secret.path), `Deleted ${secret.path}`);
  }

  async function seal() {
    // Sealing clears keys on the server, so stop showing decrypted data as well.
    setSelectedSecret(null);
    await runAction(api.seal, 'Vault sealed');
  }

  function submitShare(share: string): Promise<boolean> {
    return runAction(
      () => api.unseal(share),
      (progress) =>
        progress.unsealed
          ? 'Vault unsealed'
          : `Share accepted. ${progress.sharesRemaining} more ${progress.sharesRemaining === 1 ? 'share' : 'shares'} needed.`
    );
  }

  function rewrapSecrets(): Promise<boolean> {
    return runAction(api.rewrapSecrets, ({ rewrappedCount, activeVersion }) =>
      rewrappedCount === 0
        ? `Nothing to re-wrap. Every secret already uses KEK v${activeVersion}.`
        : `Re-wrapped ${rewrappedCount} ${rewrappedCount === 1 ? 'secret' : 'secrets'} to KEK v${activeVersion}`
    );
  }

  function createSecret(dto: CreateSecretDto): Promise<boolean> {
    return runAction(() => api.createSecret(dto), `Encrypted and stored ${dto.path.trim()}`);
  }

  const { state } = snapshot;
  const sealed = state?.status === 'SEALED';
  const staticSecrets = snapshot.secrets.filter((secret) => !secret.isDynamic).length;
  const outdatedSecrets = state ? snapshot.secrets.filter((secret) => secret.kekVersion < state.activeKekVersion).length : 0;

  return (
    <main className="shell">
      <section className="masthead" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">VaultMesh</p>
          <h1 id="page-title">Secrets operations console</h1>
          <p className="lede">
            Store envelope-encrypted secrets, walk through a custodian unseal, rotate and re-wrap keys, manage dynamic
            leases and check the tamper-evident audit chain.
          </p>
        </div>
        <div className={`status-pill ${state ? state.status.toLowerCase() : 'loading'}`} role="status">
          <span aria-hidden="true" />
          {state ? state.status : 'Loading'}
        </div>
      </section>

      <section className="toolbar" aria-label="Vault actions">
        <button type="button" onClick={() => void refresh()} disabled={busy}>
          Refresh
        </button>
        <button type="button" onClick={() => void seal()} disabled={busy || !state || sealed}>
          Seal
        </button>
        <button
          type="button"
          onClick={() => void runAction(api.rotateKek, 'New KEK version created')}
          disabled={busy || !state || sealed}
        >
          Rotate KEK
        </button>
        <button type="button" onClick={() => void rewrapSecrets()} disabled={busy || !state || sealed}>
          Re-wrap secrets{outdatedSecrets > 0 ? ` (${outdatedSecrets})` : ''}
        </button>
        {sealed ? <p className="hint toolbar-hint">Sealed: key operations stay disabled until the vault is unsealed.</p> : null}
      </section>

      {notice ? (
        <p className={`notice ${notice.kind}`} role={notice.kind === 'error' ? 'alert' : 'status'}>
          {notice.text}
        </p>
      ) : null}

      <section className="metrics" aria-label="Vault metrics">
        <article>
          <span>{state?.totalSecrets ?? 0}</span>
          <p>Total secrets</p>
        </article>
        <article>
          <span>{staticSecrets}</span>
          <p>Static secrets</p>
        </article>
        <article>
          <span>{state?.activeLeases ?? 0}</span>
          <p>Active leases</p>
        </article>
        <article>
          <span>v{state?.activeKekVersion ?? 0}</span>
          <p>Active KEK</p>
        </article>
      </section>

      <div className="grid">
        <section className="panel" aria-labelledby="secrets-title">
          <div className="panel-heading">
            <h2 id="secrets-title">Secret inventory</h2>
            <span>{loading ? 'Loading' : `${snapshot.secrets.length} paths`}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Path</th>
                  <th scope="col">KEK</th>
                  <th scope="col">Ciphertext</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {!loading && snapshot.secrets.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="muted">
                      No secrets stored yet.
                    </td>
                  </tr>
                ) : null}
                {snapshot.secrets.map((secret) => (
                  <tr key={secret.id}>
                    <td>
                      <strong>
                        {secret.name}
                        {secret.isDynamic ? <span className="tag">Dynamic</span> : null}
                      </strong>
                      <small>{secret.path}</small>
                    </td>
                    <td>
                      v{secret.kekVersion}
                      {state && secret.kekVersion < state.activeKekVersion ? <small>needs re-wrap</small> : null}
                    </td>
                    <td className="mono" title={`Updated ${formatDateTime(secret.updatedAt)}`}>
                      {maskHex(secret.ciphertext)}
                    </td>
                    <td>
                      <div className="button-row compact">
                        <button
                          type="button"
                          className="small"
                          onClick={(event) => void inspectSecret(secret.path, event.currentTarget)}
                          disabled={sealed}
                          aria-label={`Inspect ${secret.path}`}
                        >
                          Inspect
                        </button>
                        <button
                          type="button"
                          className="small secondary"
                          onClick={() => void deleteSecret(secret)}
                          disabled={busy || sealed}
                          aria-label={`Delete ${secret.path}`}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <CreateSecretForm disabled={busy || !state || sealed} onCreate={createSecret} />

        <UnsealPanel
          state={state}
          shares={snapshot.shares}
          busy={busy}
          onSubmit={submitShare}
          onReset={() => void runAction(api.resetUnseal, 'Submitted shares cleared')}
        />

        <LeaseList
          leases={snapshot.leases}
          disabled={busy || sealed}
          onRenew={(lease) => void runAction(() => api.renewLease(lease.id, 30), `Lease for ${lease.secretPath} renewed`)}
          onRevoke={(lease) => void runAction(() => api.revokeLease(lease.id), `Lease for ${lease.secretPath} revoked`)}
        />

        <section className="panel" aria-labelledby="keks-title">
          <div className="panel-heading">
            <h2 id="keks-title">Key versions</h2>
            <span>{snapshot.keks.length} versions</span>
          </div>
          <ul className="stack-list">
            {snapshot.keks.map((kek) => (
              <li key={kek.version} className="list-item">
                <div>
                  <strong>KEK v{kek.version}</strong>
                  <small>
                    {kek.secretsCount} {kek.secretsCount === 1 ? 'secret' : 'secrets'}, created {formatDateTime(kek.createdAt)}
                  </small>
                </div>
                <span className={kek.isActive ? 'tag active' : 'tag'}>{kek.isActive ? 'Active' : 'Historical'}</span>
              </li>
            ))}
          </ul>
        </section>

        <AuditLedger entries={snapshot.audit} verification={snapshot.auditVerification} />
      </div>

      {selectedSecret ? <SecretDrawer secret={selectedSecret} onClose={closeDrawer} /> : null}
    </main>
  );
}
