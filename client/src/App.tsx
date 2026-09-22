import { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import type {
  AuditEntry,
  AuditVerificationResult,
  CreateSecretDto,
  DecryptedSecret,
  KekVersionInfo,
  ReadSecretOptions,
  SecretLease,
  StoredSecret,
  VaultState,
} from '../../shared/types';
import { api, isDemoMode, resetDemoData } from './services/api';
import { AuditLedger } from './components/AuditLedger';
import { CreateSecretForm } from './components/CreateSecretForm';
import { DemoBanner } from './components/DemoBanner';
import { LeaseList } from './components/LeaseList';
import { SecretDrawer } from './components/SecretDrawer';
import { UnsealPanel } from './components/UnsealPanel';
import { countLabel, errorMessage, formatDateTime, maskHex } from './components/format';

const REFRESH_INTERVAL_MS = 5000;
const AUDIT_ENTRIES_SHOWN = 8;
const DEFAULT_POLICY_PURPOSE = 'Incident follow-up';

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
  const [policyReview, setPolicyReview] = useState({ enabled: false, purpose: DEFAULT_POLICY_PURPOSE, approvalCode: '' });
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
      const options: ReadSecretOptions | undefined = policyReview.enabled
        ? { purpose: policyReview.purpose, approvalCode: policyReview.approvalCode }
        : undefined;
      const secret = await api.readSecret(path, options);
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
          : `Share accepted. ${countLabel(progress.sharesRemaining, 'more share', 'more shares')} needed.`
    );
  }

  function rewrapSecrets(): Promise<boolean> {
    return runAction(api.rewrapSecrets, ({ rewrappedCount, activeVersion }) =>
      rewrappedCount === 0
        ? `Nothing to re-wrap. Every secret already uses KEK v${activeVersion}.`
        : `Re-wrapped ${countLabel(rewrappedCount, 'secret')} to KEK v${activeVersion}`
    );
  }

  async function resetDemo() {
    if (!resetDemoData) return;
    if (!window.confirm('Reset the demo? Everything you changed in this browser is replaced with fresh sample data.')) return;
    setSelectedSecret(null);
    await runAction(resetDemoData, 'Demo data reset');
  }

  function createSecret(dto: CreateSecretDto): Promise<boolean> {
    return runAction(() => api.createSecret(dto), `Encrypted and stored ${dto.path.trim()}`);
  }

  const { state } = snapshot;
  const sealed = state?.status === 'SEALED';
  const staticSecrets = snapshot.secrets.filter((secret) => !secret.isDynamic).length;
  const outdatedSecrets = state ? snapshot.secrets.filter((secret) => secret.kekVersion < state.activeKekVersion).length : 0;

  return (
    <div className="app-shell">
      {isDemoMode ? <DemoBanner onReset={() => void resetDemo()} busy={busy} /> : null}

      <header className="app-header">
        <div className="header-inner">
          <div>
            <h1 className="brand-name">VaultMesh</h1>
            <p className="brand-subtitle">
              Envelope-encrypted secrets with custodian unseal, key rotation and dynamic leases.
            </p>
          </div>
          <div className="header-actions">
            <div className={`status-pill ${state ? state.status.toLowerCase() : 'loading'}`} role="status">
              <span aria-hidden="true" />
              {state ? state.status : 'Loading'}
            </div>
            <button type="button" className="btn btn-secondary" onClick={() => void seal()} disabled={busy || !state || sealed}>
              Seal
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void runAction(api.rotateKek, 'New KEK version created')}
              disabled={busy || !state || sealed}
            >
              Rotate KEK
            </button>
          </div>
        </div>
        {sealed ? (
          <p className="header-hint">Sealed: key operations stay disabled until the vault is unsealed.</p>
        ) : null}
      </header>

      <main className="app-main">
        {notice ? (
          <p className={`notice ${notice.kind}`} role={notice.kind === 'error' ? 'alert' : 'status'}>
            {notice.text}
          </p>
        ) : null}

        <section aria-labelledby="status-title">
          <div className="section-heading-row">
            <h2 id="status-title" className="section-heading">
              Vault status
            </h2>
            <button type="button" className="btn-icon" onClick={() => void refresh()} disabled={busy}>
              <RefreshCw size={16} aria-hidden="true" />
              Refresh
            </button>
          </div>
          <div className="stats-strip">
            <div className="stat-cell">
              <span className="stat-label">Total secrets</span>
              <span className="stat-value">{state?.totalSecrets ?? 0}</span>
            </div>
            <div className="stat-cell">
              <span className="stat-label">Static secrets</span>
              <span className="stat-value">{staticSecrets}</span>
            </div>
            <div className="stat-cell">
              <span className="stat-label">Active leases</span>
              <span className="stat-value">{state?.activeLeases ?? 0}</span>
            </div>
            <div className="stat-cell">
              <span className="stat-label">Active KEK</span>
              <span className="stat-value">v{state?.activeKekVersion ?? 0}</span>
            </div>
          </div>
        </section>

        <div className="grid">
          <section className="panel" aria-labelledby="secrets-title">
            <div className="panel-heading">
              <h2 id="secrets-title">Secret inventory</h2>
              <div className="panel-heading-meta">
                <span>{loading ? 'Loading' : countLabel(snapshot.secrets.length, 'path')}</span>
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => void rewrapSecrets()}
                  disabled={busy || !state || sealed}
                >
                  Re-wrap secrets{outdatedSecrets > 0 ? ` (${outdatedSecrets})` : ''}
                </button>
              </div>
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
                      <td className="mono">
                        v{secret.kekVersion}
                        {state && secret.kekVersion < state.activeKekVersion ? <small>needs re-wrap</small> : null}
                      </td>
                      <td className="mono" title={`Updated ${formatDateTime(secret.updatedAt)}`}>
                        {maskHex(secret.ciphertext)}
                      </td>
                      <td>
                        <div className="button-row">
                          <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={(event) => void inspectSecret(secret.path, event.currentTarget)}
                            disabled={sealed}
                            aria-label={`Inspect ${secret.path}`}
                          >
                            Inspect
                          </button>
                          <button
                            type="button"
                            className="btn btn-danger"
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
        </div>

        <section className="panel access-panel" aria-labelledby="access-policy-title">
          <div className="panel-heading">
            <h2 id="access-policy-title">Read access review</h2>
            <span className="muted">{policyReview.enabled ? 'Enabled' : 'Bypass'}</span>
          </div>
          <label className="check">
            <input
              type="checkbox"
              checked={policyReview.enabled}
              onChange={(event) => setPolicyReview((value) => ({ ...value, enabled: event.target.checked }))}
            />
            Simulate approval policy on inspect
          </label>
          <div className="field">
            <label htmlFor="read-purpose">Purpose</label>
            <input
              id="read-purpose"
              value={policyReview.purpose}
              onChange={(event) => setPolicyReview((value) => ({ ...value, purpose: event.target.value }))}
              disabled={!policyReview.enabled}
              maxLength={120}
            />
          </div>
          <div className="field">
            <label htmlFor="approval-code">Approval code</label>
            <input
              id="approval-code"
              value={policyReview.approvalCode}
              onChange={(event) => setPolicyReview((value) => ({ ...value, approvalCode: event.target.value }))}
              disabled={!policyReview.enabled}
              maxLength={40}
              placeholder="VM-APPROVED"
            />
          </div>
          <p className="hint">Sensitive sample paths require the approval code when this simulation is enabled.</p>
        </section>

        <div className="grid">
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
        </div>

        <div className="grid">
          <AuditLedger entries={snapshot.audit} verification={snapshot.auditVerification} />

          <section className="panel" aria-labelledby="keks-title">
            <div className="panel-heading">
              <h2 id="keks-title">Key versions</h2>
              <span className="muted">{countLabel(snapshot.keks.length, 'version')}</span>
            </div>
            <ul className="dense-list">
              {snapshot.keks.map((kek) => (
                <li key={kek.version} className="dense-row">
                  <div className="dense-row-main">
                    <strong>
                      KEK v{kek.version} <span className={kek.isActive ? 'tag active' : 'tag'}>{kek.isActive ? 'Active' : 'Historical'}</span>
                    </strong>
                    <small>
                      {countLabel(kek.secretsCount, 'secret')}, created {formatDateTime(kek.createdAt)}
                    </small>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </main>

      {selectedSecret ? <SecretDrawer secret={selectedSecret} onClose={closeDrawer} /> : null}

      <footer className="app-footer">
        <div>VaultMesh &bull; MIT License</div>
        <a href="https://github.com/Taan1el/vaultmesh" target="_blank" rel="noreferrer">
          Source on GitHub
        </a>
      </footer>
    </div>
  );
}
