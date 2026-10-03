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

type SectionId = 'status' | 'secrets' | 'keys' | 'leases' | 'audit';

const SECTIONS: { id: SectionId; label: string; lede: string }[] = [
  { id: 'status', label: 'Status', lede: 'Seal state, custodian shares and the numbers behind the vault.' },
  { id: 'secrets', label: 'Secrets', lede: 'Every stored path with the key version that wraps it.' },
  { id: 'keys', label: 'Keys', lede: 'Key versions, rotation and re-wrapping.' },
  { id: 'leases', label: 'Leases', lede: 'Short-lived credentials issued from dynamic secrets.' },
  { id: 'audit', label: 'Audit', lede: 'A hash-chained record of every vault operation.' },
];

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
  const [section, setSection] = useState<SectionId>('secrets');
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
  const activeLeaseCount = snapshot.leases.filter((lease) => lease.status === 'ACTIVE').length;
  const secretsOnActiveKey = snapshot.secrets.length - outdatedSecrets;
  const activeSection = SECTIONS.find((item) => item.id === section) ?? SECTIONS[1];
  const railCounts: Record<SectionId, string> = {
    status: state ? (sealed ? 'Sealed' : 'Open') : '-',
    secrets: String(snapshot.secrets.length),
    keys: String(snapshot.keks.length),
    leases: String(activeLeaseCount),
    audit: String(snapshot.auditVerification?.totalEntries ?? snapshot.audit.length),
  };

  return (
    <div className="app-shell">
      {isDemoMode ? <DemoBanner onReset={() => void resetDemo()} busy={busy} /> : null}

      <div className="frame">
        <aside className="rail">
          <div className="rail-brand">
            <h1 className="brand-name">VaultMesh</h1>
            <p className="brand-subtitle">Envelope-encrypted secrets with custodian unseal, key rotation and dynamic leases.</p>
          </div>
          <nav className="rail-nav" aria-label="Sections">
            <ul>
              {SECTIONS.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className="rail-link"
                    aria-current={item.id === section ? 'page' : undefined}
                    onClick={() => setSection(item.id)}
                  >
                    <span>{item.label}</span>
                    <span className="rail-count">{railCounts[item.id]}</span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <div className="rail-foot">
            <div>MIT License</div>
            <a href="https://github.com/Taan1el/vaultmesh" target="_blank" rel="noreferrer">
              Source on GitHub
            </a>
          </div>
        </aside>

        <main className="app-main">
          <header className="topbar">
            <div>
              <h2 className="page-title">{activeSection.label}</h2>
              <p className="page-lede">{activeSection.lede}</p>
            </div>
            <div className="topbar-actions">
              <div className={`status-pill ${state ? state.status.toLowerCase() : 'loading'}`} role="status">
                <span aria-hidden="true" />
                {state ? state.status : 'Loading'}
              </div>
              <button type="button" className="btn-icon" onClick={() => void refresh()} disabled={busy}>
                <RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />
                Refresh
              </button>
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
          </header>
          {sealed ? <p className="header-hint">Sealed: key operations stay disabled until the vault is unsealed.</p> : null}

          {notice ? (
            <p className={`notice ${notice.kind}`} role={notice.kind === 'error' ? 'alert' : 'status'}>
              {notice.text}
            </p>
          ) : null}

          {section === 'status' ? (
            <div className="section">
              <div className="split wide-left">
                <section className="panel" aria-labelledby="status-title">
                  <div className="panel-heading">
                    <h3 id="status-title">Vault status</h3>
                  </div>
                  <dl className="ledger">
                    <div className="ledger-row">
                      <dt>Total secrets</dt>
                      <dd>{state?.totalSecrets ?? 0}</dd>
                    </div>
                    <div className="ledger-row">
                      <dt>Static secrets</dt>
                      <dd>{staticSecrets}</dd>
                    </div>
                    <div className="ledger-row">
                      <dt>Active leases</dt>
                      <dd>{state?.activeLeases ?? 0}</dd>
                    </div>
                    <div className="ledger-row">
                      <dt>Active KEK</dt>
                      <dd>v{state?.activeKekVersion ?? 0}</dd>
                    </div>
                  </dl>
                </section>
                <UnsealPanel
                  state={state}
                  shares={snapshot.shares}
                  busy={busy}
                  onSubmit={submitShare}
                  onReset={() => void runAction(api.resetUnseal, 'Submitted shares cleared')}
                />
              </div>
            </div>
          ) : null}

          {section === 'secrets' ? (
            <div className="section">
              <section className="panel" aria-labelledby="secrets-title">
                <div className="panel-heading">
                  <h3 id="secrets-title">Secret inventory</h3>
                  <div className="panel-heading-meta">
                    <span>{loading ? 'Loading' : countLabel(snapshot.secrets.length, 'path')}</span>
                  </div>
                </div>
                <div className="table-wrap" role="region" tabIndex={0} aria-label="Secrets table">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col" className="col-index">
                          No.
                        </th>
                        <th scope="col">Path</th>
                        <th scope="col">Key</th>
                        <th scope="col">Ciphertext</th>
                        <th scope="col" className="col-actions">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {!loading && snapshot.secrets.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="muted">
                            No secrets stored yet.
                          </td>
                        </tr>
                      ) : null}
                      {snapshot.secrets.map((secret, index) => (
                        <tr key={secret.id}>
                          <td className="col-index">{String(index + 1).padStart(2, '0')}</td>
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
                          <td className="col-actions">
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

              <div className="split">
                <CreateSecretForm disabled={busy || !state || sealed} onCreate={createSecret} />

                <section className="panel access-panel" aria-labelledby="access-policy-title">
                  <div className="panel-heading">
                    <h3 id="access-policy-title">Read access review</h3>
                    <span className="muted">{policyReview.enabled ? 'Enabled' : 'Bypass'}</span>
                  </div>
                  <form onSubmit={(event) => event.preventDefault()}>
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
                  </form>
                  <p className="hint">Sensitive sample paths require the approval code when this simulation is enabled.</p>
                </section>
              </div>
            </div>
          ) : null}

          {section === 'keys' ? (
            <div className="section">
              <section className="panel" aria-labelledby="keks-title">
                <div className="panel-heading">
                  <h3 id="keks-title">Key versions</h3>
                  <div className="panel-heading-meta">
                    <span>{countLabel(snapshot.keks.length, 'version')}</span>
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
                <div className="meter">
                  <span className="meter-label">Secrets wrapped by the active key</span>
                  <div className="meter-track" aria-hidden="true">
                    <div
                      className="meter-fill"
                      style={{ width: `${snapshot.secrets.length ? (secretsOnActiveKey / snapshot.secrets.length) * 100 : 0}%` }}
                    />
                  </div>
                  <span className="meter-value">{`${secretsOnActiveKey} / ${snapshot.secrets.length}`}</span>
                </div>
                <div className="table-wrap" role="region" tabIndex={0} aria-label="Key usage table">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Version</th>
                        <th scope="col">State</th>
                        <th scope="col">Secrets</th>
                        <th scope="col">Created</th>
                      </tr>
                    </thead>
                    <tbody>
                      {snapshot.keks.map((kek) => (
                        <tr key={kek.version}>
                          <td className="mono">KEK v{kek.version}</td>
                          <td>
                            <span className={kek.isActive ? 'state active' : 'state'}>{kek.isActive ? 'Active' : 'Historical'}</span>
                          </td>
                          <td className="mono">{countLabel(kek.secretsCount, 'secret')}</td>
                          <td className="mono">{formatDateTime(kek.createdAt)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          ) : null}

          {section === 'leases' ? (
            <div className="section">
              <LeaseList
                leases={snapshot.leases}
                disabled={busy || sealed}
                onRenew={(lease) => void runAction(() => api.renewLease(lease.id, 30), `Lease for ${lease.secretPath} renewed`)}
                onRevoke={(lease) => void runAction(() => api.revokeLease(lease.id), `Lease for ${lease.secretPath} revoked`)}
              />
            </div>
          ) : null}

          {section === 'audit' ? (
            <div className="section">
              <AuditLedger entries={snapshot.audit} verification={snapshot.auditVerification} />
            </div>
          ) : null}

          <footer className="app-footer">VaultMesh is released under the MIT License.</footer>
        </main>
      </div>

      {selectedSecret ? <SecretDrawer secret={selectedSecret} onClose={closeDrawer} /> : null}
    </div>
  );
}
