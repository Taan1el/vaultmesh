import { useCallback, useEffect, useMemo, useState } from 'react';
import type {
  AuditEntry,
  AuditVerificationResult,
  DecryptedSecret,
  KekVersionInfo,
  SecretLease,
  StoredSecret,
  VaultState,
} from '../../shared/types';
import { api } from './services/api';

type LoadState = 'idle' | 'loading' | 'ready' | 'error';

interface Snapshot {
  state: VaultState | null;
  secrets: StoredSecret[];
  leases: SecretLease[];
  keks: KekVersionInfo[];
  audit: AuditEntry[];
  auditVerification: AuditVerificationResult | null;
  shares: string[];
}

const emptySnapshot: Snapshot = {
  state: null,
  secrets: [],
  leases: [],
  keks: [],
  audit: [],
  auditVerification: null,
  shares: [],
};

function maskCiphertext(value: string): string {
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

export function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(emptySnapshot);
  const [loadState, setLoadState] = useState<LoadState>('idle');
  const [message, setMessage] = useState('');
  const [selectedSecret, setSelectedSecret] = useState<DecryptedSecret | null>(null);
  const [shareInput, setShareInput] = useState('');
  const [form, setForm] = useState({
    path: 'secret/apps/reporting',
    name: 'Reporting API Token',
    description: 'Token used by the reporting worker',
    plaintext: '{"token":"rpt_live_example","scope":"reports:read"}',
    isDynamic: false,
    ttlSeconds: 60,
  });

  const refresh = useCallback(async () => {
    setLoadState('loading');
    try {
      const [state, secrets, leases, keks, audit, auditVerification, shares] = await Promise.all([
        api.status(),
        api.secrets(),
        api.leases(),
        api.keks(),
        api.audit(),
        api.verifyAudit(),
        api.demoShares(),
      ]);

      setSnapshot({
        state,
        secrets,
        leases,
        keks,
        audit,
        auditVerification,
        shares: shares.shares,
      });
      setLoadState('ready');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load vault state');
      setLoadState('error');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const activeSecrets = useMemo(
    () => snapshot.secrets.filter((secret) => !secret.isDynamic).length,
    [snapshot.secrets]
  );

  async function runAction(action: () => Promise<unknown>, success: string) {
    setMessage('');
    try {
      await action();
      setMessage(success);
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Action failed');
    }
  }

  async function readSecret(path: string) {
    setMessage('');
    try {
      const secret = await api.readSecret(path);
      setSelectedSecret(secret);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to read secret');
    }
  }

  async function createSecret(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await runAction(
      () =>
        api.createSecret({
          path: form.path,
          name: form.name,
          description: form.description,
          plaintext: form.plaintext,
          isDynamic: form.isDynamic,
          ttlSeconds: form.isDynamic ? form.ttlSeconds : undefined,
          maxTtlSeconds: form.isDynamic ? form.ttlSeconds * 5 : undefined,
        }),
      'Secret created and encrypted'
    );
  }

  const status = snapshot.state?.status ?? 'SEALED';

  return (
    <main className="shell">
      <section className="masthead" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">VaultMesh</p>
          <h1 id="page-title">Secrets operations console</h1>
          <p className="lede">
            Manage envelope-encrypted secrets, custodian unseal flow, key rotation, dynamic leases, and
            tamper-evident audit checks from one control surface.
          </p>
        </div>
        <div className={`status-pill ${status.toLowerCase()}`} role="status">
          <span aria-hidden="true" />
          {status}
        </div>
      </section>

      <section className="toolbar" aria-label="Vault actions">
        <button type="button" onClick={() => void refresh()} disabled={loadState === 'loading'}>
          Refresh
        </button>
        <button type="button" onClick={() => void runAction(api.seal, 'Vault sealed')}>
          Seal
        </button>
        <button type="button" onClick={() => void runAction(api.rotateKek, 'New KEK version created')}>
          Rotate KEK
        </button>
        <button type="button" onClick={() => void runAction(api.rewrapSecrets, 'Secrets re-wrapped')}>
          Re-wrap secrets
        </button>
      </section>

      {message ? <p className="notice">{message}</p> : null}

      <section className="metrics" aria-label="Vault metrics">
        <article>
          <span>{snapshot.state?.totalSecrets ?? 0}</span>
          <p>Total secrets</p>
        </article>
        <article>
          <span>{activeSecrets}</span>
          <p>Static secrets</p>
        </article>
        <article>
          <span>{snapshot.state?.activeLeases ?? 0}</span>
          <p>Active leases</p>
        </article>
        <article>
          <span>v{snapshot.state?.activeKekVersion ?? 0}</span>
          <p>Active KEK</p>
        </article>
      </section>

      <div className="grid">
        <section className="panel" aria-labelledby="secrets-title">
          <div className="panel-heading">
            <h2 id="secrets-title">Secret inventory</h2>
            <span>{loadState === 'loading' ? 'Loading' : `${snapshot.secrets.length} paths`}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Path</th>
                  <th scope="col">KEK</th>
                  <th scope="col">Ciphertext</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.secrets.map((secret) => (
                  <tr key={secret.id}>
                    <td>
                      <strong>{secret.name}</strong>
                      <small>{secret.path}</small>
                    </td>
                    <td>v{secret.kekVersion}</td>
                    <td className="mono">{maskCiphertext(secret.ciphertext)}</td>
                    <td>
                      <button type="button" className="small" onClick={() => void readSecret(secret.path)}>
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel" aria-labelledby="create-title">
          <div className="panel-heading">
            <h2 id="create-title">Create encrypted secret</h2>
          </div>
          <form onSubmit={(event) => void createSecret(event)}>
            <label>
              Path
              <input
                value={form.path}
                onChange={(event) => setForm({ ...form, path: event.target.value })}
                required
              />
            </label>
            <label>
              Name
              <input
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
              />
            </label>
            <label>
              Description
              <input
                value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })}
              />
            </label>
            <label>
              Plaintext
              <textarea
                value={form.plaintext}
                onChange={(event) => setForm({ ...form, plaintext: event.target.value })}
                rows={5}
                required
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={form.isDynamic}
                onChange={(event) => setForm({ ...form, isDynamic: event.target.checked })}
              />
              Issue a dynamic lease
            </label>
            {form.isDynamic ? (
              <label>
                TTL seconds
                <input
                  type="number"
                  min="10"
                  max="600"
                  value={form.ttlSeconds}
                  onChange={(event) => setForm({ ...form, ttlSeconds: Number(event.target.value) })}
                />
              </label>
            ) : null}
            <button type="submit">Encrypt secret</button>
          </form>
        </section>

        <section className="panel" aria-labelledby="unseal-title">
          <div className="panel-heading">
            <h2 id="unseal-title">Custodian unseal</h2>
            <span>
              {snapshot.state?.sharesSubmitted ?? 0}/{snapshot.state?.threshold ?? 3}
            </span>
          </div>
          <p className="muted">Use any three demo shares after sealing the vault.</p>
          <textarea
            aria-label="Custodian share"
            value={shareInput}
            onChange={(event) => setShareInput(event.target.value)}
            rows={4}
            placeholder={snapshot.shares[0] ?? 'vmshare-...'}
          />
          <div className="button-row">
            <button
              type="button"
              onClick={() => void runAction(() => api.unseal(shareInput), 'Share accepted')}
              disabled={!shareInput.trim()}
            >
              Submit share
            </button>
            <button type="button" className="secondary" onClick={() => setShareInput(snapshot.shares[0] ?? '')}>
              Load sample
            </button>
          </div>
        </section>

        <section className="panel" aria-labelledby="leases-title">
          <div className="panel-heading">
            <h2 id="leases-title">Dynamic leases</h2>
          </div>
          <div className="stack-list">
            {snapshot.leases.length === 0 ? <p className="muted">No leases have been issued.</p> : null}
            {snapshot.leases.map((lease) => (
              <article key={lease.id} className="list-item">
                <div>
                  <strong>{lease.secretPath}</strong>
                  <small>
                    {lease.status} until {formatDate(lease.expiresAt)}
                  </small>
                </div>
                {lease.status === 'ACTIVE' ? (
                  <div className="button-row compact">
                    <button type="button" className="small" onClick={() => void runAction(() => api.renewLease(lease.id, 30), 'Lease renewed')}>
                      Renew
                    </button>
                    <button type="button" className="small secondary" onClick={() => void runAction(() => api.revokeLease(lease.id), 'Lease revoked')}>
                      Revoke
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="panel" aria-labelledby="keks-title">
          <div className="panel-heading">
            <h2 id="keks-title">Key versions</h2>
            <span>{snapshot.keks.length} versions</span>
          </div>
          <div className="stack-list">
            {snapshot.keks.map((kek) => (
              <article key={kek.version} className="list-item">
                <div>
                  <strong>KEK v{kek.version}</strong>
                  <small>{kek.secretsCount} secrets using this version</small>
                </div>
                <span className={kek.isActive ? 'tag active' : 'tag'}>{kek.isActive ? 'Active' : 'Historical'}</span>
              </article>
            ))}
          </div>
        </section>

        <section className="panel" aria-labelledby="audit-title">
          <div className="panel-heading">
            <h2 id="audit-title">Audit ledger</h2>
            <span>{snapshot.auditVerification?.isValid ? 'Verified' : 'Check pending'}</span>
          </div>
          <div className="stack-list">
            {snapshot.audit.map((entry) => (
              <article key={entry.id} className="list-item">
                <div>
                  <strong>{entry.action}</strong>
                  <small>{entry.details}</small>
                </div>
                <span className="mono hash">{maskCiphertext(entry.entryHash)}</span>
              </article>
            ))}
          </div>
        </section>
      </div>

      {selectedSecret ? (
        <section className="drawer" aria-label="Selected secret">
          <div>
            <p className="eyebrow">Decrypted preview</p>
            <h2>{selectedSecret.name}</h2>
            <p className="muted">{selectedSecret.path}</p>
          </div>
          <pre>{selectedSecret.plaintext}</pre>
          <button type="button" className="secondary" onClick={() => setSelectedSecret(null)}>
            Close
          </button>
        </section>
      ) : null}
    </main>
  );
}
