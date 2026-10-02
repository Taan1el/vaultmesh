import { useEffect, useState } from 'react';
import type { SecretLease } from '../../../shared/types';
import { formatDuration, formatTime } from './format';

interface LeaseListProps {
  leases: SecretLease[];
  disabled: boolean;
  onRenew: (lease: SecretLease) => void;
  onRevoke: (lease: SecretLease) => void;
}

function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

function describeLease(lease: SecretLease, now: number): string {
  if (lease.status === 'REVOKED') {
    return `Revoked at ${formatTime(lease.revokedAt ?? lease.expiresAt)}`;
  }
  const remaining = Date.parse(lease.expiresAt) - now;
  if (lease.status === 'EXPIRED' || remaining <= 0) {
    return `Expired at ${formatTime(lease.expiresAt)}`;
  }
  return `Expires in ${formatDuration(remaining)}`;
}

export function LeaseList({ leases, disabled, onRenew, onRevoke }: LeaseListProps) {
  const now = useNow(1000);

  return (
    <section className="panel" aria-labelledby="leases-title">
      <div className="panel-heading">
        <h2 id="leases-title">Dynamic leases</h2>
        <span className="muted">{leases.filter((lease) => lease.status === 'ACTIVE').length} active</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Path</th>
              <th scope="col">State</th>
              <th scope="col">Expiry</th>
              <th scope="col">Renewals</th>
              <th scope="col" className="col-actions">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {leases.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
                  No leases have been issued.
                </td>
              </tr>
            ) : null}
            {leases.map((lease) => {
              const expired = lease.status === 'EXPIRED' || Date.parse(lease.expiresAt) <= now;
              const active = lease.status === 'ACTIVE' && !expired;
              const statusLabel = active ? 'Active' : lease.status === 'REVOKED' ? 'Revoked' : 'Expired';
              return (
                <tr key={lease.id}>
                  <td className="mono">{lease.secretPath}</td>
                  <td>
                    <span className={active ? 'state active' : 'state'}>{statusLabel}</span>
                  </td>
                  <td className="mono">{describeLease(lease, now)}</td>
                  <td className="mono">{`${lease.renewCount} of ${lease.maxRenewals}`}</td>
                  <td className="col-actions">
                    {active ? (
                      <div className="button-row">
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => onRenew(lease)}
                          disabled={disabled || lease.renewCount >= lease.maxRenewals}
                          aria-label={`Renew lease for ${lease.secretPath}`}
                        >
                          Renew
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger"
                          onClick={() => onRevoke(lease)}
                          disabled={disabled}
                          aria-label={`Revoke lease for ${lease.secretPath}`}
                        >
                          Revoke
                        </button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
