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
        <span>{leases.filter((lease) => lease.status === 'ACTIVE').length} active</span>
      </div>
      <ul className="stack-list">
        {leases.length === 0 ? <li className="muted">No leases have been issued.</li> : null}
        {leases.map((lease) => {
          const expired = lease.status === 'EXPIRED' || Date.parse(lease.expiresAt) <= now;
          const active = lease.status === 'ACTIVE' && !expired;
          const statusLabel = active ? 'Active' : lease.status === 'REVOKED' ? 'Revoked' : 'Expired';
          return (
            <li key={lease.id} className="list-item">
              <div>
                <strong>{lease.secretPath}</strong>
                <small>
                  {describeLease(lease, now)}. Renewed {lease.renewCount} of {lease.maxRenewals} times.
                </small>
              </div>
              <div className="item-actions">
                <span className={`tag ${active ? 'active' : ''}`}>{statusLabel}</span>
                {active ? (
                  <div className="button-row compact">
                    <button
                      type="button"
                      className="small"
                      onClick={() => onRenew(lease)}
                      disabled={disabled || lease.renewCount >= lease.maxRenewals}
                      aria-label={`Renew lease for ${lease.secretPath}`}
                    >
                      Renew
                    </button>
                    <button
                      type="button"
                      className="small secondary"
                      onClick={() => onRevoke(lease)}
                      disabled={disabled}
                      aria-label={`Revoke lease for ${lease.secretPath}`}
                    >
                      Revoke
                    </button>
                  </div>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
